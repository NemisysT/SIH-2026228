"""The default feature space: a deterministic classical image descriptor.

Why not a pretrained CNN (ADR-005)
----------------------------------
A ResNet/CLIP embedding would separate classes better.  It would also require
downloading weights, which is exactly what an air-gapped deployment forbids, and
it would make every downstream number depend on an artifact whose provenance we
would then have to assure — a circular dependency in an integrity tool.  So the
default is a handcrafted descriptor that runs anywhere, needs no weights, and is
bit-reproducible.  A CNN backend exists behind the same interface
(:mod:`cvtrust.features.torch_backend`) for deployments that vendor weights
locally; it is never auto-downloaded and reports ``NOT_ASSESSED`` when absent.

The descriptor is five independent *views* of the image:

=======  ====================================================  =========================
block    content                                                sensitive to
=======  ====================================================  =========================
S        16x16 grayscale thumbnail, z-normalised                spatial layout, structure
C        HSV joint histogram (8x4x4)                            colour distribution
G        3x3 grid of 16-bin gradient-orientation histograms     texture and edge layout
F        8x8 DCT low band (DC removed)                          coarse frequency content
Q        acquisition statistics (focus, noise, exposure, ...)   sensor / capture conditions
=======  ====================================================  =========================

Each block is L2-normalised **independently** and then concatenated, so every
view contributes equally regardless of its dimensionality; the concatenation is
L2-normalised again so cosine similarity is well-behaved.  Block Q is what lets
the OOD detector respond to a genuine sensor/illumination change rather than
only to content change — the distinction Module 4 will build on.
"""

from __future__ import annotations

import numpy as np
from PIL import Image
from scipy.fft import dct

from ..core.config import FeatureConfig

EPS = 1e-8

#: Names of the 23 values in the acquisition block, in the order
#: :meth:`ClassicalFeatureExtractor._acquisition` emits them.
#:
#: Module 4 reports marginal distribution shift on a *named* subset of these,
#: because "PSI 0.41 on mean_luminance" is a statement an analyst can check
#: against the imagery and "PSI 0.41 on feature 597" is not.
ACQUISITION_NAMES: tuple[str, ...] = (
    "mean_red", "mean_green", "mean_blue",
    "std_red", "std_green", "std_blue",
    "mean_luminance", "std_luminance",
    "luminance_p01", "luminance_p05", "luminance_p25", "luminance_p50",
    "luminance_p75", "luminance_p95", "luminance_p99",
    "focus_laplacian_variance", "noise_floor_laplacian_mad",
    "mean_saturation", "std_saturation",
    "mean_value", "std_value",
    "edge_density", "luminance_entropy",
)


def _l2(vector: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vector))
    return vector if norm < EPS else vector / norm


class ClassicalFeatureExtractor:
    """Deterministic, weight-free image descriptor."""

    name = "classical"
    version = "1.0"

    def __init__(self, cfg: FeatureConfig | None = None) -> None:
        self.cfg = cfg or FeatureConfig()
        self._dim: int | None = None
        self._blocks: tuple[tuple[str, int, int], ...] | None = None

    @property
    def dim(self) -> int:
        if self._dim is None:
            probe = Image.new("RGB", (64, 64), (127, 127, 127))
            self._dim = int(self.extract(probe).shape[0])
        return self._dim

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "dim": self.dim,
            "blocks": [name for name, _, _ in self.blocks()],
            "block_spans": {
                name: [start, end] for name, start, end in self.blocks()
            },
            "requires_pretrained_weights": False,
            "deterministic": True,
        }

    def blocks(self) -> tuple[tuple[str, int, int], ...]:
        """Where each view lives in the concatenated vector: ``(name, start, end)``.

        Added for Module 4.  A population-level mean shift is far more useful to
        an analyst when it can be attributed to a *view* — "the movement is in
        the colour and acquisition blocks" reads as an illumination or sensor
        change, "the movement is in the structure and gradient blocks" reads as
        a content or terrain change — and that attribution needs the layout,
        which was previously implicit in :meth:`extract`.

        Measured from a probe rather than recomputed from configuration, so the
        spans cannot drift away from what ``extract`` actually produces.
        """
        if self._blocks is None:
            probe = Image.new("RGB", (64, 64), (127, 127, 127))
            rgb = self._prepare(probe)
            gray = rgb @ np.array([0.299, 0.587, 0.114])
            sizes = (
                ("structure", self._structure(gray).size),
                ("colour", self._colour(rgb).size),
                ("gradient", self._gradient(gray).size),
                ("dct", self._dct(gray).size),
                ("acquisition", self._acquisition(rgb, gray).size),
            )
            spans: list[tuple[str, int, int]] = []
            cursor = 0
            for name, size in sizes:
                spans.append((name, cursor, cursor + int(size)))
                cursor += int(size)
            self._blocks = tuple(spans)
        return self._blocks

    def extract(self, image: Image.Image) -> np.ndarray:
        return self.extract_with_blocks(image)[0]

    def extract_with_blocks(
        self, image: Image.Image
    ) -> tuple[np.ndarray, dict[str, np.ndarray]]:
        """The embedding, plus each view **before** normalisation.

        Added for Module 4.  The concatenated vector is L2-normalised per block
        and then again globally, which is right for distance work and wrong for
        reading a physical quantity off: the acquisition block's mean luminance
        is no longer a mean luminance once it has been divided by the block's
        norm twice.  Module 4 needs the physical values to report an
        illumination or sensor change in units an analyst can argue with, so
        the raw blocks are returned alongside rather than recomputed in a
        second decode pass.

        ``extract`` is unchanged and still returns exactly what it always did.
        """
        rgb = self._prepare(image)
        gray = rgb @ np.array([0.299, 0.587, 0.114])

        raw = {
            "structure": self._structure(gray),
            "colour": self._colour(rgb),
            "gradient": self._gradient(gray),
            "dct": self._dct(gray),
            "acquisition": self._acquisition(rgb, gray),
        }
        vector = _l2(
            np.concatenate([_l2(raw[name]) for name, _, _ in self.blocks()])
        ).astype(np.float32)
        return vector, raw

    # -- preparation ----------------------------------------------------

    def _prepare(self, image: Image.Image) -> np.ndarray:
        """Downscale to a bounded longest side.

        Bounding the size removes resolution as a confound (otherwise a
        contributor submitting higher-resolution imagery would look
        out-of-distribution purely because of pixel count) and bounds cost.
        """
        img = image.convert("RGB")
        longest = max(img.size)
        if longest > self.cfg.max_side:
            scale = self.cfg.max_side / longest
            new_size = (max(1, round(img.width * scale)), max(1, round(img.height * scale)))
            img = img.resize(new_size, Image.Resampling.LANCZOS)
        return np.asarray(img, dtype=np.float64) / 255.0

    # -- blocks ---------------------------------------------------------

    def _structure(self, gray: np.ndarray) -> np.ndarray:
        size = 16
        thumb = np.asarray(
            Image.fromarray((gray * 255).astype(np.uint8)).resize(
                (size, size), Image.Resampling.LANCZOS
            ),
            dtype=np.float64,
        )
        centred = thumb - thumb.mean()
        std = float(centred.std())
        return (centred / std if std > EPS else centred).reshape(-1)

    def _colour(self, rgb: np.ndarray) -> np.ndarray:
        hue, sat, val = _rgb_to_hsv(rgb)
        h_bins, s_bins, v_bins = self.cfg.hsv_bins
        hist, _ = np.histogramdd(
            np.stack([hue.ravel(), sat.ravel(), val.ravel()], axis=1),
            bins=(h_bins, s_bins, v_bins),
            range=((0.0, 1.0), (0.0, 1.0), (0.0, 1.0)),
        )
        return (hist / max(hist.sum(), EPS)).reshape(-1)

    def _gradient(self, gray: np.ndarray) -> np.ndarray:
        gy, gx = np.gradient(gray)
        magnitude = np.hypot(gx, gy)
        # Orientation folded to [0, pi): gradient direction and its reverse
        # describe the same edge, so keeping both would split every edge's mass.
        orientation = (np.arctan2(gy, gx) % np.pi) / np.pi
        bins = self.cfg.gradient_bins
        rows = np.array_split(np.arange(gray.shape[0]), 3)
        cols = np.array_split(np.arange(gray.shape[1]), 3)
        cells: list[np.ndarray] = []
        for row_idx in rows:
            for col_idx in cols:
                if row_idx.size == 0 or col_idx.size == 0:
                    cells.append(np.zeros(bins))
                    continue
                cell_o = orientation[np.ix_(row_idx, col_idx)].ravel()
                cell_m = magnitude[np.ix_(row_idx, col_idx)].ravel()
                hist, _ = np.histogram(
                    cell_o, bins=bins, range=(0.0, 1.0), weights=cell_m
                )
                cells.append(hist / max(hist.sum(), EPS))
        return np.concatenate(cells)

    def _dct(self, gray: np.ndarray) -> np.ndarray:
        size = 32
        thumb = np.asarray(
            Image.fromarray((gray * 255).astype(np.uint8)).resize(
                (size, size), Image.Resampling.LANCZOS
            ),
            dtype=np.float64,
        )
        coefficients = dct(dct(thumb, axis=0, norm="ortho"), axis=1, norm="ortho")
        band = self.cfg.dct_band
        low = coefficients[:band, :band].reshape(-1)[1:]  # drop DC (exposure only)
        # Signed log compression: DCT magnitudes span orders of magnitude and a
        # raw band would be dominated by two or three coefficients.
        return np.sign(low) * np.log1p(np.abs(low))

    def _acquisition(self, rgb: np.ndarray, gray: np.ndarray) -> np.ndarray:
        laplacian = (
            -4 * gray[1:-1, 1:-1]
            + gray[:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, :-2] + gray[1:-1, 2:]
        ) if gray.shape[0] > 2 and gray.shape[1] > 2 else np.zeros((1, 1))
        hue, sat, val = _rgb_to_hsv(rgb)
        percentiles = np.percentile(gray, [1, 5, 25, 50, 75, 95, 99])
        histogram, _ = np.histogram(gray, bins=32, range=(0.0, 1.0))
        probabilities = histogram / max(histogram.sum(), EPS)
        entropy = float(-(probabilities[probabilities > 0]
                          * np.log2(probabilities[probabilities > 0])).sum())
        return np.array(
            [
                *rgb.reshape(-1, 3).mean(axis=0),
                *rgb.reshape(-1, 3).std(axis=0),
                float(gray.mean()),
                float(gray.std()),
                *percentiles,
                float(np.var(laplacian)),          # focus / sharpness
                float(np.median(np.abs(laplacian))),  # noise floor proxy
                float(sat.mean()),
                float(sat.std()),
                float(val.mean()),
                float(val.std()),
                float(np.mean(np.abs(np.gradient(gray)[0]) > 0.05)),  # edge density
                entropy,
            ],
            dtype=np.float64,
        )


def _rgb_to_hsv(rgb: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Vectorised RGB->HSV on a float array in [0, 1]."""
    maximum = rgb.max(axis=2)
    minimum = rgb.min(axis=2)
    delta = maximum - minimum
    red, green, blue = rgb[..., 0], rgb[..., 1], rgb[..., 2]

    hue = np.zeros_like(maximum)
    safe = delta > EPS
    red_max = safe & (maximum == red)
    green_max = safe & (maximum == green) & ~red_max
    blue_max = safe & ~red_max & ~green_max
    with np.errstate(invalid="ignore", divide="ignore"):
        hue[red_max] = ((green - blue)[red_max] / delta[red_max]) % 6
        hue[green_max] = ((blue - red)[green_max] / delta[green_max]) + 2
        hue[blue_max] = ((red - green)[blue_max] / delta[blue_max]) + 4
    hue = np.clip(hue / 6.0, 0.0, 1.0)
    saturation = np.where(maximum > EPS, delta / np.maximum(maximum, EPS), 0.0)
    return hue, saturation, maximum
