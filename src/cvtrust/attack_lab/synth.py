"""Procedural generation of the clean baseline dataset.

Operational imagery for this problem domain is classified and unavailable, so
the attack laboratory is built on a synthetic corpus that is fully specified by
a seed.  That is not only a workaround: a generated corpus is the only kind
where the *clean* ground truth is known with certainty, which is what makes a
measured false-positive rate meaningful.

The generator models three things that matter to the detectors under test:

1. **Class-conditional appearance** — six classes with distinguishable colour,
   shape and texture statistics, so that neighbourhood label analysis has a
   feature space to work in.  Classes overlap enough to be non-trivial.
2. **Per-contributor acquisition style** — exposure, sensor noise and JPEG
   quality vary by contributor, exactly as they would across real collection
   platforms.  This is what stops the OOD detector's measured false-positive
   rate from being flattered by an unrealistically homogeneous corpus.
3. **Within-class variation** — position, scale, orientation and background
   texture vary per sample, so near-duplicate detection is not trivially
   solved by "everything in this class looks the same".

Stated limitation, repeated in the evaluation output: metrics measured here
describe detector behaviour on this corpus.  They are evidence that the
detectors work as designed and a lower bound on evidence quality, not a
prediction of operational performance on real imagery.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from PIL import Image

from ..core.evidence import utc_now_iso
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger

log = get_logger("attack_lab.synth")

GENERATOR_VERSION = "1.0"
IMAGE_SIZE = 128

CLASSES: tuple[str, ...] = (
    "vehicle",
    "aircraft",
    "building",
    "vessel",
    "terrain",
    "personnel",
)

#: Per-class appearance parameters: background hue/roughness and object shape.
CLASS_PROFILE: dict[str, dict[str, Any]] = {
    "vehicle":   {"bg": (0.30, 0.40, 0.22), "rough": 0.55, "shape": "rect",
                  "obj": (0.32, 0.34, 0.30), "size": (0.22, 0.34), "aspect": (1.6, 2.6)},
    "aircraft":  {"bg": (0.55, 0.57, 0.60), "rough": 0.25, "shape": "cross",
                  "obj": (0.80, 0.82, 0.85), "size": (0.30, 0.45), "aspect": (1.0, 1.3)},
    "building":  {"bg": (0.45, 0.42, 0.36), "rough": 0.35, "shape": "grid",
                  "obj": (0.62, 0.58, 0.50), "size": (0.36, 0.52), "aspect": (0.8, 1.4)},
    "vessel":    {"bg": (0.16, 0.26, 0.40), "rough": 0.20, "shape": "ellipse",
                  "obj": (0.72, 0.72, 0.70), "size": (0.26, 0.40), "aspect": (2.4, 4.0)},
    "terrain":   {"bg": (0.38, 0.34, 0.24), "rough": 0.80, "shape": "none",
                  "obj": (0.0, 0.0, 0.0), "size": (0.0, 0.0), "aspect": (1.0, 1.0)},
    "personnel": {"bg": (0.34, 0.38, 0.26), "rough": 0.60, "shape": "dots",
                  "obj": (0.20, 0.18, 0.22), "size": (0.06, 0.11), "aspect": (0.4, 0.7)},
}


@dataclass(frozen=True, slots=True)
class ContributorProfile:
    """How one collection source's imagery differs, physically."""

    name: str
    exposure: float          # multiplicative gain
    noise_sigma: float       # additive sensor noise
    jpeg_quality: int
    blur: float              # mild optical blur


DEFAULT_CONTRIBUTORS: tuple[ContributorProfile, ...] = (
    ContributorProfile("alpha", 1.00, 0.020, 92, 0.0),
    ContributorProfile("bravo", 0.94, 0.030, 85, 0.4),
    ContributorProfile("charlie", 1.08, 0.025, 90, 0.2),
    ContributorProfile("delta", 0.98, 0.035, 80, 0.6),
)


@dataclass
class GeneratedDataset:
    root: Path
    samples: list[dict[str, Any]] = field(default_factory=list)
    spec: dict[str, Any] = field(default_factory=dict)


def _sample_seed(seed: int, label: str, contributor: str, index: int) -> int:
    """Stable 64-bit seed for one sample, identical on every machine and run."""
    digest = sha256_canonical(
        {"seed": seed, "label": label, "contributor": contributor, "index": index}
    )
    return int(digest[:16], 16)


def _fractal_texture(rng: np.random.Generator, size: int, roughness: float) -> np.ndarray:
    """Band-limited noise texture with 1/f-like structure.

    Real imagery has correlated, multi-scale texture; white noise does not, and
    a corpus built on white noise would make every frequency-domain feature
    (pHash's DCT band, the descriptor's DCT block) behave unrealistically.
    """
    field_ = np.zeros((size, size), dtype=np.float64)
    amplitude = 1.0
    octave = 4
    while octave <= size:
        coarse = rng.random((octave, octave))
        upscaled = np.asarray(
            Image.fromarray((coarse * 255).astype(np.uint8)).resize(
                (size, size), Image.Resampling.BILINEAR
            ),
            dtype=np.float64,
        ) / 255.0
        field_ += amplitude * (upscaled - 0.5)
        amplitude *= roughness
        octave *= 2
    span = float(field_.max() - field_.min())
    return (field_ - field_.min()) / span if span > 1e-9 else field_


def _draw_object(
    canvas: np.ndarray, rng: np.random.Generator, profile: dict[str, Any]
) -> tuple[float, float, float, float] | None:
    """Draw the class object; returns its bounding box in pixels."""
    size = canvas.shape[0]
    shape = profile["shape"]
    if shape == "none":
        return None

    colour = np.array(profile["obj"], dtype=np.float64)
    extent = rng.uniform(*profile["size"]) * size
    aspect = rng.uniform(*profile["aspect"])
    # Clamp to the canvas: a long aspect ratio on a large extent (a vessel, for
    # instance) can otherwise exceed the frame and leave no valid centre.
    margin = 4.0
    width = min(extent * aspect, size - 2 * margin)
    height = min(extent, size - 2 * margin)
    cx = rng.uniform(width / 2 + margin, size - width / 2 - margin)
    cy = rng.uniform(height / 2 + margin, size - height / 2 - margin)
    yy, xx = np.mgrid[0:size, 0:size]
    angle = rng.uniform(-0.35, 0.35)
    dx = (xx - cx) * np.cos(angle) + (yy - cy) * np.sin(angle)
    dy = -(xx - cx) * np.sin(angle) + (yy - cy) * np.cos(angle)

    if shape == "rect":
        mask = (np.abs(dx) <= width / 2) & (np.abs(dy) <= height / 2)
    elif shape == "ellipse":
        mask = (dx / (width / 2)) ** 2 + (dy / (height / 2)) ** 2 <= 1.0
    elif shape == "cross":
        mask = ((np.abs(dx) <= width / 2) & (np.abs(dy) <= height / 8)) | (
            (np.abs(dx) <= width / 10) & (np.abs(dy) <= height / 2)
        )
    elif shape == "grid":
        base = (np.abs(dx) <= width / 2) & (np.abs(dy) <= height / 2)
        lines = (np.abs(dx) % max(width / 5, 2) < 1.4) | (
            np.abs(dy) % max(height / 5, 2) < 1.4
        )
        mask = base
        canvas[base & lines] = colour * 0.55
    elif shape == "dots":
        mask = np.zeros_like(dx, dtype=bool)
        for _ in range(rng.integers(2, 5)):
            ox, oy = rng.uniform(-size / 4, size / 4), rng.uniform(-size / 4, size / 4)
            mask |= ((dx - ox) / (width / 2)) ** 2 + ((dy - oy) / (height / 2)) ** 2 <= 1.0
    else:  # pragma: no cover - guarded by CLASS_PROFILE
        raise ValueError(f"unknown shape {shape!r}")

    if shape != "grid":
        canvas[mask] = colour
    shade = rng.uniform(-0.06, 0.06)
    canvas[mask] = np.clip(canvas[mask] + shade, 0.0, 1.0)
    return (
        max(0.0, cx - width / 2), max(0.0, cy - height / 2),
        min(float(size), cx + width / 2), min(float(size), cy + height / 2),
    )


def render_sample(
    label: str, contributor: ContributorProfile, rng: np.random.Generator
) -> tuple[Image.Image, tuple[float, float, float, float] | None]:
    profile = CLASS_PROFILE[label]
    texture = _fractal_texture(rng, IMAGE_SIZE, profile["rough"])
    base = np.array(profile["bg"], dtype=np.float64)
    canvas = np.clip(
        base[None, None, :] + (texture[..., None] - 0.5) * 0.45, 0.0, 1.0
    )
    bbox = _draw_object(canvas, rng, profile)

    # Contributor acquisition characteristics, applied in physical order:
    # optics -> exposure -> sensor noise -> compression.
    if contributor.blur > 0:
        image = Image.fromarray((canvas * 255).astype(np.uint8))
        from PIL import ImageFilter

        image = image.filter(ImageFilter.GaussianBlur(contributor.blur))
        canvas = np.asarray(image, dtype=np.float64) / 255.0
    canvas = np.clip(canvas * contributor.exposure, 0.0, 1.0)
    canvas = np.clip(canvas + rng.normal(0.0, contributor.noise_sigma, canvas.shape), 0.0, 1.0)
    return Image.fromarray((canvas * 255).astype(np.uint8)), bbox


def generate_clean_dataset(
    out_dir: Path,
    *,
    seed: int = 20260917,
    per_class_per_contributor: int = 14,
    contributors: Sequence[ContributorProfile] = DEFAULT_CONTRIBUTORS,
    classes: Sequence[str] = CLASSES,
    export_coco: bool = True,
    export_yolo: bool = False,
    overwrite: bool = True,
) -> GeneratedDataset:
    """Write a clean, reproducible dataset in folder layout (+ optional COCO/YOLO).

    The folder layout is the ingestion root used by the classification-level
    detectors; the COCO and YOLO exports describe the *same* images so that all
    three adapters are exercised against identical ground truth.
    """
    out_dir = Path(out_dir)
    if overwrite and out_dir.exists():
        shutil.rmtree(out_dir)
    root = out_dir / "dataset"
    root.mkdir(parents=True, exist_ok=True)

    result = GeneratedDataset(root=root)
    sidecar: dict[str, Any] = {"schema": "cvtrust.contributors/1.0", "samples": {}}
    coco_images: list[dict[str, Any]] = []
    coco_annotations: list[dict[str, Any]] = []
    category_ids = {name: i + 1 for i, name in enumerate(classes)}

    index = 0
    for label in classes:
        (root / label).mkdir(parents=True, exist_ok=True)
        for contributor in contributors:
            for n in range(per_class_per_contributor):
                # A per-sample seed derived from the identity of the sample makes
                # generation order irrelevant: adding a class or contributor does
                # not perturb the pixels of any existing sample.
                #
                # Derived with SHA-256, not Python's hash(): hash() of a string
                # is salted per interpreter process, so seeding from it would
                # make the corpus differ between runs on the same machine and
                # silently break every reproducibility claim built on top of it.
                stream = np.random.default_rng(_sample_seed(seed, label, contributor.name, n))
                image, bbox = render_sample(label, contributor, stream)
                relpath = f"{label}/{contributor.name}_{n:03d}.jpg"
                path = root / relpath
                image.save(path, "JPEG", quality=contributor.jpeg_quality, subsampling=0)

                sidecar["samples"][relpath] = {
                    "contributor": contributor.name,
                    "batch": f"{contributor.name}-b{n // 7:02d}",
                    "source": f"platform-{contributor.name[0]}",
                }
                result.samples.append(
                    {
                        "relpath": relpath, "label": label,
                        "contributor": contributor.name, "bbox": bbox,
                    }
                )
                index += 1
                coco_images.append(
                    {
                        "id": index, "file_name": relpath,
                        "width": IMAGE_SIZE, "height": IMAGE_SIZE,
                        "contributor": contributor.name,
                    }
                )
                if bbox is not None:
                    x1, y1, x2, y2 = bbox
                    coco_annotations.append(
                        {
                            "id": len(coco_annotations) + 1, "image_id": index,
                            "category_id": category_ids[label],
                            "bbox": [round(x1, 2), round(y1, 2),
                                     round(x2 - x1, 2), round(y2 - y1, 2)],
                            "area": round((x2 - x1) * (y2 - y1), 2), "iscrowd": 0,
                        }
                    )

    (root / "contributors.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8"
    )

    result.spec = {
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "created_at": utc_now_iso(),
        "classes": list(classes),
        "contributors": [
            {
                "name": c.name, "exposure": c.exposure, "noise_sigma": c.noise_sigma,
                "jpeg_quality": c.jpeg_quality, "blur": c.blur,
            }
            for c in contributors
        ],
        "per_class_per_contributor": per_class_per_contributor,
        "image_size": IMAGE_SIZE,
        "total_samples": len(result.samples),
    }
    (out_dir / "generation_spec.json").write_text(
        json.dumps(result.spec, indent=2, sort_keys=True), encoding="utf-8"
    )

    if export_coco:
        coco_dir = out_dir / "coco"
        _export_coco(coco_dir, root, coco_images, coco_annotations, category_ids)
    if export_yolo:
        _export_yolo(out_dir / "yolo", root, result.samples, list(classes))

    log.info("generated %d clean samples under %s", len(result.samples), root)
    return result


def _export_coco(
    coco_dir: Path,
    source_root: Path,
    images: list[dict[str, Any]],
    annotations: list[dict[str, Any]],
    category_ids: dict[str, int],
) -> None:
    (coco_dir / "images").mkdir(parents=True, exist_ok=True)
    (coco_dir / "annotations").mkdir(parents=True, exist_ok=True)
    remapped: list[dict[str, Any]] = []
    for entry in images:
        flat = entry["file_name"].replace("/", "__")
        shutil.copy2(source_root / entry["file_name"], coco_dir / "images" / flat)
        remapped.append({**entry, "file_name": flat})
    (coco_dir / "annotations" / "instances.json").write_text(
        json.dumps(
            {
                "info": {"description": "cvtrust synthetic corpus"},
                "images": remapped,
                "annotations": annotations,
                "categories": [
                    {"id": i, "name": name} for name, i in sorted(category_ids.items(), key=lambda kv: kv[1])
                ],
            },
            indent=1, sort_keys=True,
        ),
        encoding="utf-8",
    )


def _export_yolo(
    yolo_dir: Path, source_root: Path, samples: list[dict[str, Any]], classes: list[str]
) -> None:
    (yolo_dir / "images").mkdir(parents=True, exist_ok=True)
    (yolo_dir / "labels").mkdir(parents=True, exist_ok=True)
    for sample in samples:
        flat = sample["relpath"].replace("/", "__")
        shutil.copy2(source_root / sample["relpath"], yolo_dir / "images" / flat)
        lines: list[str] = []
        if sample["bbox"] is not None:
            x1, y1, x2, y2 = sample["bbox"]
            cx = (x1 + x2) / 2 / IMAGE_SIZE
            cy = (y1 + y2) / 2 / IMAGE_SIZE
            width = (x2 - x1) / IMAGE_SIZE
            height = (y2 - y1) / IMAGE_SIZE
            lines.append(
                f"{classes.index(sample['label'])} {cx:.6f} {cy:.6f} {width:.6f} {height:.6f}"
            )
        (yolo_dir / "labels" / f"{Path(flat).stem}.txt").write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
    (yolo_dir / "data.yaml").write_text(
        "names:\n" + "".join(f"  {i}: {n}\n" for i, n in enumerate(classes)),
        encoding="utf-8",
    )


#: Appearance of the "different sensor" used for out-of-distribution insertion.
#: A genuinely different acquisition process, not the clean generator with the
#: knobs turned: single-band thermal-style response mapped through a palette,
#: inverted object polarity, strong vignetting and a different noise character.
#: If OOD samples were only a photometric edit of in-distribution samples, a
#: detector could "pass" the scenario while detecting nothing real.
def render_ood_sample(
    label: str, rng: np.random.Generator, *, palette: str = "thermal"
) -> Image.Image:
    profile = CLASS_PROFILE[label]
    texture = _fractal_texture(rng, IMAGE_SIZE, 0.9)
    band = texture * 0.7 + 0.15

    if profile["shape"] != "none":
        canvas = np.repeat(band[..., None], 3, axis=2)
        # Objects read HOT (bright) against a cool background: the opposite
        # polarity to the visible-band generator.
        bbox_canvas = canvas.copy()
        _draw_object(bbox_canvas, rng, {**profile, "obj": (0.97, 0.97, 0.97)})
        band = bbox_canvas[..., 0]

    if palette == "thermal":
        red = np.clip(1.6 * band - 0.35, 0.0, 1.0)
        green = np.clip(1.25 * band - 0.18, 0.0, 1.0) * 0.55
        blue = np.clip(1.0 - 1.4 * band, 0.0, 1.0) * 0.85
        rgb = np.stack([red, green, blue], axis=2)
    else:  # pragma: no cover - single palette in use
        rgb = np.repeat(band[..., None], 3, axis=2)

    # Heavy radial vignette, characteristic of a different optical train.
    yy, xx = np.mgrid[0:IMAGE_SIZE, 0:IMAGE_SIZE]
    radius = np.hypot(xx - IMAGE_SIZE / 2, yy - IMAGE_SIZE / 2) / (IMAGE_SIZE / 2)
    rgb = rgb * np.clip(1.0 - 0.55 * radius**2, 0.0, 1.0)[..., None]
    # Fixed-pattern row noise rather than i.i.d. sensor noise.
    rgb = np.clip(rgb + rng.normal(0.0, 0.05, (IMAGE_SIZE, 1, 1)), 0.0, 1.0)
    return Image.fromarray((rgb * 255).astype(np.uint8))
