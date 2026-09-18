"""The reference battery: the inputs every behavioural claim is made against.

A behavioural statement about a model is meaningless without the inputs that
produced it, so the battery is a first-class, **versioned and digested**
artifact.  ``battery_digest`` is mandatory in the evidence of every behavioural
finding: an analyst can regenerate the identical probes from
``(version, config, seed, input spec)`` and recompute the claim.

Probe categories and why each is here
-------------------------------------

``clean``
    Class-conditional samples from the Module 1 synthetic generator.  The
    operating point — everything else is measured relative to it.

``borderline``
    Convex interpolations between two class prototypes.  A retrained or
    fine-tuned model differs from its reference at the decision boundary long
    before it differs in the class interiors, so probes that sit *on* the
    boundary are where behavioural divergence is most sensitive.

``perturbation``
    Brightness, contrast, gaussian noise, JPEG re-encoding, small translation
    and small crop, each applied to a ``clean`` probe and each paired with its
    source.  These are **metamorphic** pairs: the transformation is
    semantics-preserving, so the prediction *should* be preserved, and a flip
    is a measurement rather than an opinion.

``ood``
    The Module 1 thermal-palette renderer — a genuinely different acquisition
    process, not the clean generator with the knobs turned.  Present to guard
    the inverse error: a model behaving oddly on out-of-distribution input must
    not be reported as backdoored.  Module 1's rule that OOD is never equated
    with malicious applies to models too.

``trigger_probe``
    A declared patch family — positions × sizes × patterns — applied to clean
    probes.  These are the **only** inputs on which a targeted-transition or
    attack-success-rate claim may be made, and the family is recorded in the
    finding so the claim's scope is legible: a trigger outside the family is
    outside the claim.

Determinism
-----------
Probe tensors are derived from the run seed via SHA-256-mixed streams, never
from global RNG and never from Python's salted ``hash()`` (the Module 1 bug this
rule came from).  Every probe carries its own tensor digest, and the battery
digest is taken over the spec plus those digests.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
from PIL import Image

from ..core.canonical import digest_safe
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger

log = get_logger("models.battery")

BATTERY_VERSION = "1.0"

#: Probe category identifiers.  Stable strings: they appear in evidence.
CLEAN = "clean"
BORDERLINE = "borderline"
PERTURBATION = "perturbation"
OOD = "ood"
TRIGGER_PROBE = "trigger_probe"

CATEGORIES: tuple[str, ...] = (CLEAN, BORDERLINE, PERTURBATION, OOD, TRIGGER_PROBE)

#: The declared patch-trigger family.  Every targeted-behaviour claim Module 2
#: makes without gradients is scoped to exactly this set, and the set is printed
#: in the report so the scope is not a matter of trust.
#:
#: ``position`` is the corner the patch is anchored at; ``size_fraction`` is the
#: patch side as a fraction of the shorter image side; ``pattern`` names the
#: fill.  Chosen to cover the BadNets operating range (Gu et al. 2017) reported
#: in the literature: small, high-contrast, corner-anchored patches.
DEFAULT_TRIGGER_FAMILY: tuple[dict[str, Any], ...] = (
    {"position": "bottom_right", "size_fraction": 0.12, "pattern": "white"},
    {"position": "bottom_right", "size_fraction": 0.20, "pattern": "checker"},
    {"position": "top_left", "size_fraction": 0.12, "pattern": "white"},
    {"position": "top_left", "size_fraction": 0.20, "pattern": "checker"},
    {"position": "top_right", "size_fraction": 0.16, "pattern": "magenta"},
    {"position": "bottom_left", "size_fraction": 0.16, "pattern": "magenta"},
    {"position": "centre", "size_fraction": 0.16, "pattern": "checker"},
)

#: Semantics-preserving transformations used for the metamorphic pairs.
PERTURBATIONS: tuple[dict[str, Any], ...] = (
    {"kind": "brightness", "amount": 1.15},
    {"kind": "brightness", "amount": 0.85},
    {"kind": "contrast", "amount": 1.20},
    {"kind": "contrast", "amount": 0.82},
    {"kind": "gaussian_noise", "amount": 0.02},
    {"kind": "jpeg", "amount": 70},
    {"kind": "translate", "amount": 2},
    {"kind": "crop_resize", "amount": 0.92},
)


@dataclass(frozen=True, slots=True)
class Probe:
    """One battery input.

    ``pair_id`` links a perturbed probe to the clean probe it was derived from,
    which is what makes metamorphic consistency computable.  ``meta`` carries
    the transformation or trigger parameters, so a finding can name exactly what
    the model was shown.
    """

    probe_id: str
    category: str
    label: str | None
    pair_id: str | None
    meta: dict[str, Any]
    digest: str


@dataclass
class ReferenceBattery:
    """A versioned, digested set of probes plus the tensor that holds them."""

    version: str
    seed: int
    input_shape: tuple[int, ...]
    classes: tuple[str, ...]
    probes: tuple[Probe, ...]
    tensor: np.ndarray          # (N, C, H, W) float32
    spec: dict[str, Any]
    digest: str
    trigger_family: tuple[dict[str, Any], ...]

    def __len__(self) -> int:
        return len(self.probes)

    def indices(self, *categories: str) -> np.ndarray:
        wanted = set(categories)
        return np.asarray(
            [i for i, p in enumerate(self.probes) if p.category in wanted], dtype=int
        )

    def subset(self, *categories: str) -> tuple[np.ndarray, list[Probe]]:
        idx = self.indices(*categories)
        return self.tensor[idx], [self.probes[i] for i in idx]

    def by_id(self) -> dict[str, int]:
        return {p.probe_id: i for i, p in enumerate(self.probes)}

    def metamorphic_pairs(self) -> list[tuple[int, int, dict[str, Any]]]:
        """``(clean index, perturbed index, transformation)`` triples."""
        index = self.by_id()
        out: list[tuple[int, int, dict[str, Any]]] = []
        for i, probe in enumerate(self.probes):
            if probe.category != PERTURBATION or probe.pair_id is None:
                continue
            source = index.get(probe.pair_id)
            if source is not None:
                out.append((source, i, dict(probe.meta)))
        return out

    def trigger_pairs(self) -> list[tuple[int, int, dict[str, Any]]]:
        """``(clean index, triggered index, trigger parameters)`` triples."""
        index = self.by_id()
        out: list[tuple[int, int, dict[str, Any]]] = []
        for i, probe in enumerate(self.probes):
            if probe.category != TRIGGER_PROBE or probe.pair_id is None:
                continue
            source = index.get(probe.pair_id)
            if source is not None:
                out.append((source, i, dict(probe.meta)))
        return out

    def describe(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for probe in self.probes:
            counts[probe.category] = counts.get(probe.category, 0) + 1
        return {
            "battery_version": self.version,
            "battery_digest": self.digest,
            "seed": self.seed,
            "input_shape": list(self.input_shape),
            "classes": list(self.classes),
            "total_probes": len(self.probes),
            "probes_by_category": dict(sorted(counts.items())),
            "trigger_family": [dict(t) for t in self.trigger_family],
            "perturbations": [dict(p) for p in PERTURBATIONS],
        }


def _probe_digest(array: np.ndarray) -> str:
    """Digest of one probe tensor.

    Quantised to a fixed grid before hashing for the same reason parameter
    digests are: a probe regenerated on another platform must hash identically,
    and float text formatting and last-bit differences must not break that.
    """
    quantised = np.rint(np.asarray(array, dtype=np.float64) * 1_000_000).astype(np.int64)
    digest = hashlib.sha256()
    digest.update(f"{'x'.join(str(d) for d in array.shape)}|".encode("utf-8"))
    digest.update(np.ascontiguousarray(quantised).tobytes())
    return digest.hexdigest()


def _to_chw(image: Image.Image, shape: tuple[int, ...]) -> np.ndarray:
    """Resize and lay out a PIL image to match a model's declared input."""
    channels, height, width = shape[0], shape[1], shape[2]
    if channels == 1:
        image = image.convert("L")
    else:
        image = image.convert("RGB")
    image = image.resize((width, height), Image.Resampling.BILINEAR)
    array = np.asarray(image, dtype=np.float32) / 255.0
    if array.ndim == 2:
        array = array[..., None]
    array = array.transpose(2, 0, 1)
    if array.shape[0] != channels:
        array = np.repeat(array[:1], channels, axis=0)
    return np.ascontiguousarray(array, dtype=np.float32)


def _apply_perturbation(array: np.ndarray, spec: dict[str, Any]) -> np.ndarray:
    """Apply one semantics-preserving transformation to a CHW float array."""
    kind, amount = spec["kind"], spec["amount"]
    out = np.asarray(array, dtype=np.float32).copy()

    if kind == "brightness":
        out = np.clip(out * float(amount), 0.0, 1.0)
    elif kind == "contrast":
        mean = float(out.mean())
        out = np.clip((out - mean) * float(amount) + mean, 0.0, 1.0)
    elif kind == "gaussian_noise":
        # Deterministic, structured noise rather than an RNG draw: the battery
        # must be reproducible from its spec alone, and a fixed low-frequency
        # pattern is as good a semantics-preserving perturbation as an i.i.d.
        # one for this purpose.
        channels, height, width = out.shape
        grid = np.arange(height * width, dtype=np.float32).reshape(height, width)
        pattern = np.sin(grid * 0.37) * np.cos(grid * 0.11)
        out = np.clip(out + float(amount) * pattern[None, :, :], 0.0, 1.0)
    elif kind == "jpeg":
        out = _jpeg_roundtrip(out, int(amount))
    elif kind == "translate":
        shift = int(amount)
        out = np.roll(out, shift=(shift, shift), axis=(1, 2))
    elif kind == "crop_resize":
        channels, height, width = out.shape
        keep = float(amount)
        new_h, new_w = max(2, int(height * keep)), max(2, int(width * keep))
        top, left = (height - new_h) // 2, (width - new_w) // 2
        cropped = out[:, top:top + new_h, left:left + new_w]
        image = Image.fromarray(
            (np.clip(cropped.transpose(1, 2, 0), 0, 1) * 255).astype(np.uint8).squeeze()
        )
        image = image.resize((width, height), Image.Resampling.BILINEAR)
        restored = np.asarray(image, dtype=np.float32) / 255.0
        if restored.ndim == 2:
            restored = restored[..., None]
        out = np.ascontiguousarray(restored.transpose(2, 0, 1), dtype=np.float32)
        if out.shape[0] != channels:
            out = np.repeat(out[:1], channels, axis=0)
    else:  # pragma: no cover - the table above is closed
        raise ValueError(f"unknown perturbation kind {kind!r}")
    return np.ascontiguousarray(out, dtype=np.float32)


def _jpeg_roundtrip(array: np.ndarray, quality: int) -> np.ndarray:
    channels = array.shape[0]
    rgb = np.clip(array.transpose(1, 2, 0), 0.0, 1.0)
    if channels == 1:
        image = Image.fromarray((rgb[:, :, 0] * 255).astype(np.uint8), mode="L")
    else:
        image = Image.fromarray((rgb[:, :, :3] * 255).astype(np.uint8), mode="RGB")
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    with Image.open(buffer) as handle:
        decoded = np.asarray(handle.convert("L" if channels == 1 else "RGB"),
                             dtype=np.float32) / 255.0
    if decoded.ndim == 2:
        decoded = decoded[..., None]
    out = decoded.transpose(2, 0, 1)
    if out.shape[0] != channels:
        out = np.repeat(out[:1], channels, axis=0)
    return np.ascontiguousarray(out, dtype=np.float32)


def apply_trigger(array: np.ndarray, spec: dict[str, Any]) -> np.ndarray:
    """Stamp one patch trigger from the declared family onto a CHW array.

    Shared with the model attack lab so that the trigger the lab *injects* and
    the trigger the detector *probes with* are produced by one function.  If
    they diverged, a measured detection rate would be measuring the agreement of
    two implementations rather than the detector's ability.
    """
    out = np.asarray(array, dtype=np.float32).copy()
    channels, height, width = out.shape
    side = max(2, int(round(min(height, width) * float(spec["size_fraction"]))))
    position = spec["position"]
    margin = 1
    if position == "bottom_right":
        top, left = height - side - margin, width - side - margin
    elif position == "top_left":
        top, left = margin, margin
    elif position == "top_right":
        top, left = margin, width - side - margin
    elif position == "bottom_left":
        top, left = height - side - margin, margin
    elif position == "centre":
        top, left = (height - side) // 2, (width - side) // 2
    else:  # pragma: no cover - the family above is closed
        raise ValueError(f"unknown trigger position {position!r}")
    top, left = max(0, top), max(0, left)
    patch = _trigger_patch(spec["pattern"], channels, side)
    opacity = float(spec.get("opacity", 1.0))
    region = out[:, top:top + side, left:left + side]
    blended = (1.0 - opacity) * region + opacity * patch[:, : region.shape[1], : region.shape[2]]
    out[:, top:top + side, left:left + side] = blended
    return np.ascontiguousarray(np.clip(out, 0.0, 1.0), dtype=np.float32)


def _trigger_patch(pattern: str, channels: int, side: int) -> np.ndarray:
    if pattern == "white":
        patch = np.ones((channels, side, side), dtype=np.float32)
    elif pattern == "checker":
        grid = np.indices((side, side)).sum(axis=0) % 2
        patch = np.repeat(grid[None, :, :].astype(np.float32), channels, axis=0)
    elif pattern == "magenta":
        patch = np.zeros((channels, side, side), dtype=np.float32)
        patch[0] = 1.0
        if channels >= 3:
            patch[2] = 1.0
        else:
            patch[:] = 1.0
    else:  # pragma: no cover - the family above is closed
        raise ValueError(f"unknown trigger pattern {pattern!r}")
    return patch


def build_battery(
    *,
    seed: int,
    input_shape: tuple[int, ...],
    classes: Sequence[str] | None = None,
    clean_per_class: int = 4,
    borderline_pairs: int = 6,
    ood_count: int = 8,
    perturbations: Sequence[dict[str, Any]] = PERTURBATIONS,
    trigger_family: Sequence[dict[str, Any]] = DEFAULT_TRIGGER_FAMILY,
    trigger_bases: int = 6,
    version: str = BATTERY_VERSION,
) -> ReferenceBattery:
    """Construct the battery.

    ``input_shape`` is ``(C, H, W)`` — the model's declared input, minus the
    batch axis.  Probes are rendered by the Module 1 synthetic generator and
    resized to it, so a model of any input size gets a battery that matches its
    contract rather than a battery that matches ours.
    """
    from ..attack_lab.synth import CLASSES, DEFAULT_CONTRIBUTORS, render_ood_sample, render_sample

    classes = tuple(classes) if classes else CLASSES
    contributor = DEFAULT_CONTRIBUTORS[0]

    probes: list[Probe] = []
    tensors: list[np.ndarray] = []

    def _add(array: np.ndarray, probe_id: str, category: str, label: str | None,
             pair_id: str | None, meta: dict[str, Any]) -> None:
        probes.append(
            Probe(
                probe_id=probe_id, category=category, label=label,
                pair_id=pair_id, meta=meta, digest=_probe_digest(array),
            )
        )
        tensors.append(array)

    # -- clean -----------------------------------------------------------
    clean_index: dict[str, np.ndarray] = {}
    for class_index, label in enumerate(classes):
        for n in range(clean_per_class):
            rng = _stream(seed, "clean", label, n)
            image, _ = render_sample(label, contributor, rng)
            array = _to_chw(image, input_shape)
            probe_id = f"clean/{label}/{n:03d}"
            clean_index[probe_id] = array
            _add(array, probe_id, CLEAN, label, None,
                 {"class_index": class_index, "generator": "cvtrust.attack_lab.synth"})

    # -- borderline ------------------------------------------------------
    # Convex interpolation between two class prototypes at alpha near 0.5: the
    # region where a model's decision is least stable, and therefore where two
    # models that differ at all differ most visibly.
    pairs: list[tuple[str, str]] = []
    for i in range(len(classes)):
        for j in range(i + 1, len(classes)):
            pairs.append((classes[i], classes[j]))
    for n, (left_label, right_label) in enumerate(pairs[:borderline_pairs]):
        left_rng = _stream(seed, "borderline_left", left_label, n)
        right_rng = _stream(seed, "borderline_right", right_label, n)
        left_image, _ = render_sample(left_label, contributor, left_rng)
        right_image, _ = render_sample(right_label, contributor, right_rng)
        left = _to_chw(left_image, input_shape)
        right = _to_chw(right_image, input_shape)
        for alpha in (0.45, 0.55):
            blended = np.ascontiguousarray(
                np.clip((1 - alpha) * left + alpha * right, 0.0, 1.0), dtype=np.float32
            )
            _add(
                blended,
                f"borderline/{left_label}-{right_label}/{alpha:.2f}",
                BORDERLINE, None, None,
                {"left_class": left_label, "right_class": right_label,
                 "alpha": repr(alpha)},
            )

    # -- perturbations ---------------------------------------------------
    clean_ids = sorted(clean_index)
    for n, spec in enumerate(perturbations):
        # Spread the transformations across different clean probes so that a
        # single unusual source image cannot dominate the metamorphic measure.
        source_id = clean_ids[n % len(clean_ids)]
        perturbed = _apply_perturbation(clean_index[source_id], spec)
        _add(
            perturbed,
            f"perturbation/{spec['kind']}/{n:02d}",
            PERTURBATION,
            None,
            source_id,
            {"kind": spec["kind"], "amount": repr(spec["amount"]), "source": source_id},
        )

    # -- out-of-distribution --------------------------------------------
    for n in range(ood_count):
        label = classes[n % len(classes)]
        rng = _stream(seed, "ood", label, n)
        array = _to_chw(render_ood_sample(label, rng), input_shape)
        _add(array, f"ood/{label}/{n:03d}", OOD, None, None,
             {"renderer": "render_ood_sample", "palette": "thermal",
              "nearest_class": label})

    # -- trigger probes --------------------------------------------------
    bases = clean_ids[:: max(1, len(clean_ids) // max(1, trigger_bases))][:trigger_bases]
    for spec in trigger_family:
        for source_id in bases:
            triggered = apply_trigger(clean_index[source_id], spec)
            _add(
                triggered,
                f"trigger/{spec['position']}-{spec['size_fraction']}-{spec['pattern']}/{source_id}",
                TRIGGER_PROBE, None, source_id,
                {**{k: (repr(v) if isinstance(v, float) else v) for k, v in spec.items()},
                 "source": source_id},
            )

    tensor = np.stack(tensors).astype(np.float32)
    spec_payload = {
        "battery_version": version,
        "seed": seed,
        "input_shape": list(input_shape),
        "classes": list(classes),
        "clean_per_class": clean_per_class,
        "borderline_pairs": borderline_pairs,
        "ood_count": ood_count,
        "trigger_bases": trigger_bases,
        "perturbations": [dict(p) for p in perturbations],
        "trigger_family": [dict(t) for t in trigger_family],
    }
    digest = sha256_canonical(
        digest_safe(
            {
                "spec": spec_payload,
                "probes": [
                    {"probe_id": p.probe_id, "category": p.category, "digest": p.digest}
                    for p in probes
                ],
            }
        )
    )
    log.info(
        "battery %s: %d probes over %s", version, len(probes), list(input_shape)
    )
    return ReferenceBattery(
        version=version,
        seed=seed,
        input_shape=tuple(int(d) for d in input_shape),
        classes=classes,
        probes=tuple(probes),
        tensor=tensor,
        spec=spec_payload,
        digest=digest,
        trigger_family=tuple(dict(t) for t in trigger_family),
    )


def _stream(seed: int, name: str, label: str, index: int) -> np.random.Generator:
    """A generator seeded from SHA-256 over ``(seed, name, label, index)``.

    Never Python's ``hash()``: it is salted per interpreter process, so seeding
    from it would make the battery differ between runs on the same machine and
    silently break every reproducibility claim built on top of it.  That is not
    hypothetical — it is the Module 1 defect this rule exists because of.
    """
    digest = sha256_canonical(
        {"seed": seed, "stream": name, "label": label, "index": index}
    )
    return np.random.default_rng(int(digest[:16], 16))
