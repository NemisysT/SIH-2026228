"""Reproducible synthetic attacks.

Each attack takes a clean dataset, produces an attacked copy, and writes ground
truth **outside the ingestion root**:

    <scenario>/
      dataset/            <- the only thing a detector ever sees
      ground_truth.json   <- what was actually done
      attack_config.json  <- seed and parameters, sufficient to regenerate

Keeping ground truth out of ``dataset/`` is not a formality.  Adapters walk the
dataset root; a ground-truth file inside it would be visible to ingestion and,
in a subtle case, could leak into a feature or a contributor rate.  Putting it
one level up makes that structurally impossible.

Every attack is a pure function of ``(clean dataset, seed, parameters)``.
Re-running produces byte-identical output, which is what lets the evaluation
metrics be reproduced by a reviewer who does not trust our numbers.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np
from PIL import Image

from ..core.evidence import utc_now_iso
from ..core.logging import get_logger
from .synth import CLASSES, IMAGE_SIZE, render_ood_sample

log = get_logger("attack_lab.attacks")

ATTACK_LAB_VERSION = "1.0"


@dataclass
class AttackResult:
    scenario: str
    attack_classes: list[str]
    out_dir: Path
    root: Path
    ground_truth: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)

    def write(self) -> None:
        (self.out_dir / "ground_truth.json").write_text(
            json.dumps(self.ground_truth, indent=2, sort_keys=True), encoding="utf-8"
        )
        (self.out_dir / "attack_config.json").write_text(
            json.dumps(self.config, indent=2, sort_keys=True), encoding="utf-8"
        )


class _Workspace:
    """A writable copy of the clean dataset plus its contributor sidecar."""

    def __init__(self, clean_root: Path, out_dir: Path) -> None:
        self.out_dir = Path(out_dir)
        if self.out_dir.exists():
            shutil.rmtree(self.out_dir)
        self.out_dir.mkdir(parents=True)
        self.root = self.out_dir / "dataset"
        shutil.copytree(clean_root, self.root)
        self.sidecar_path = self.root / "contributors.json"
        self.sidecar: dict[str, Any] = (
            json.loads(self.sidecar_path.read_text(encoding="utf-8"))
            if self.sidecar_path.is_file()
            else {"schema": "cvtrust.contributors/1.0", "samples": {}}
        )
        self.affected: dict[str, dict[str, Any]] = {}

    def samples_of(self, contributor: str | None = None, label: str | None = None) -> list[str]:
        out = []
        for relpath, meta in sorted(self.sidecar.get("samples", {}).items()):
            if contributor and meta.get("contributor") != contributor:
                continue
            if label and relpath.split("/", 1)[0] != label:
                continue
            if (self.root / relpath).is_file():
                out.append(relpath)
        return out

    def attribute(self, relpath: str, meta: dict[str, Any]) -> None:
        self.sidecar.setdefault("samples", {})[relpath] = meta

    def meta_of(self, relpath: str) -> dict[str, Any]:
        return dict(self.sidecar.get("samples", {}).get(relpath, {}))

    def move(self, src_rel: str, dst_rel: str) -> None:
        (self.root / dst_rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.root / src_rel), str(self.root / dst_rel))
        meta = self.sidecar.get("samples", {}).pop(src_rel, {})
        self.sidecar.setdefault("samples", {})[dst_rel] = meta

    def mark(self, relpath: str, **detail: Any) -> None:
        self.affected[relpath] = detail

    def finish(
        self, scenario: str, attack_classes: Sequence[str], seed: int, params: dict[str, Any]
    ) -> AttackResult:
        self.sidecar_path.write_text(
            json.dumps(self.sidecar, indent=2, sort_keys=True), encoding="utf-8"
        )
        all_samples = sorted(
            p.relative_to(self.root).as_posix()
            for p in self.root.rglob("*")
            if p.is_file() and p.suffix.lower() in {".jpg", ".jpeg", ".png"}
        )
        result = AttackResult(
            scenario=scenario,
            attack_classes=list(attack_classes),
            out_dir=self.out_dir,
            root=self.root,
            ground_truth={
                "schema": "cvtrust.ground_truth/1.0",
                "scenario": scenario,
                "attack_classes": list(attack_classes),
                "seed": seed,
                "created_at": utc_now_iso(),
                "total_samples": len(all_samples),
                "affected": self.affected,
                "affected_count": len(self.affected),
                "clean": [s for s in all_samples if s not in self.affected],
            },
            config={
                "attack_lab_version": ATTACK_LAB_VERSION,
                "scenario": scenario,
                "attack_classes": list(attack_classes),
                "seed": seed,
                "parameters": params,
            },
        )
        result.write()
        log.info(
            "scenario '%s': %d/%d samples affected",
            scenario, len(self.affected), len(all_samples),
        )
        return result


# --------------------------------------------------------------------------
# Attacks
# --------------------------------------------------------------------------


def duplicate_flood(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 101,
    contributor: str = "delta",
    label: str = "vehicle",
    n_exact: int = 14,
    n_reencoded: int = 8,
) -> AttackResult:
    """Byte-identical and pixel-identical copies of one source image.

    The re-encoded half is the interesting half: saving the decoded pixels into
    a different container gives a different file digest with identical content,
    which defeats byte hashing alone.  Including both halves in one scenario is
    what makes the content-digest check measurable rather than merely present.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)
    pool = ws.samples_of(contributor=contributor, label=label)
    if not pool:
        raise ValueError(f"no samples for contributor={contributor} label={label}")
    source = pool[int(rng.integers(0, len(pool)))]
    source_meta = ws.meta_of(source)
    ws.mark(source, reason="source of duplicate flood", role="original",
            attack_class="duplicate_flood")

    for i in range(n_exact):
        relpath = f"{label}/{contributor}_dupe_{i:03d}.jpg"
        shutil.copy2(ws.root / source, ws.root / relpath)
        ws.attribute(relpath, {**source_meta, "batch": f"{contributor}-flood"})
        ws.mark(relpath, reason="byte-identical copy", role="injected",
                source=source, attack_class="duplicate_flood")

    with Image.open(ws.root / source) as handle:
        pixels = handle.convert("RGB")
        for i in range(n_reencoded):
            relpath = f"{label}/{contributor}_recode_{i:03d}.png"
            # PNG is lossless, so the decoded pixels are identical while the
            # file bytes are not.
            pixels.save(ws.root / relpath, "PNG", compress_level=(i % 9))
            ws.attribute(relpath, {**source_meta, "batch": f"{contributor}-flood"})
            ws.mark(relpath, reason="re-encoded pixel-identical copy", role="injected",
                    source=source, attack_class="duplicate_flood")

    return ws.finish(
        "duplicate_flood", ["duplicate_flood"], seed,
        {"contributor": contributor, "label": label,
         "n_exact": n_exact, "n_reencoded": n_reencoded, "source": source},
    )


def near_duplicate_flood(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 202,
    contributor: str = "delta",
    label: str = "aircraft",
    n_variants: int = 18,
) -> AttackResult:
    """Perceptually near-identical variants produced by photometric and mild
    geometric edits: exposure, re-compression, small centre crop, sensor noise.

    Deliberately excluded: rotation and reflection.  pHash is not invariant to
    them, the detector says so in its limitations, and generating variants the
    detector openly cannot see would inflate the measured recall by testing an
    easier problem than the one claimed.  Rotation is instead exercised in the
    adversarial test suite, where the expected result is *degraded* recall.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)
    pool = ws.samples_of(contributor=contributor, label=label)
    if not pool:
        raise ValueError(f"no samples for contributor={contributor} label={label}")
    source = pool[int(rng.integers(0, len(pool)))]
    source_meta = ws.meta_of(source)
    ws.mark(source, reason="source of near-duplicate flood", role="original",
            attack_class="near_duplicate_flood")

    with Image.open(ws.root / source) as handle:
        base = handle.convert("RGB")

    for i in range(n_variants):
        exposure = float(rng.uniform(0.92, 1.08))
        quality = int(rng.integers(62, 96))
        crop_fraction = float(rng.uniform(0.0, 0.05))
        noise_sigma = float(rng.uniform(0.0, 0.02))

        array = np.asarray(base, dtype=np.float64) / 255.0
        array = np.clip(array * exposure, 0.0, 1.0)
        array = np.clip(array + rng.normal(0.0, noise_sigma, array.shape), 0.0, 1.0)
        variant = Image.fromarray((array * 255).astype(np.uint8))
        if crop_fraction > 0:
            inset = int(IMAGE_SIZE * crop_fraction)
            variant = variant.crop(
                (inset, inset, IMAGE_SIZE - inset, IMAGE_SIZE - inset)
            ).resize((IMAGE_SIZE, IMAGE_SIZE), Image.Resampling.LANCZOS)

        relpath = f"{label}/{contributor}_var_{i:03d}.jpg"
        variant.save(ws.root / relpath, "JPEG", quality=quality)
        ws.attribute(relpath, {**source_meta, "batch": f"{contributor}-variants"})
        ws.mark(
            relpath, reason="near-duplicate variant", role="injected", source=source,
            attack_class="near_duplicate_flood",
            transform={"exposure": exposure, "jpeg_quality": quality,
                       "crop_fraction": crop_fraction, "noise_sigma": noise_sigma},
        )

    return ws.finish(
        "near_duplicate_flood", ["near_duplicate_flood"], seed,
        {"contributor": contributor, "label": label,
         "n_variants": n_variants, "source": source},
    )


def label_flip(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 303,
    contributor: str = "bravo",
    rate: float = 0.30,
    classes: Sequence[str] = CLASSES,
) -> AttackResult:
    """Random label flipping: a fraction of one contributor's labels are changed
    to a uniformly-chosen different class.

    Random, not directional — that is what separates this scenario from
    ``systematic_mislabel`` and lets the evaluation show that the two detectors
    respond to different structure rather than both firing on any label noise.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)
    pool = ws.samples_of(contributor=contributor)
    n_flip = int(round(len(pool) * rate))
    chosen = sorted(rng.choice(len(pool), size=n_flip, replace=False).tolist())

    for index in chosen:
        relpath = pool[index]
        original = relpath.split("/", 1)[0]
        alternatives = [c for c in classes if c != original]
        new_label = alternatives[int(rng.integers(0, len(alternatives)))]
        new_rel = f"{new_label}/{Path(relpath).name}"
        ws.move(relpath, new_rel)
        ws.mark(new_rel, reason="label flipped", role="flipped",
                original_label=original, declared_label=new_label,
                attack_class="label_flip")

    return ws.finish(
        "label_flip", ["label_flip"], seed,
        {"contributor": contributor, "rate": rate, "n_flipped": len(chosen)},
    )


def systematic_mislabel(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 404,
    contributor: str = "charlie",
    source_label: str = "vehicle",
    target_label: str = "building",
    fraction: float = 0.85,
) -> AttackResult:
    """A single contributor applies one consistent, directional label mapping.

    Every individual label remains plausible; only the concentration on one
    ordered pair, relative to the rest of the cohort, reveals it.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)
    pool = ws.samples_of(contributor=contributor, label=source_label)
    n_affect = int(round(len(pool) * fraction))
    chosen = sorted(rng.choice(len(pool), size=n_affect, replace=False).tolist())

    for index in chosen:
        relpath = pool[index]
        new_rel = f"{target_label}/{Path(relpath).name}"
        ws.move(relpath, new_rel)
        ws.mark(new_rel, reason=f"systematic mapping {source_label} -> {target_label}",
                role="mislabelled", original_label=source_label,
                declared_label=target_label, attack_class="systematic_mislabel")

    return ws.finish(
        "systematic_mislabel", ["systematic_mislabel"], seed,
        {"contributor": contributor, "source_label": source_label,
         "target_label": target_label, "fraction": fraction, "n_affected": len(chosen)},
    )


def ood_insertion(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 505,
    contributor: str = "delta",
    n_samples: int = 24,
    classes: Sequence[str] = CLASSES,
) -> AttackResult:
    """Insert samples from a different acquisition process under valid labels.

    The inserted imagery is generated by a genuinely different renderer
    (thermal-style palette, inverted object polarity, heavy vignette,
    fixed-pattern noise), not by perturbing clean samples.  Labels are correct
    for the depicted content, so nothing about the annotation is wrong -- only
    the distribution is.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)
    template = next(iter(ws.samples_of(contributor=contributor)), None)
    base_meta = ws.meta_of(template) if template else {"contributor": contributor}

    for i in range(n_samples):
        label = classes[int(rng.integers(0, len(classes)))]
        image = render_ood_sample(label, np.random.default_rng(seed * 1000 + i))
        relpath = f"{label}/{contributor}_alt_{i:03d}.jpg"
        (ws.root / label).mkdir(parents=True, exist_ok=True)
        image.save(ws.root / relpath, "JPEG", quality=88)
        ws.attribute(relpath, {**base_meta, "batch": f"{contributor}-alt-sensor",
                               "source": "platform-alt"})
        ws.mark(relpath, reason="inserted from a different acquisition process",
                role="injected", declared_label=label, attack_class="ood_insertion")

    return ws.finish(
        "ood_insertion", ["ood_insertion"], seed,
        {"contributor": contributor, "n_samples": n_samples, "renderer": "thermal"},
    )


def combined(
    clean_root: Path,
    out_dir: Path,
    *,
    seed: int = 606,
) -> AttackResult:
    """Several attacks by different contributors at once.

    This is the realistic case and the one the analyst workflow is designed
    around: a pipeline is rarely attacked in exactly one way, and contributor
    aggregation only becomes meaningful when different sources behave
    differently.
    """
    ws = _Workspace(clean_root, out_dir)
    rng = np.random.default_rng(seed)

    # delta: near-duplicate flooding
    pool = ws.samples_of(contributor="delta", label="aircraft")
    source = pool[int(rng.integers(0, len(pool)))]
    source_meta = ws.meta_of(source)
    ws.mark(source, reason="source of near-duplicate flood", role="original",
            attack_class="near_duplicate_flood")
    with Image.open(ws.root / source) as handle:
        base = handle.convert("RGB")
    for i in range(14):
        array = np.clip(
            np.asarray(base, dtype=np.float64) / 255.0 * float(rng.uniform(0.93, 1.07)),
            0.0, 1.0,
        )
        relpath = f"aircraft/delta_var_{i:03d}.jpg"
        Image.fromarray((array * 255).astype(np.uint8)).save(
            ws.root / relpath, "JPEG", quality=int(rng.integers(65, 95))
        )
        ws.attribute(relpath, {**source_meta, "batch": "delta-variants"})
        ws.mark(relpath, reason="near-duplicate variant", role="injected",
                source=source, attack_class="near_duplicate_flood")

    # charlie: systematic mislabelling vehicle -> building
    for relpath in ws.samples_of(contributor="charlie", label="vehicle")[:12]:
        new_rel = f"building/{Path(relpath).name}"
        ws.move(relpath, new_rel)
        ws.mark(new_rel, reason="systematic mapping vehicle -> building",
                role="mislabelled", original_label="vehicle",
                declared_label="building", attack_class="systematic_mislabel")

    # bravo: random label flips
    bravo = ws.samples_of(contributor="bravo")
    for index in sorted(rng.choice(len(bravo), size=8, replace=False).tolist()):
        relpath = bravo[index]
        original = relpath.split("/", 1)[0]
        alternatives = [c for c in CLASSES if c != original]
        new_label = alternatives[int(rng.integers(0, len(alternatives)))]
        new_rel = f"{new_label}/{Path(relpath).name}"
        ws.move(relpath, new_rel)
        ws.mark(new_rel, reason="label flipped", role="flipped",
                original_label=original, declared_label=new_label,
                attack_class="label_flip")

    # delta: out-of-distribution insertion
    delta_meta = ws.meta_of(next(iter(ws.samples_of(contributor="delta")), ""))
    for i in range(16):
        label = CLASSES[int(rng.integers(0, len(CLASSES)))]
        image = render_ood_sample(label, np.random.default_rng(seed * 7919 + i))
        relpath = f"{label}/delta_alt_{i:03d}.jpg"
        image.save(ws.root / relpath, "JPEG", quality=88)
        ws.attribute(relpath, {**delta_meta, "batch": "delta-alt-sensor",
                               "source": "platform-alt"})
        ws.mark(relpath, reason="inserted from a different acquisition process",
                role="injected", declared_label=label, attack_class="ood_insertion")

    return ws.finish(
        "combined",
        ["near_duplicate_flood", "systematic_mislabel", "label_flip", "ood_insertion"],
        seed,
        {"note": "multi-contributor scenario used for the end-to-end demonstration"},
    )


SCENARIOS: dict[str, Callable[..., AttackResult]] = {
    "duplicate_flood": duplicate_flood,
    "near_duplicate_flood": near_duplicate_flood,
    "label_flip": label_flip,
    "systematic_mislabel": systematic_mislabel,
    "ood_insertion": ood_insertion,
    "combined": combined,
}
