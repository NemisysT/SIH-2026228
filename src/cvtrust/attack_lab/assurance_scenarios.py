"""The Module 4 assurance laboratory: populations, conditions and scenarios.

Two things are built here and they answer different questions.

**Population pairs** exercise the shift subsystem.  Each pair is a reference
corpus and a current corpus rendered by the *same* generator, with a documented
physical transform applied to the current side and a declared operational
context attached to both.  Ground truth for a pair is not "an attack happened";
it is ``(shift_present, explained_by_declaration)``, which is the distinction
the problem statement actually asks the system to make.

**Assurance scenarios** exercise the fusion engine.  Each one composes evidence
from the *real* Module 1, 2 and 3 pipelines — never hand-written findings —
because a fusion engine tested against fixtures written by the same author is a
fusion engine tested against its author's expectations.  A scenario whose
evidence cannot be produced in this environment (the model scenarios need a
trained model lab) is reported ``NOT_RUN`` with the reason, never skipped
silently and never faked.

The transforms are **physically motivated and deliberately legitimate**.  Every
one of them is something a real collection programme does: the sun goes down,
a platform is swapped, winter arrives, the area of operations moves.  That is
the point.  The system's hardest requirement is not detecting an attack, it is
*not* reporting these as attacks — so the lab's centre of gravity is negative
controls, and the ``ground_truth`` of most pairs says ``attack: false``.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from PIL import Image, ImageFilter

from ..core.evidence import utc_now_iso
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger
from .synth import DEFAULT_CONTRIBUTORS, IMAGE_SIZE, generate_clean_dataset

log = get_logger("attack_lab.assurance")

LAB_VERSION = "1.0"


# ---------------------------------------------------------------------------
# Physical condition transforms
#
# Each returns a new image and declares which feature views it is EXPECTED to
# move, so the lab's own expectation can be compared against what the
# characteriser attributes -- a transform whose declared blocks and measured
# blocks disagree is a defect in one of the two, and the evaluation harness
# prints both rather than asserting the one it prefers.
# ---------------------------------------------------------------------------


def _as_array(image: Image.Image) -> np.ndarray:
    return np.asarray(image.convert("RGB"), dtype=np.float64) / 255.0


def _as_image(array: np.ndarray) -> Image.Image:
    return Image.fromarray((np.clip(array, 0.0, 1.0) * 255).astype(np.uint8))


def low_illumination(image: Image.Image, rng: np.random.Generator) -> Image.Image:
    """Dusk/night: less light reaching the sensor, so more gain and more noise.

    Modelled the way the physics works rather than as a brightness slider:
    exposure falls, contrast compresses toward the black point, and the sensor's
    read noise becomes visible because the signal shrank while the noise did
    not.
    """
    canvas = _as_array(image)
    canvas = canvas * 0.45
    canvas = 0.5 + (canvas - 0.5) * 0.75  # contrast compression
    canvas = canvas + rng.normal(0.0, 0.035, canvas.shape)
    return _as_image(canvas)


def different_sensor(image: Image.Image, rng: np.random.Generator) -> Image.Image:
    """A different imaging chain: other optics, other read-out, other encoder.

    Three independent changes, because a real platform swap is never one: a
    softer optical train, column-correlated fixed-pattern noise instead of
    i.i.d. read noise, and a different spectral response.
    """
    blurred = image.convert("RGB").filter(ImageFilter.GaussianBlur(0.9))
    canvas = _as_array(blurred)
    canvas = canvas + rng.normal(0.0, 0.03, (1, IMAGE_SIZE, 1))  # column pattern
    canvas = canvas * np.array([1.06, 0.98, 0.90])  # response curve
    return _as_image(canvas)


def winter_season(image: Image.Image, rng: np.random.Generator) -> Image.Image:
    """Winter: brighter, colder, flatter ground cover.

    Snow and low solar angle raise the ground's luminance, pull the colour
    balance toward blue and remove the saturation that vegetation supplies.
    """
    canvas = _as_array(image)
    luminance = canvas @ np.array([0.299, 0.587, 0.114])
    # Desaturate toward luminance, then push the residual cold.
    canvas = 0.45 * canvas + 0.55 * luminance[..., None]
    canvas = canvas * np.array([0.94, 0.99, 1.12])
    canvas = np.clip(canvas + 0.10, 0.0, 1.0)
    canvas = canvas + rng.normal(0.0, 0.01, canvas.shape)
    return _as_image(canvas)


def desert_terrain(image: Image.Image, rng: np.random.Generator) -> Image.Image:
    """A different area of operations: other ground cover, other texture scale.

    Warm, bright, low-contrast ground with less fine structure than the
    baseline's mixed cover.
    """
    canvas = _as_array(image)
    luminance = canvas @ np.array([0.299, 0.587, 0.114])
    canvas = 0.55 * canvas + 0.45 * luminance[..., None]
    canvas = canvas * np.array([1.18, 1.04, 0.74])
    canvas = 0.5 + (canvas - 0.5) * 0.85
    canvas = canvas + rng.normal(0.0, 0.012, canvas.shape)
    return _as_image(canvas)


#: name -> (transform, declared context for the CURRENT population, the feature
#: views the transform is expected to move).
CONDITIONS: dict[str, dict[str, Any]] = {
    "identical": {
        "transform": None,
        "context": {},
        "expected_blocks": (),
        "description": "the same collection conditions on both sides",
    },
    "low_illumination": {
        "transform": low_illumination,
        "context": {"illumination": "low", "acquisition_mode": "night"},
        # Measured: the movement lands almost entirely in the colour view, not
        # in acquisition. Per-block L2 normalisation (ADR-005) removes the
        # common-mode scaling an exposure change applies to every acquisition
        # statistic, while the HSV histogram's mass genuinely redistributes
        # across value bins.
        "expected_blocks": ("colour",),
        "description": "dusk/night collection: lower exposure, compressed "
        "contrast, visible read noise",
    },
    "different_sensor": {
        "transform": different_sensor,
        "context": {"sensor": "sensor_b"},
        # Measured, not predicted: 81% of the squared displacement lands in the
        # gradient view, because softer optics IS a change in edge statistics.
        # The context table was corrected to match this rather than the other
        # way round.
        "expected_blocks": ("gradient", "colour"),
        "description": "a different imaging chain: softer optics, "
        "column-correlated fixed-pattern noise, different spectral response",
    },
    "winter_season": {
        "transform": winter_season,
        "context": {"season": "winter"},
        "expected_blocks": ("colour",),  # measured
        "description": "winter collection: snow cover, low solar angle, "
        "desaturated and colder ground",
    },
    "desert_terrain": {
        "transform": desert_terrain,
        "context": {"terrain": "desert"},
        "expected_blocks": ("colour",),  # measured
        "description": "a different area of operations: warm, bright, "
        "low-contrast ground with less fine structure",
    },
}

#: The reference population's declared context, shared by every pair. Held
#: constant so that a pair's declared *change* is exactly the current side's
#: declaration.
REFERENCE_CONTEXT: dict[str, str] = {
    "season": "summer",
    "terrain": "mixed",
    "sensor": "sensor_a",
    "illumination": "daylight",
    "acquisition_mode": "day",
    "source": "lab baseline declaration; synthetic, and a claim like any other",
}


@dataclass
class PopulationPair:
    """One reference/current pair, with its ground truth kept outside the data."""

    name: str
    reference_root: Path
    current_root: Path
    reference_context: dict[str, str]
    current_context: dict[str, str]
    ground_truth: dict[str, Any] = field(default_factory=dict)

    def write_ground_truth(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.ground_truth, indent=2, sort_keys=True), encoding="utf-8"
        )


def _sample_rng(seed: int, scenario: str, relpath: str) -> np.random.Generator:
    """Per-image generator, stable across machines and generation order.

    Derived with SHA-256 rather than ``hash()``: Python salts string hashing per
    interpreter, so seeding from it would make the corpus differ between runs on
    the same machine and silently break every reproducibility claim built on it
    (``docs/research.md`` §"Measured corrections" item 4).
    """
    digest = sha256_canonical({"seed": seed, "scenario": scenario, "relpath": relpath})
    return np.random.default_rng(int(digest[:16], 16))


def apply_condition(
    source_root: Path,
    out_root: Path,
    condition: str,
    *,
    seed: int,
    limit_samples: int | None = None,
) -> int:
    """Copy a corpus, applying a physical condition transform to every image."""
    meta = CONDITIONS[condition]
    transform = meta["transform"]
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    paths = sorted(
        p for p in source_root.rglob("*") if p.is_file() and p.suffix.lower() == ".jpg"
    )
    if limit_samples is not None:
        # Take a stride rather than a prefix: the corpus is laid out class by
        # class, so the first N images would be one or two classes and the
        # "small sample" scenario would also be a class-imbalance scenario.
        stride = max(1, len(paths) // limit_samples)
        paths = paths[::stride][:limit_samples]

    written = 0
    for path in paths:
        relpath = path.relative_to(source_root).as_posix()
        target = out_root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        if transform is None:
            shutil.copy2(path, target)
        else:
            with Image.open(path) as handle:
                image = handle.convert("RGB")
            transformed = transform(image, _sample_rng(seed, condition, relpath))
            transformed.save(target, "JPEG", quality=90, subsampling=0)
        written += 1

    sidecar = source_root / "contributors.json"
    if sidecar.is_file():
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        kept = {
            relpath: value
            for relpath, value in payload.get("samples", {}).items()
            if (out_root / relpath).is_file()
        }
        (out_root / "contributors.json").write_text(
            json.dumps({**payload, "samples": kept}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    return written


#: The population pairs the lab ships.  ``expect`` is the verdict the design
#: predicts; the evaluation harness compares it against what the characteriser
#: actually produced and reports mismatches rather than asserting them away.
PAIR_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "clean_baseline",
        "condition": "identical",
        "declare": True,
        "expect": "NO_SHIFT_DETECTED",
        "attack": False,
        "note": "the primary negative control: two draws from one process, "
        "declared identical. Any shift verdict here is a false positive.",
    },
    {
        "name": "operational_illumination",
        "condition": "low_illumination",
        "declare": True,
        "expect": "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT",
        "attack": False,
        "note": "a legitimate night collection, declared. The shift is real and "
        "must be observed; calling it an attack is the failure.",
    },
    {
        "name": "operational_sensor",
        "condition": "different_sensor",
        "declare": True,
        "expect": "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT",
        "attack": False,
        "note": "a legitimate platform swap, declared.",
    },
    {
        "name": "operational_season",
        "condition": "winter_season",
        "declare": True,
        "expect": "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT",
        "attack": False,
        "note": "a legitimate seasonal change, declared.",
    },
    {
        "name": "operational_terrain",
        "condition": "desert_terrain",
        "declare": True,
        "expect": "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT",
        "attack": False,
        "note": "a legitimate change of operating area, declared.",
    },
    {
        "name": "undeclared_illumination",
        "condition": "low_illumination",
        "declare": False,
        "expect": "SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT",
        "attack": False,
        "note": "THE central ambiguous case. The same physical change as "
        "operational_illumination, with the declaration saying nothing changed. "
        "Correct behaviour is REVIEW: the system cannot tell an undeclared "
        "legitimate change from a manipulated one, and must not pretend to.",
    },
    {
        "name": "misdeclared_sensor_as_illumination",
        "condition": "different_sensor",
        "declare": "low_illumination",
        "expect": "SHIFT_PARTIALLY_EXPLAINED",
        "attack": False,
        "note": "a platform swap declared as an illumination change. The "
        "declaration predicts the colour movement and not the gradient "
        "movement an optical change produces, so a named residual remains. "
        "This is the pair that shows the explanation check has teeth.",
    },
    {
        "name": "misdeclared_illumination_as_season",
        "condition": "low_illumination",
        "declare": "winter_season",
        "expect": "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT",
        "attack": False,
        "note": "THE NEGATIVE CONTROL FOR THE EXPLANATION MECHANISM ITSELF. An "
        "illumination change declared as a seasonal one is reported CONSISTENT, "
        "because both declarations predict movement in the colour view and that "
        "is where ~93% of the displacement lands for either. Measured, expected, "
        "and the reason the finding says consistency is not confirmation: the "
        "attribution answers 'does the declaration predict this movement', not "
        "'which declared change occurred'.",
    },
    {
        "name": "small_current_batch",
        "condition": "low_illumination",
        "declare": True,
        "limit": 6,
        "expect": "INSUFFICIENT_SAMPLE",
        "attack": False,
        "note": "a real shift that the system must REFUSE to report, because six "
        "samples cannot support the claim. Reporting the shift here would be "
        "right by accident and wrong by method.",
    },
    {
        "name": "no_context_declared",
        "condition": "different_sensor",
        "declare": None,
        "expect": "SHIFT_DETECTED_NO_CONTEXT",
        "attack": False,
        "note": "a real shift with no declaration on either side. Distinct from "
        "'unexplained': there is nothing to contradict, so the outcome must not "
        "read as a contradiction.",
    },
)


@dataclass
class AssuranceLab:
    root: Path
    baseline_root: Path
    pairs: list[PopulationPair] = field(default_factory=list)
    spec: dict[str, Any] = field(default_factory=dict)

    def pair(self, name: str) -> PopulationPair:
        for entry in self.pairs:
            if entry.name == name:
                return entry
        raise KeyError(f"unknown population pair: {name}")


def build_lab(
    out_dir: Path,
    *,
    seed: int = 20260917,
    per_class_per_contributor: int = 8,
    pairs: Sequence[str] | None = None,
) -> AssuranceLab:
    """Generate the reference corpus and every population pair."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = generate_clean_dataset(
        out_dir / "_reference",
        seed=seed,
        per_class_per_contributor=per_class_per_contributor,
        export_coco=False,
    )
    log.info("assurance lab reference: %d samples", len(baseline.samples))

    # The current side of a pair is generated from a DIFFERENT seed, so that an
    # unchanged pair is two genuine draws from one process rather than the same
    # images twice. Comparing a corpus against itself would give every metric a
    # perfect null and would make the clean baseline meaningless.
    current_source = generate_clean_dataset(
        out_dir / "_current_source",
        seed=seed + 1,
        per_class_per_contributor=per_class_per_contributor,
        export_coco=False,
    )

    wanted = set(pairs) if pairs else None
    built: list[PopulationPair] = []
    for spec in PAIR_SPECS:
        if wanted is not None and spec["name"] not in wanted:
            continue
        name = str(spec["name"])
        condition = str(spec["condition"])
        current_root = out_dir / name / "dataset"
        count = apply_condition(
            current_source.root,
            current_root,
            condition,
            seed=seed,
            limit_samples=spec.get("limit"),
        )

        declare = spec["declare"]
        if declare is None:
            reference_context: dict[str, str] = {}
            current_context: dict[str, str] = {}
        elif declare is True:
            reference_context = dict(REFERENCE_CONTEXT)
            current_context = {
                **REFERENCE_CONTEXT,
                **CONDITIONS[condition]["context"],
                "source": "lab declaration for the current population",
            }
        elif declare is False:
            reference_context = dict(REFERENCE_CONTEXT)
            current_context = dict(REFERENCE_CONTEXT)
        else:
            # A deliberately wrong declaration: the context of a *different*
            # condition than the one actually applied.
            reference_context = dict(REFERENCE_CONTEXT)
            current_context = {
                **REFERENCE_CONTEXT,
                **CONDITIONS[str(declare)]["context"],
                "source": "lab declaration for the current population",
            }

        pair = PopulationPair(
            name=name,
            reference_root=baseline.root,
            current_root=current_root,
            reference_context=reference_context,
            current_context=current_context,
            ground_truth={
                "scenario": name,
                "lab_version": LAB_VERSION,
                "seed": seed,
                "condition": condition,
                "condition_description": CONDITIONS[condition]["description"],
                "transform_expected_blocks": list(
                    CONDITIONS[condition]["expected_blocks"]
                ),
                "shift_present": condition != "identical",
                "declared": declare if isinstance(declare, str) else bool(declare)
                if declare is not None
                else None,
                "expected_verdict": spec["expect"],
                "attack": spec["attack"],
                "current_samples": count,
                "reference_samples": len(baseline.samples),
                "note": spec["note"],
                "created_at": utc_now_iso(),
            },
        )
        (out_dir / name).mkdir(parents=True, exist_ok=True)
        pair.write_ground_truth(out_dir / name / "ground_truth.json")
        (out_dir / name / "context.json").write_text(
            json.dumps(
                {"reference": reference_context, "current": current_context},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        built.append(pair)
        log.info("assurance lab pair %-28s %4d current samples", name, count)

    lab = AssuranceLab(
        root=out_dir,
        baseline_root=baseline.root,
        pairs=built,
        spec={
            "lab_version": LAB_VERSION,
            "seed": seed,
            "per_class_per_contributor": per_class_per_contributor,
            "reference_samples": len(baseline.samples),
            "reference_context": REFERENCE_CONTEXT,
            "pairs": [p.name for p in built],
            "conditions": {
                name: {
                    "description": meta["description"],
                    "declared_context": meta["context"],
                    "expected_blocks": list(meta["expected_blocks"]),
                }
                for name, meta in sorted(CONDITIONS.items())
            },
            "note": "every transform here is a LEGITIMATE collection condition. "
            "The lab's purpose is to establish that the system observes them "
            "without classifying them as attacks.",
            "created_at": utc_now_iso(),
        },
    )
    (out_dir / "lab_spec.json").write_text(
        json.dumps(lab.spec, indent=2, sort_keys=True), encoding="utf-8"
    )
    return lab


__all__ = [
    "LAB_VERSION", "CONDITIONS", "REFERENCE_CONTEXT", "PAIR_SPECS",
    "AssuranceLab", "PopulationPair", "apply_condition", "build_lab",
    "low_illumination", "different_sensor", "winter_season", "desert_terrain",
]
