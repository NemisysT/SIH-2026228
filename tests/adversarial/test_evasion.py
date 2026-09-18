"""Adversarial tests: try to beat the detectors.

Two kinds of assertion appear here, and both matter:

* **Must hold** — evasion attempts that the detector is designed to survive.
* **Honest failure** — evasion attempts that succeed.  Those are asserted too,
  because the detector's ``limitations`` claim they will succeed, and a claimed
  limitation that silently stopped being true would mean the documentation is
  wrong.  A test that only ever proves the tool works is not a security test.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from cvtrust.core.evidence import AssetType, Severity
from cvtrust.pipeline import analyse

pytestmark = [pytest.mark.slow, pytest.mark.adversarial]


def _copy(clean_root: Path, tmp_path: Path) -> Path:
    root = tmp_path / "dataset"
    shutil.copytree(clean_root, root)
    return root


def _attribute(root: Path, relpath: str, contributor: str = "delta") -> None:
    import json

    path = root / "contributors.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["samples"][relpath] = {"contributor": contributor, "batch": "evasion"}
    path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")


def _flagged(report, attack_class: str) -> set[str]:
    return {
        f.asset.id
        for f in report.findings
        if f.attack_class == attack_class and f.asset.type is AssetType.SAMPLE
    } | {
        ref
        for f in report.findings
        if f.attack_class == attack_class
        for e in f.evidence
        if e.kind in {"perceptual_hash_distance", "file_digest_collision",
                      "content_digest_collision"}
        for ref in e.refs
    }


# -- evasion the detectors must survive -----------------------------------


def test_re_encoding_does_not_hide_an_exact_duplicate(clean_root, tmp_path, config):
    """Changing the container changes the file digest but not the content digest."""
    root = _copy(clean_root, tmp_path)
    source = sorted((root / "vehicle").glob("*.jpg"))[0]
    with Image.open(source) as handle:
        pixels = handle.convert("RGB")
        for i in range(6):
            target = source.with_name(f"evade_recode_{i}.png")
            pixels.save(target, "PNG", compress_level=i)
            _attribute(root, f"vehicle/{target.name}")

    report, _, _ = analyse(root, config)
    flagged = _flagged(report, "duplicate_flood")
    assert sum(1 for f in flagged if "evade_recode" in f) >= 5


def test_metadata_stripping_does_not_hide_an_exact_duplicate(clean_root, tmp_path, config):
    root = _copy(clean_root, tmp_path)
    source = sorted((root / "vessel").glob("*.jpg"))[0]
    with Image.open(source) as handle:
        pixels = handle.convert("RGB")
    for i in range(5):
        target = source.with_name(f"evade_strip_{i}.jpg")
        # Same pixels, re-encoded at maximum quality with no metadata.
        pixels.save(target, "JPEG", quality=100, subsampling=0, optimize=True)
        _attribute(root, f"vessel/{target.name}")

    report, _, _ = analyse(root, config)
    flagged = _flagged(report, "near_duplicate_flood") | _flagged(report, "duplicate_flood")
    assert sum(1 for f in flagged if "evade_strip" in f) >= 4


def test_photometric_perturbation_does_not_hide_near_duplicates(clean_root, tmp_path, config):
    """Exposure, contrast and noise are what a lazy adversary reaches for first."""
    root = _copy(clean_root, tmp_path)
    source = sorted((root / "aircraft").glob("*.jpg"))[0]
    rng = np.random.default_rng(11)
    with Image.open(source) as handle:
        base = np.asarray(handle.convert("RGB"), dtype=np.float64) / 255.0

    for i in range(10):
        array = np.clip(base * rng.uniform(0.85, 1.15) + rng.uniform(-0.05, 0.05), 0, 1)
        array = np.clip(array + rng.normal(0, 0.015, array.shape), 0, 1)
        target = source.with_name(f"evade_photo_{i}.jpg")
        Image.fromarray((array * 255).astype(np.uint8)).save(
            target, "JPEG", quality=int(rng.integers(55, 95))
        )
        _attribute(root, f"aircraft/{target.name}")

    report, _, _ = analyse(root, config)
    flagged = _flagged(report, "near_duplicate_flood")
    detected = sum(1 for f in flagged if "evade_photo" in f)
    assert detected >= 8, f"only {detected}/10 photometric variants detected"


def test_flooding_cannot_manufacture_agreement_for_a_flipped_label(
    clean_root, tmp_path, config
):
    """The reason near-duplicates are excluded from neighbourhoods.

    The adversary flips one label, then floods near-copies carrying the same
    wrong label so the neighbourhood agrees with itself.  Excluding perceptual
    duplicates from the query's neighbourhood defeats this.
    """
    root = _copy(clean_root, tmp_path)
    source = sorted((root / "vessel").glob("*.jpg"))[0]
    victim = root / "building" / f"flip_{source.name}"
    shutil.move(str(source), str(victim))
    _attribute(root, f"building/{victim.name}")

    rng = np.random.default_rng(5)
    with Image.open(victim) as handle:
        base = np.asarray(handle.convert("RGB"), dtype=np.float64) / 255.0
    for i in range(12):
        array = np.clip(base * rng.uniform(0.96, 1.04), 0, 1)
        target = root / "building" / f"flip_support_{i}.jpg"
        Image.fromarray((array * 255).astype(np.uint8)).save(target, "JPEG", quality=92)
        _attribute(root, f"building/{target.name}")

    report, _, _ = analyse(root, config)
    label_flagged = {
        f.asset.id for f in report.findings if f.attack_class == "label_flip"
    }
    assert f"building/{victim.name}" in label_flagged, (
        "flooding suppressed the label-flip signal; neighbourhood exclusion failed"
    )


def test_spreading_an_attack_over_many_contributors_still_yields_findings(
    clean_root, tmp_path, config
):
    """Contributor aggregation can be diluted; sample-level evidence cannot.

    Splitting a label-flip campaign across every contributor removes the
    contributor-level signal by construction -- there is no cohort to stand out
    against.  The sample-level findings must survive, which is why the report
    carries both levels rather than only the aggregate.
    """
    root = _copy(clean_root, tmp_path)
    moved = 0
    for contributor in ("alpha", "bravo", "charlie", "delta"):
        for source in sorted((root / "terrain").glob(f"{contributor}_*.jpg"))[:2]:
            target = root / "aircraft" / f"spread_{source.name}"
            shutil.move(str(source), str(target))
            _attribute(root, f"aircraft/{target.name}", contributor)
            moved += 1

    report, _, _ = analyse(root, config)
    flagged = {f.asset.id for f in report.findings if f.attack_class == "label_flip"}
    assert sum(1 for f in flagged if "spread_" in f) >= moved // 2


# -- documented limitations, asserted as such -----------------------------


def test_rotation_defeats_near_duplicate_detection_as_documented(
    clean_root, tmp_path, config
):
    """pHash has no rotation invariance and the detector says so.

    This test exists to keep that statement true.  If a future change made
    rotation detectable, this test fails and the ``limitations`` text must be
    updated -- coverage claims and code must not drift apart.
    """
    root = _copy(clean_root, tmp_path)
    source = sorted((root / "building").glob("*.jpg"))[0]
    with Image.open(source) as handle:
        base = handle.convert("RGB")
    for i, angle in enumerate((90, 180, 270)):
        target = source.with_name(f"evade_rot_{i}.jpg")
        base.rotate(angle, expand=False).save(target, "JPEG", quality=95)
        _attribute(root, f"building/{target.name}")

    report, _, _ = analyse(root, config)
    flagged = _flagged(report, "near_duplicate_flood")
    assert not any("evade_rot" in f for f in flagged)

    entry = next(
        e for e in report.coverage.entries if e.attack_class == "near_duplicate_flood"
    )
    assert any("rotation" in l for l in entry.limitations)


def test_a_uniformly_mislabelled_class_is_not_detectable_as_documented(
    clean_root, tmp_path, config
):
    """Renaming an entire class is internally consistent, so nothing stands out."""
    root = _copy(clean_root, tmp_path)
    import json

    sidecar = json.loads((root / "contributors.json").read_text(encoding="utf-8"))
    (root / "renamed_class").mkdir()
    for source in sorted((root / "vessel").glob("*.jpg")):
        target = root / "renamed_class" / source.name
        shutil.move(str(source), str(target))
        meta = sidecar["samples"].pop(f"vessel/{source.name}", {})
        sidecar["samples"][f"renamed_class/{source.name}"] = meta
    (root / "vessel").rmdir()
    (root / "contributors.json").write_text(
        json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8"
    )

    report, _, _ = analyse(root, config)
    label_findings = [f for f in report.findings if f.attack_class == "label_flip"]
    assert not any("renamed_class" in f.asset.id for f in label_findings)

    entry = next(e for e in report.coverage.entries if e.attack_class == "label_flip")
    assert any("uniformly mislabelled" in l for l in entry.limitations)


def test_a_dataset_too_large_for_exact_pairing_is_refused_not_approximated(
    clean_root, tmp_path, config
):
    """Refusing beats silently sampling: coverage must say NOT_ASSESSED."""
    from cvtrust.core.evidence import Coverage

    root = _copy(clean_root, tmp_path)
    tight = config.merged({"near_duplicate": {"max_pairwise_samples": 100}})
    report, _, _ = analyse(root, tight)
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "near_duplicate_flood"
    )
    assert entry.coverage is Coverage.NOT_ASSESSED
    assert "refused rather than approximated" in (entry.reason or "")
    assert not [f for f in report.findings if f.method == "near_duplicate"]
