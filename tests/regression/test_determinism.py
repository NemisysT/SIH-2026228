"""Reproducibility: the property every other claim rests on.

If two runs over the same inputs disagree, then a finding is not evidence, a
metric is not a measurement, and a judge cannot check anything we say.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from cvtrust.attack_lab import attacks
from cvtrust.core.config import Config
from cvtrust.core.context import VOLATILE_FIELDS
from cvtrust.pipeline import analyse

pytestmark = pytest.mark.slow


def test_two_runs_produce_the_same_stable_digest(clean_root, config):
    first, _, _ = analyse(clean_root, config)
    second, _, _ = analyse(clean_root, config)
    assert first.stable_digest() == second.stable_digest()
    assert first.report_id == second.report_id
    assert first.run.run_id == second.run.run_id


def test_two_runs_produce_identical_findings(clean_root, config):
    first, _, _ = analyse(clean_root, config)
    second, _, _ = analyse(clean_root, config)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert [f.confidence for f in first.findings] == [f.confidence for f in second.findings]
    assert [f.severity for f in first.findings] == [f.severity for f in second.findings]


def test_only_the_declared_volatile_fields_differ(clean_root, config):
    first, _, _ = analyse(clean_root, config)
    second, _, _ = analyse(clean_root, config)
    left, right = first.model_dump(mode="json"), second.model_dump(mode="json")

    def differences(a, b, path="$"):
        if isinstance(a, dict) and isinstance(b, dict):
            out = []
            for key in set(a) | set(b):
                out += differences(a.get(key), b.get(key), f"{path}.{key}")
            return out
        if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            out = []
            for i, (x, y) in enumerate(zip(a, b)):
                out += differences(x, y, f"{path}[{i}]")
            return out
        return [] if a == b else [path]

    for path in differences(left, right):
        assert any(field in path for field in VOLATILE_FIELDS), path


def test_the_run_id_is_a_function_of_config_dataset_and_seed(clean_root, config):
    baseline, _, _ = analyse(clean_root, config)
    other_seed, _, _ = analyse(clean_root, config.merged({"seed": config.seed + 1}))
    other_threshold, _, _ = analyse(
        clean_root, config.merged({"near_duplicate": {"phash_hamming_max": 4}})
    )
    assert baseline.run.run_id != other_seed.run.run_id
    assert baseline.run.run_id != other_threshold.run.run_id
    assert baseline.configuration["config_hash"] != other_threshold.configuration["config_hash"]


def test_a_changed_threshold_changes_the_report_digest(clean_root, config):
    baseline, _, _ = analyse(clean_root, config)
    tightened, _, _ = analyse(
        clean_root, config.merged({"label_consistency": {"disagreement_min": 0.4}})
    )
    assert baseline.stable_digest() != tightened.stable_digest()


def test_corpus_generation_is_reproducible_across_processes(tmp_path):
    """Regression guard: seeding from Python's salted hash() broke this once."""
    script = (
        "import sys, logging; logging.getLogger('cvtrust').setLevel(logging.ERROR)\n"
        "from pathlib import Path\n"
        "from cvtrust.attack_lab.synth import generate_clean_dataset\n"
        "from cvtrust.core.config import ContributorConfig\n"
        "from cvtrust.datasets import ADAPTERS, ContributorResolver, build_manifest\n"
        "out = Path(sys.argv[1])\n"
        "generate_clean_dataset(out, seed=4242, per_class_per_contributor=3,\n"
        "                       export_coco=False)\n"
        "root = out / 'dataset'\n"
        "m, *_ = build_manifest(ADAPTERS.get('folder').load(root),\n"
        "                       ContributorResolver(ContributorConfig(), root))\n"
        "print(m.digest)\n"
    )
    digests = []
    for i in range(2):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / f"run{i}")],
            capture_output=True, text=True, check=True,
        )
        digests.append(result.stdout.strip().splitlines()[-1])
    assert digests[0] == digests[1], digests


def test_attacks_are_reproducible(clean_root, tmp_path):
    first = attacks.combined(clean_root, tmp_path / "a")
    second = attacks.combined(clean_root, tmp_path / "b")
    assert first.ground_truth["affected"] == second.ground_truth["affected"]

    config = Config()
    left, _, _ = analyse(first.root, config)
    right, _, _ = analyse(second.root, config)
    assert left.dataset["digest"] == right.dataset["digest"]
    assert left.stable_digest() == right.stable_digest()


def test_sample_order_does_not_depend_on_filesystem_order(clean_root, tmp_path, config):
    """Copying a dataset changes directory iteration order on some filesystems."""
    copy_root = tmp_path / "dataset"
    shutil.copytree(clean_root, copy_root)
    original, _, _ = analyse(clean_root, config)
    copied, _, _ = analyse(copy_root, config)
    assert original.dataset["digest"] == copied.dataset["digest"]


def test_ground_truth_is_never_inside_the_dataset_root(clean_root, tmp_path):
    """Structural guarantee that no detector can read the answer key."""
    result = attacks.combined(clean_root, tmp_path / "scenario")
    assert (result.out_dir / "ground_truth.json").is_file()
    assert not list(result.root.rglob("ground_truth.json"))
    assert not list(result.root.rglob("attack_config.json"))
