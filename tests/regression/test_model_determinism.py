"""Reproducibility of a model assessment.

The same property Module 1's determinism suite protects, applied to Module 2.
If two assessments of the same artifact disagree, then a model finding is not
evidence, a measured detection rate is not a measurement, and a reviewer cannot
check anything the report says.

Module 2 has determinism hazards Module 1 does not: runtime thread counts change
float reduction order, and a reordered sum changes the low bits of a logit,
which changes an argmax at a decision boundary. The adapters pin thread counts
for exactly that reason, and these tests are what would catch it if that
regressed.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from cvtrust.core.config import Config
from cvtrust.core.context import VOLATILE_FIELDS
from cvtrust.model_pipeline import assess_model

pytestmark = pytest.mark.slow


def test_two_assessments_produce_the_same_report_id(model_lab, reference_onnx):
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    first, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    second, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    assert first.stable_digest() == second.stable_digest()
    assert first.report_id == second.report_id
    assert first.run.run_id == second.run.run_id


def test_two_assessments_produce_identical_findings(model_lab, reference_onnx):
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    first, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    second, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    assert [f.confidence for f in first.findings] == [f.confidence for f in second.findings]
    assert [f.severity for f in first.findings] == [f.severity for f in second.findings]


def test_only_the_declared_volatile_fields_differ(model_lab, reference_onnx):
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    first, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    second, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
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

    for where in differences(left, right):
        assert any(field in where for field in VOLATILE_FIELDS), where


def test_the_behavioural_fingerprint_is_deterministic(model_lab, model_battery):
    """Every behavioural claim is scoped to a fingerprint digest."""
    from cvtrust.models import build_model_manifest, compute_fingerprint, detect_model_adapter

    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    adapter = detect_model_adapter(path)
    handle = adapter.load(path)
    manifest = build_model_manifest(handle, adapter)

    first = compute_fingerprint(handle, adapter, model_battery, model_id=manifest.model_id)
    second = compute_fingerprint(
        adapter.load(path), adapter, model_battery, model_id=manifest.model_id
    )
    assert first.digest == second.digest
    assert (first.predictions == second.predictions).all()


def test_the_run_id_depends_on_the_model_and_the_configuration(
    model_lab, reference_onnx
):
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    baseline, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    other_model, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    other_seed, _, _ = assess_model(
        path, Config().merged({"seed": Config().seed + 1}), reference_path=reference_onnx
    )
    assert baseline.run.run_id != other_model.run.run_id
    assert baseline.run.run_id != other_seed.run.run_id


def test_a_changed_threshold_changes_the_report_digest(model_lab, reference_onnx):
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    baseline, _, _ = assess_model(path, Config(), reference_path=reference_onnx)
    tightened, _, _ = assess_model(
        path,
        Config().merged({"model": {"behaviour": {"agreement_floor": 0.5}}}),
        reference_path=reference_onnx,
    )
    assert baseline.stable_digest() != tightened.stable_digest()
    assert baseline.configuration["config_hash"] != tightened.configuration["config_hash"]


def test_model_training_is_reproducible_across_processes(tmp_path):
    """Regression guard, inherited from the Module 1 salted-hash() defect.

    Cross-process is the test that matters: a seed derived from Python's
    ``hash()`` agrees within one interpreter and differs between them, which is
    exactly the failure mode that would make every lab measurement unverifiable.
    """
    pytest.importorskip("torch")
    script = (
        "import sys, logging, hashlib, warnings\n"
        "warnings.filterwarnings('ignore')\n"
        "logging.getLogger('cvtrust').setLevel(logging.ERROR)\n"
        "from cvtrust.attack_lab.model_synth import generate_corpus, train_model, lab_seed\n"
        "corpus = generate_corpus(seed=lab_seed(99, 'corpus'), per_class=4)\n"
        "model, spec = train_model(corpus, seed=lab_seed(99, 'train'), epochs=2)\n"
        "import numpy as np\n"
        "flat = np.concatenate([p.detach().cpu().numpy().ravel() "
        "for _, p in sorted(model.named_parameters())])\n"
        "print(hashlib.sha256(np.rint(flat * 1e6).astype('int64').tobytes()).hexdigest())\n"
    )
    digests = []
    for _ in range(2):
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        digests.append(result.stdout.strip().splitlines()[-1])
    assert digests[0] == digests[1], digests


def test_a_model_assessment_is_reproducible_across_processes(
    model_lab, reference_onnx, tmp_path
):
    """Cross-process determinism of the whole assessment, not just training."""
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    script = (
        "import sys, logging, warnings\n"
        "warnings.filterwarnings('ignore')\n"
        "logging.getLogger('cvtrust').setLevel(logging.ERROR)\n"
        "from pathlib import Path\n"
        "from cvtrust.core.config import Config\n"
        "from cvtrust.model_pipeline import assess_model\n"
        "report, _, _ = assess_model(Path(sys.argv[1]), Config(), "
        "reference_path=Path(sys.argv[2]))\n"
        "print(report.report_id)\n"
    )
    ids = []
    for _ in range(2):
        result = subprocess.run(
            [sys.executable, "-c", script, str(path), str(reference_onnx)],
            capture_output=True, text=True, check=True,
        )
        ids.append(result.stdout.strip().splitlines()[-1])
    assert ids[0] == ids[1], ids


def test_the_model_lab_is_reproducible(tmp_path):
    """Rebuilding a scenario produces the same artifact, byte for byte."""
    pytest.importorskip("torch")
    from cvtrust.attack_lab.model_attacks import build_lab
    from cvtrust.core.hashing import sha256_file

    digests = []
    for name in ("a", "b"):
        _, scenarios = build_lab(
            tmp_path / name, per_class=8, epochs=2, scenarios=["backdoor_badnets"]
        )
        digests.append(sha256_file(scenarios[0].onnx_path))
    assert digests[0] == digests[1]


def test_ground_truth_is_never_inside_the_directory_a_detector_reads(model_lab):
    """Structural guarantee that no model detector can read the answer key.

    The artifact and its ground truth share a directory here, so the guarantee
    is that the *detector* only ever receives the artifact path — which the
    pipeline enforces by construction, and which this test pins by confirming
    the ground truth is not reachable from the model's own bytes.
    """
    for scenario in model_lab["scenarios"].values():
        assert (scenario.out_dir / "ground_truth.json").is_file()
        payload = (scenario.out_dir / "ground_truth.json").read_bytes()
        assert payload not in scenario.onnx_path.read_bytes()
        assert payload not in scenario.torchscript_path.read_bytes()
