"""Adversarial tests: attacks chosen to be *outside* the detectors' assumptions.

The point of this file is to fail usefully.  A test suite that only contains
attacks matching the detector's assumptions measures nothing, so these cases are
selected to sit outside them, and the assertion is that the system **reports
degraded coverage** rather than either detecting what it cannot detect or
quietly returning a clean result.

Where a test asserts a miss, that is not a defect being tolerated — it is a
documented coverage boundary being pinned, so that the code and
``docs/model-security.md`` cannot drift apart.
"""

from __future__ import annotations

import numpy as np
import pytest

from cvtrust.core.config import Config
from cvtrust.core.evidence import Coverage, Severity
from cvtrust.model_pipeline import assess_model
from cvtrust.models.battery import apply_trigger, build_battery
from cvtrust.reporting.model_report import AssessmentStatus

pytestmark = [pytest.mark.slow, pytest.mark.adversarial]


# ---------------------------------------------------------------------------
# Clean models that look unusual — the false-positive pressure cases
# ---------------------------------------------------------------------------


def test_a_clean_model_with_unusual_weights_is_not_called_backdoored(
    model_lab, reference_onnx
):
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_unusual_init"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR
    backdoor = [
        f for f in report.findings
        if f.attack_class == "model_backdoor" and f.severity is not Severity.INFO
    ]
    assert not backdoor, "unusual weights must not become a backdoor claim"


def test_a_clean_retrained_model_produces_no_backdoor_finding(
    model_lab, reference_onnx
):
    """The commonest benign event in a real pipeline."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR


def test_out_of_distribution_input_is_never_treated_as_a_backdoor(
    model_lab, reference_onnx
):
    """Module 1's rule, applied to models.

    The battery deliberately contains out-of-distribution probes, on which any
    model behaves oddly. That must contribute context, never a backdoor claim.
    """
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    behaviour = [f for f in report.findings if f.method == "model_behaviour"]
    for finding in behaviour:
        assert "ood" not in finding.attack_class
    assert report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR


def test_unusual_weights_do_not_reach_a_severe_disposition_on_their_own(
    model_lab
):
    """With no reference, peer screening is all there is, and it is capped."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_unusual_init"].onnx_path,
        Config(), reference_path=None,
    )
    for finding in report.findings:
        if finding.method == "model_parameters":
            assert finding.severity <= Severity.MEDIUM or finding.severity is Severity.MEDIUM
            assert finding.disposition.value != "QUARANTINE"


# ---------------------------------------------------------------------------
# Triggers outside the declared family — expected, documented misses
# ---------------------------------------------------------------------------


def _probe_asr(model_path, trigger, seed=20260917):
    """Attack success rate of one specific trigger against one model."""
    from cvtrust.models import detect_model_adapter
    from cvtrust.models.trigger import probe_trigger_family

    adapter = detect_model_adapter(model_path)
    handle = adapter.load(model_path)
    battery = build_battery(seed=seed, input_shape=(3, 32, 32))
    result = probe_trigger_family(handle, adapter, battery, family=[trigger])
    return result["per_trigger"][0]["attack_success_rate"]


def test_the_probe_only_covers_the_family_it_declares(model_lab):
    """A trigger the family does not contain is outside the claim, by construction."""
    from cvtrust.models import detect_model_adapter
    from cvtrust.models.trigger import probe_trigger_family

    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    adapter = detect_model_adapter(path)
    handle = adapter.load(path)
    battery = build_battery(seed=20260917, input_shape=(3, 32, 32))
    result = probe_trigger_family(handle, adapter, battery)

    assert result["family_size"] == len(battery.trigger_family)
    assert "finds a trigger only if the trigger is in the family" in result["coverage_note"]
    # And the finding built from it must never be labelled reconstruction.
    assert result["method"] == "trigger_family_probe"
    assert "not trigger reconstruction" in result["origin"]


def test_a_very_low_opacity_trigger_degrades_the_probe(model_lab):
    """Blended attacks (Chen et al. 2017) sit outside the full-opacity family.

    Asserting the degradation rather than the detection: this is the documented
    boundary, and if it ever moved silently the coverage table would be wrong.
    """
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    strong = {"position": "bottom_right", "size_fraction": 0.20, "pattern": "white"}
    faint = {**strong, "opacity": 0.05}
    assert _probe_asr(path, faint) < _probe_asr(path, strong)


def test_a_trigger_at_an_untested_position_is_less_effective(model_lab):
    """Position matters, which is exactly why the family sweeps positions."""
    path = model_lab["scenarios"]["backdoor_badnets"].onnx_path
    # The lab's badnets trigger is bottom-right; the opposite corner is not it.
    matched = _probe_asr(
        path, {"position": "bottom_right", "size_fraction": 0.20, "pattern": "white"}
    )
    mismatched = _probe_asr(
        path, {"position": "top_left", "size_fraction": 0.20, "pattern": "white"}
    )
    assert matched >= mismatched


def test_coverage_is_partial_whenever_reconstruction_did_not_run(
    model_lab, reference_onnx
):
    """An ONNX artifact cannot support reconstruction, and must say PARTIAL."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    trigger_entries = [
        e for e in report.coverage.entries if e.attack_class == "model_backdoor"
    ]
    assert trigger_entries
    assert all(e.coverage is not Coverage.SUPPORTED for e in trigger_entries)


def test_unsupported_trigger_families_are_declared_in_every_finding(
    model_lab, reference_onnx
):
    """The list of what is NOT covered must travel with the claim."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    trigger = [f for f in report.findings if f.method == "model_trigger"][0]
    joined = " ".join(trigger.limitations).lower()
    for uncovered in ("sample-specific", "semantic", "adaptive"):
        assert uncovered in joined, f"{uncovered} backdoors must be declared uncovered"


# ---------------------------------------------------------------------------
# Neural Cleanse's measured discrimination limit
# ---------------------------------------------------------------------------


def test_neural_cleanse_declares_its_anomaly_index_uninterpretable_at_low_class_count(
    model_lab
):
    """Measured: at six classes the index does not separate clean from backdoored.

    Rather than reporting a number whose threshold does not mean what it
    implies, the implementation declares the index uninterpretable and falls
    back to reporting the per-class mask ranking as evidence.
    """
    from cvtrust.models import detect_model_adapter
    from cvtrust.models.trigger import reconstruct_triggers

    path = model_lab["scenarios"]["backdoor_badnets"].torchscript_path
    adapter = detect_model_adapter(path)
    handle = adapter.load(path)
    battery = build_battery(seed=20260917, input_shape=(3, 32, 32))
    result = reconstruct_triggers(
        handle, adapter, battery, n_classes=6, seed=1, steps=60
    )
    assert result["anomaly_index_interpretable"] is False
    assert "MAD" in result["anomaly_index_uninterpretable_reason"]
    assert result["flagged_classes"] == [], "an uninterpretable index must flag nothing"
    # The ranking is still reported, because it is genuinely informative.
    assert result["smallest_mask_class"] is not None
    assert result["mask_l1_ratio_to_next"] is not None


# ---------------------------------------------------------------------------
# Evasion of the identity check
# ---------------------------------------------------------------------------


def test_renaming_an_artifact_does_not_change_its_identity(model_lab, tmp_path):
    """Identity is content, so a rename is not an evasion."""
    import shutil

    from cvtrust.models import build_model_manifest, detect_model_adapter

    original = model_lab["scenarios"]["substitution_architecture"].onnx_path
    disguised = tmp_path / "reference.onnx"  # named like the trusted artifact
    shutil.copy2(original, disguised)

    adapter = detect_model_adapter(disguised)
    manifest = build_model_manifest(adapter.load(disguised), adapter)
    reference_adapter = detect_model_adapter(model_lab["reference"].onnx_path)
    reference = build_model_manifest(
        reference_adapter.load(model_lab["reference"].onnx_path), reference_adapter
    )
    assert manifest.file_sha256 != reference.file_sha256


def test_declared_metadata_cannot_launder_a_substituted_model(
    model_lab, reference_onnx
):
    """The substituted model keeps the reference's architecture name on purpose."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["substitution_architecture"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    # It claims to be the same architecture...
    assert report.model["architecture_declared"] == "cvtrust_small_cnn"
    # ...and is caught anyway, because the claim plays no part in the decision.
    assert report.assessment.identity.status is AssessmentStatus.MISMATCH
    assert report.assessment.structure.status is AssessmentStatus.MISMATCH
    identity = [f for f in report.findings if f.method == "model_identity"][0]
    metadata = {item.kind: item.observation for item in identity.evidence}
    assert metadata["declared_metadata"]["used_in_identity_decision"] is False


# ---------------------------------------------------------------------------
# Deserialisation safety
# ---------------------------------------------------------------------------


def test_a_module_pickle_is_refused_by_default(tmp_path):
    """Loading an untrusted pickle executes code; the default must refuse."""
    torch = pytest.importorskip("torch")

    from cvtrust.core.errors import AdapterError
    from cvtrust.models.torch_adapter import TorchModelAdapter

    path = tmp_path / "module.pt"
    torch.save(torch.nn.Linear(2, 2), path)

    adapter = TorchModelAdapter()
    with pytest.raises(AdapterError) as excinfo:
        adapter.load(path)
    message = str(excinfo.value)
    assert "weights_only=True" in message
    assert "would execute code" in message
    assert "--allow-unsafe-deserialisation" in message


def test_a_state_dict_loads_safely_but_offers_no_behavioural_analysis(tmp_path):
    """Weights without a graph: white-box for parameters, nothing else."""
    torch = pytest.importorskip("torch")

    from cvtrust.models.base import Capability
    from cvtrust.models.torch_adapter import TorchModelAdapter

    path = tmp_path / "state.pt"
    torch.save(torch.nn.Linear(4, 3).state_dict(), path)

    handle = TorchModelAdapter().load(path)
    assert handle.has(Capability.PARAMETERS)
    assert not handle.has(Capability.INFERENCE)
    assert "inference" in handle.unavailable
    assert "graph" in handle.unavailable


def test_a_state_dict_assessment_reports_every_behavioural_level_unassessed(tmp_path):
    torch = pytest.importorskip("torch")

    from cvtrust.models.torch_adapter import TorchModelAdapter

    path = tmp_path / "state.pt"
    torch.save(torch.nn.Linear(4, 3).state_dict(), path)

    report, _, _ = assess_model(path, Config(), adapter_name="torch")
    for level in ("behaviour", "activation", "trigger"):
        status = getattr(report.assessment, level).status
        assert status in (
            AssessmentStatus.NOT_ASSESSED, AssessmentStatus.REQUIRES_WHITE_BOX
        ), f"{level} must not be reported as clean on a state dict"
        assert getattr(report.assessment, level).reason


def test_an_out_of_family_blended_backdoor_is_missed_as_documented(tmp_path):
    """The documented coverage boundary, pinned so it cannot drift silently.

    `backdoor_blended_faint` is a Chen et al. blended trigger at opacity 0.08,
    deliberately constructed to sit OUTSIDE the full-opacity patch family the
    gradient-free probe sweeps. Its ground truth records
    `trigger_in_declared_probe_family: false` and says in advance that the probe
    is expected to miss it.

    This test asserts the miss. If a future change made the probe catch it, that
    would be good news — and this test failing is how we would find out, rather
    than the coverage table quietly becoming wrong in the other direction.
    """
    import json

    pytest.importorskip("torch")
    from cvtrust.attack_lab.model_attacks import build_lab

    reference, scenarios = build_lab(
        tmp_path / "lab", per_class=30, epochs=20,
        scenarios=["backdoor_blended_faint"],
    )
    scenario = scenarios[0]
    truth = json.loads((scenario.out_dir / "ground_truth.json").read_text())

    # The lab must declare, in advance, that this trigger is out of family.
    assert truth["trigger_in_declared_probe_family"] is False
    # And the backdoor must genuinely be installed, or the miss proves nothing.
    assert float(truth["effectiveness"]["attack_success_rate"]) > 0.5

    report, _, _ = assess_model(
        scenario.onnx_path, Config(), reference_path=reference.onnx_path
    )
    assert report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR, (
        "an out-of-family blended trigger being detected would be welcome, but "
        "docs/model-security.md §5 and docs/limitations.md both state it is "
        "missed — update them together with this test"
    )
    # The coverage entry must still declare the family bound that caused the miss.
    entries = [e for e in report.coverage.entries if e.attack_class == "model_backdoor"]
    assert any(e.coverage is Coverage.PARTIAL for e in entries)
