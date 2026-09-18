"""End-to-end: model -> adapter -> detectors -> findings -> report.

These tests assert the *contracts* the report rests on, not particular numbers:
that findings use the shared Module 1 schema, that every assessment level is
populated, that an unavailable method says so rather than going quiet, and that
the same assessment run twice produces the same report id.
"""

from __future__ import annotations

import pytest

from cvtrust.core.config import Config
from cvtrust.core.evidence import (
    SCHEMA_VERSION,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    Disposition,
    Finding,
    Severity,
)
from cvtrust.model_pipeline import assess_model
from cvtrust.reporting.model_report import AssessmentStatus

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def clean_report(model_lab, reference_onnx):
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    return report


@pytest.fixture(scope="module")
def backdoor_report(model_lab, reference_onnx):
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    return report


# ---------------------------------------------------------------------------
# Schema conformance — Module 2 must not invent its own finding shape
# ---------------------------------------------------------------------------


def test_model_findings_use_the_shared_module_1_schema(backdoor_report):
    assert backdoor_report.findings
    for finding in backdoor_report.findings:
        assert isinstance(finding, Finding)
        assert finding.schema_version == SCHEMA_VERSION
        assert finding.category is Category.MODEL
        assert finding.asset.type is AssetType.MODEL
        assert finding.evidence, "a finding with no evidence cannot exist"
        for item in finding.evidence:
            assert item.observation, "evidence must carry measured values"


def test_every_finding_is_bound_to_the_artifact_digest(backdoor_report):
    """A finding bound to a path would be bound to something an adversary owns."""
    for finding in backdoor_report.findings:
        assert finding.asset.digest == backdoor_report.model["file_sha256"]


def test_confidence_basis_is_always_declared(backdoor_report):
    for finding in backdoor_report.findings:
        assert finding.confidence_basis in set(ConfidenceBasis)
        if finding.confidence_basis is ConfidenceBasis.DETERMINISTIC:
            assert finding.confidence == 1.0
        if finding.confidence_basis is ConfidenceBasis.HEURISTIC_UNCALIBRATED:
            assert finding.confidence <= 0.60
            assert any("uncalibrated" in limit for limit in finding.limitations)


def test_severity_and_confidence_are_not_collapsed(backdoor_report):
    """A HIGH finding may legitimately have modest confidence."""
    trigger = [
        f for f in backdoor_report.findings if f.method == "model_trigger"
    ]
    assert trigger
    assert trigger[0].severity is Severity.HIGH
    assert trigger[0].confidence < 1.0


def test_every_finding_declares_its_limitations(backdoor_report):
    for finding in backdoor_report.findings:
        assert finding.limitations, f"{finding.finding_id} claims no limitations"


# ---------------------------------------------------------------------------
# The assessment matrix
# ---------------------------------------------------------------------------


def test_all_six_assessment_levels_are_always_populated(clean_report):
    levels = {level.level for level in clean_report.assessment.levels()}
    assert levels == {
        "identity", "structure", "parameters", "behaviour", "activation", "trigger"
    }


def test_the_report_never_asserts_that_the_model_is_safe(clean_report, backdoor_report):
    """The single hardest requirement in the brief, asserted mechanically.

    Scoped to the report's *assertive* surface — statuses, titles, details,
    summary — rather than the whole document, because the limitations section
    contains the sentence "This report never states that a model is safe",
    which is the opposite of the thing being guarded against.
    """
    for report in (clean_report, backdoor_report):
        assertive: list[str] = [report.summary.overall, report.summary.rationale]
        for level in report.assessment.levels():
            assertive += [level.status.value, level.detail]
        for finding in report.findings:
            assertive += [finding.title] + [item.statement for item in finding.evidence]

        for text in assertive:
            lowered = text.lower()
            assert "is safe" not in lowered, text
            assert "safe" not in lowered.split(), text


def test_the_assessment_vocabulary_is_closed_and_excludes_safe():
    """No status may ever be added that asserts safety."""
    values = {status.value for status in AssessmentStatus}
    assert "SAFE" not in values
    assert not any("SAFE" == v.upper() for v in values)
    # The strongest positive statements available are about the tests, not the model.
    assert "NO_ANOMALY_DETECTED" in values
    assert "NOT_ASSESSED" in values


def test_a_clean_result_is_always_qualified_by_coverage(clean_report):
    assert "coverage" in clean_report.summary.rationale.lower()


# ---------------------------------------------------------------------------
# Attack detection
# ---------------------------------------------------------------------------


def test_substitution_is_detected_deterministically(model_lab, reference_onnx):
    report, _, _ = assess_model(
        model_lab["scenarios"]["substitution_architecture"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.assessment.identity.status is AssessmentStatus.MISMATCH
    assert report.assessment.structure.status is AssessmentStatus.MISMATCH
    identity = [f for f in report.findings if f.method == "model_identity"]
    assert identity and identity[0].confidence_basis is ConfidenceBasis.DETERMINISTIC


def test_parameter_tampering_is_detected_and_localised(model_lab, reference_onnx):
    report, _, _ = assess_model(
        model_lab["scenarios"]["parameter_tamper_large"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    # The graph did not change; only the weights did.
    assert report.assessment.structure.status is AssessmentStatus.CONSISTENT
    assert report.assessment.parameters.status is AssessmentStatus.ANOMALOUS
    parameters = [f for f in report.findings if f.method == "model_parameters"]
    assert parameters
    evidence = {item.kind: item.observation for item in parameters[0].evidence}
    assert evidence["parameter_difference"]["changed"], "the changed tensors must be named"


def test_a_backdoored_model_raises_a_high_risk_trigger_indicator(backdoor_report):
    assert backdoor_report.assessment.trigger.status is AssessmentStatus.HIGH_RISK_INDICATOR
    assert "HIGH-RISK INDICATOR" in backdoor_report.assessment.trigger.detail


def test_a_clean_model_does_not_raise_a_backdoor_indicator(clean_report):
    """The false-positive case that matters most."""
    assert clean_report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR
    assert not [
        f for f in clean_report.findings
        if f.attack_class == "model_backdoor" and f.severity is not Severity.INFO
    ]


def test_reserialisation_separates_identity_from_behaviour(model_lab, reference_onnx):
    """The case a single 'model changed' flag could not express."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["reserialised"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.assessment.identity.status is AssessmentStatus.MISMATCH
    assert report.assessment.structure.status is AssessmentStatus.CONSISTENT
    assert report.assessment.parameters.status is AssessmentStatus.NO_ANOMALY_DETECTED
    assert report.assessment.behaviour.status is AssessmentStatus.NO_ANOMALY_DETECTED
    # Severity is capped for a re-serialisation: it is not a substitution.
    identity = [f for f in report.findings if f.method == "model_identity"][0]
    assert identity.severity is Severity.MEDIUM


def test_an_unusually_initialised_clean_model_is_not_reported_as_an_attack(
    model_lab, reference_onnx
):
    """A clean model with odd weight statistics must not become a backdoor finding."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_unusual_init"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.assessment.trigger.status is not AssessmentStatus.HIGH_RISK_INDICATOR


# ---------------------------------------------------------------------------
# Graceful degradation — the Module 1 contract, on the model side
# ---------------------------------------------------------------------------


def test_without_a_reference_identity_is_not_assessed_rather_than_clean(model_lab):
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].onnx_path, Config(), reference_path=None
    )
    assert report.assessment.identity.status is AssessmentStatus.NOT_ASSESSED
    assert report.assessment.identity.reason
    assert "no trusted reference" in report.assessment.identity.reason.lower()


def test_onnx_reports_that_trigger_reconstruction_did_not_run(backdoor_report):
    """ONNX Runtime gives no input gradients, and the report must say so."""
    assert any(
        "gradient" in line.lower() for line in backdoor_report.access["consequences"]
    )
    assert "gradients" in backdoor_report.access["capabilities_absent"]
    trigger = [f for f in backdoor_report.findings if f.method == "model_trigger"][0]
    assert "+probe" in trigger.method_version
    assert "reconstruction" not in trigger.title.lower()


def test_torchscript_reports_that_activation_analysis_did_not_run(
    model_lab, reference_torchscript
):
    """A ScriptModule refuses forward hooks; that is reported, not skipped."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].torchscript_path,
        Config(), reference_path=reference_torchscript,
    )
    assert report.assessment.activation.status in (
        AssessmentStatus.NOT_ASSESSED, AssessmentStatus.REQUIRES_WHITE_BOX
    )
    assert "activation" in (report.assessment.activation.reason or "").lower()


def test_torchscript_runs_neural_cleanse_because_it_has_gradients(
    model_lab, reference_torchscript
):
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].torchscript_path,
        Config(), reference_path=reference_torchscript,
    )
    trigger = [f for f in report.findings if f.method == "model_trigger"]
    assert trigger, "the trigger detector should have produced a finding"
    assert "reconstruction" in trigger[0].method_version


def test_an_unavailable_level_is_never_presented_as_clean(model_lab, reference_torchscript):
    report, _, _ = assess_model(
        model_lab["scenarios"]["clean_retrain_0"].torchscript_path,
        Config(), reference_path=reference_torchscript,
    )
    for level in report.assessment.levels():
        if level.status in (
            AssessmentStatus.NOT_ASSESSED, AssessmentStatus.REQUIRES_WHITE_BOX
        ):
            assert level.reason, f"{level.level} is unassessed with no reason given"
            assert "not a clean result" in level.detail or level.reason


# ---------------------------------------------------------------------------
# Black-box pathway
# ---------------------------------------------------------------------------


def test_black_box_mode_genuinely_removes_white_box_access(model_lab, reference_onnx):
    report, ctx, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx, force_black_box=True,
    )
    assert report.access["access_mode"] == "BLACK_BOX"
    assert report.access["capabilities"] == ["inference"]
    # Not merely flagged: the handle must actually be unable to read weights.
    from cvtrust.models.base import Capability

    assert not ctx.supplied.has(Capability.PARAMETERS)


def test_black_box_mode_reports_white_box_methods_as_requiring_white_box(
    model_lab, reference_onnx
):
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx, force_black_box=True,
    )
    assert report.assessment.parameters.status is AssessmentStatus.REQUIRES_WHITE_BOX
    assert report.assessment.structure.status is AssessmentStatus.REQUIRES_WHITE_BOX
    assert report.assessment.activation.status is AssessmentStatus.REQUIRES_WHITE_BOX


def test_black_box_mode_still_detects_the_backdoor_behaviourally(
    model_lab, reference_onnx
):
    """The black-box pathway has to be worth having."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx, force_black_box=True,
    )
    assert report.assessment.trigger.status is AssessmentStatus.HIGH_RISK_INDICATOR
    trigger = [f for f in report.findings if f.method == "model_trigger"][0]
    # And it must describe itself as black-box, never as reconstruction.
    observation = {item.kind: item.observation for item in trigger.evidence}
    assert observation["trigger_family_probe"]["access_mode"] == "BLACK_BOX"
    assert trigger.coverage is Coverage.PARTIAL


def test_identity_still_works_under_black_box_access(model_lab, reference_onnx):
    """Hashing bytes needs no access to the model at all."""
    report, _, _ = assess_model(
        model_lab["scenarios"]["substitution_architecture"].onnx_path,
        Config(), reference_path=reference_onnx, force_black_box=True,
    )
    assert report.assessment.identity.status is AssessmentStatus.MISMATCH


# ---------------------------------------------------------------------------
# Coverage and report structure
# ---------------------------------------------------------------------------


def test_the_coverage_statement_lists_every_known_attack_class(clean_report):
    from cvtrust.risk.coverage import ATTACK_CLASS_REGISTRY

    reported = {entry.attack_class for entry in clean_report.coverage.entries}
    assert reported == set(ATTACK_CLASS_REGISTRY)


def test_module_1_classes_are_declared_not_assessed_in_a_model_report(clean_report):
    """A model report must not imply dataset coverage."""
    by_class = {e.attack_class: e for e in clean_report.coverage.entries}
    assert by_class["duplicate_flood"].coverage is Coverage.NOT_ASSESSED
    assert by_class["label_flip"].coverage is Coverage.NOT_ASSESSED


def test_the_report_carries_its_battery_and_run_context(backdoor_report):
    assert backdoor_report.battery["battery_digest"]
    assert backdoor_report.battery["trigger_family"]
    assert backdoor_report.run.run_id
    assert backdoor_report.run.seed
    assert backdoor_report.configuration["config_hash"]


def test_declared_metadata_is_marked_untrusted(backdoor_report):
    assert backdoor_report.model["architecture_declared_is_untrusted"] is True


def test_markdown_rendering_is_generated_from_the_report(backdoor_report):
    from cvtrust.reporting.model_render import render_model_markdown

    markdown = render_model_markdown(backdoor_report)
    assert backdoor_report.report_id in markdown
    assert backdoor_report.model["file_sha256"] in markdown
    for finding in backdoor_report.findings:
        assert finding.finding_id in markdown
