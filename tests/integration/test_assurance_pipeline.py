"""Module 4 end to end: shift over real imagery, fusion over real findings.

Every finding these tests fuse was produced by the real Module 1 and Module 3
pipelines.  Nothing here hand-writes evidence: the point of an integration test
is to catch the case where a rule fires on evidence no detector actually emits,
and a fixture written by the same author would hide exactly that.
"""

from __future__ import annotations

import json

import pytest

from cvtrust.assurance.policy import AssuranceDisposition, Scope
from cvtrust.assurance_pipeline import (
    IMPLEMENTED_MODULES,
    assess_pipeline,
    characterise_shift,
    exit_code_for,
)
from cvtrust.core.config import Config
from cvtrust.core.errors import ConfigError
from cvtrust.core.evidence import Coverage
from cvtrust.shift.characterize import ShiftVerdict
from cvtrust.shift.context import OperationalContext

pytestmark = pytest.mark.slow


def run_shift(pair, config=None):
    assessment, _ = characterise_shift(
        pair.reference_root,
        pair.current_root,
        config or Config(),
        reference_context=OperationalContext.from_mapping(pair.reference_context),
        current_context=OperationalContext.from_mapping(pair.current_context),
    )
    return assessment


@pytest.fixture(scope="module")
def dataset_report(tmp_path_factory, clean_root):
    """A real Module 1 report over the clean corpus."""
    from cvtrust.pipeline import analyse

    report, _, _ = analyse(clean_root, Config())
    path = tmp_path_factory.mktemp("m1") / "dataset.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def provenance_reports(tmp_path_factory, provenance_lab):
    """Real Module 3 reports: one clean log, one with a tampered output."""
    from cvtrust.provenance.chain import build_anchor
    from cvtrust.provenance.log import ProvenanceLog
    from cvtrust.provenance.replay import ReplayDatabase
    from cvtrust.provenance.trust import TrustStore
    from cvtrust.provenance_pipeline import verify_log

    out = tmp_path_factory.mktemp("m3")
    clean = provenance_lab["clean"]
    paths = {}

    report, _, _ = verify_log(
        clean.log,
        Config(),
        trust_store=clean.trust_store,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(clean.log.entries),
    )
    paths["clean"] = out / "provenance-clean.json"
    paths["clean"].write_text(report.model_dump_json(indent=2), encoding="utf-8")

    scenario = provenance_lab["scenarios"]["modified_output"]
    report, _, _ = verify_log(
        ProvenanceLog.load(scenario.log_path),
        Config(),
        trust_store=TrustStore.load(scenario.trust_store_path),
        replay_database=ReplayDatabase.empty(),
    )
    paths["tampered"] = out / "provenance-tampered.json"
    paths["tampered"].write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return paths


# ---------------------------------------------------------------------------
# Shift over real imagery
# ---------------------------------------------------------------------------


def test_two_draws_from_one_process_resolve_no_shift(clean_shift):
    """The headline false-positive measurement."""
    assert clean_shift.verdict is ShiftVerdict.NO_SHIFT_DETECTED
    assert not clean_shift.shift_observed()
    assert clean_shift.resolved()


def test_a_negative_result_is_never_reported_as_stability(clean_shift):
    assert "does not establish that the population is stable" in clean_shift.statement


def test_a_declared_night_collection_is_not_an_attack(declared_shift):
    assert declared_shift.verdict is ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT
    assert declared_shift.shift_observed()
    assert not declared_shift.context.unexplained_blocks
    assert any("not an attack" in l for l in declared_shift.limitations)


def test_the_same_change_undeclared_is_an_open_question(unexplained_shift):
    assert unexplained_shift.verdict is ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT
    assert unexplained_shift.context.unexplained_blocks


def test_a_six_sample_batch_is_refused_rather_than_answered(assurance_lab):
    """A real shift the system must decline to report."""
    assessment = run_shift(assurance_lab.pair("small_current_batch"))
    assert assessment.verdict is ShiftVerdict.INSUFFICIENT_SAMPLE
    assert not assessment.resolved()
    assert assessment.unassessed


def test_a_subset_reference_is_weaker_and_says_so(assurance_lab, tmp_path):
    """The weak form: the population under assessment is inside its own baseline."""
    root = assurance_lab.pair("clean_baseline").current_root
    ids = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*.jpg")
    )
    assessment, _ = characterise_shift(
        None, root, Config(), reference_sample_ids=ids[: len(ids) // 2]
    )
    assert assessment.reference["mode"] == "DECLARED_SUBSET"
    assert "not independent" in assessment.reference["caveat"]
    assert assessment.reference["shared_dataset_digest"]


def test_a_shift_analysis_without_a_reference_is_refused(clean_root):
    """It will not fabricate a NOT_ASSESSED it was never asked to produce."""
    with pytest.raises(ConfigError, match="needs a reference population"):
        characterise_shift(None, clean_root, Config())


def test_the_shift_finding_is_statistical_not_uncalibrated(declared_shift):
    """The omnibus test has a null, so its confidence has a basis."""
    from cvtrust.risk.calibration import CalibrationSet
    from cvtrust.risk.disposition import DispositionPolicy
    from cvtrust.shift.findings import findings_for_shift

    findings = findings_for_shift(
        declared_shift,
        calibration=CalibrationSet.empty(),
        policy=DispositionPolicy(Config().disposition),
    )
    assert len(findings) == 1
    assert findings[0].confidence_basis.value == "STATISTICAL"
    assert findings[0].severity.value == "INFO"  # explained by the declaration


def test_an_unexplained_shift_finding_is_medium_and_never_higher(unexplained_shift):
    from cvtrust.risk.calibration import CalibrationSet
    from cvtrust.risk.disposition import DispositionPolicy
    from cvtrust.shift.findings import findings_for_shift

    findings = findings_for_shift(
        unexplained_shift,
        calibration=CalibrationSet.empty(),
        policy=DispositionPolicy(Config().disposition),
    )
    assert findings[0].severity.value == "MEDIUM"


def test_no_shift_emits_no_finding(clean_shift):
    """An ACCEPT row in the findings table is noise an analyst reads past."""
    from cvtrust.risk.calibration import CalibrationSet
    from cvtrust.risk.disposition import DispositionPolicy
    from cvtrust.shift.findings import findings_for_shift

    assert (
        findings_for_shift(
            clean_shift,
            calibration=CalibrationSet.empty(),
            policy=DispositionPolicy(Config().disposition),
        )
        == []
    )


# ---------------------------------------------------------------------------
# Module 1 -> Module 4
# ---------------------------------------------------------------------------


def test_a_dataset_report_alone_is_fused_but_not_accepted(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    assert report.dataset_assurance.disposition == "ACCEPT"
    assert report.decision.disposition is AssuranceDisposition.NOT_ASSESSED
    unassessed = {a.area for a in report.decision.unassessed_areas if a.kind == "scope"}
    assert unassessed == {"model", "provenance", "distribution"}


def test_the_upstream_findings_are_carried_verbatim(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    original = json.loads(dataset_report.read_text(encoding="utf-8"))["findings"]
    carried = json.loads(report.model_dump_json())["source_findings"]
    assert len(carried) == len(original)
    assert {f["finding_id"] for f in carried} == {f["finding_id"] for f in original}
    for before, after in zip(
        sorted(original, key=lambda f: f["finding_id"]),
        sorted(carried, key=lambda f: f["finding_id"]),
    ):
        assert before == after, "an upstream finding was rewritten"


def test_a_malformed_upstream_finding_is_refused_not_fused(tmp_path):
    """A report handed to this command is an untrusted file like any other."""
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "module": "1: dataset forensics",
                "report_id": "R-x",
                "findings": [{"finding_id": "not-a-valid-id"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        assess_pipeline(Config(), dataset_report=path)


def test_a_report_of_the_wrong_module_is_refused(tmp_path, dataset_report):
    """Supplying a dataset report where a model report belongs must not pass."""
    with pytest.raises(ConfigError, match="declares module"):
        assess_pipeline(Config(), model_report=dataset_report)


# ---------------------------------------------------------------------------
# Module 3 -> Module 4
# ---------------------------------------------------------------------------


def test_a_tampered_record_quarantines(provenance_reports):
    report, _ = assess_pipeline(Config(), provenance_report=provenance_reports["tampered"])
    assert report.decision.disposition is AssuranceDisposition.QUARANTINE
    assert report.provenance_assurance.governing_rule == "RULE-PROV-001"


def test_a_clean_log_accepts_its_own_scope(provenance_reports):
    report, _ = assess_pipeline(Config(), provenance_report=provenance_reports["clean"])
    assert report.provenance_assurance.disposition == "ACCEPT"
    # The scope summary carries the statement; the narrowing caveat -- that this
    # is a statement about the RECORD, not about the inference or the model --
    # lives in the rule's rationale, which is what the analyst reads.
    rationale = next(
        rule.rationale
        for rule in report.decision.fired_rules
        if rule.rule_id == "RULE-PROV-010"
    )
    assert "integrity of the RECORD" in rationale
    assert "says nothing about" in rationale


# ---------------------------------------------------------------------------
# All modules -> fusion
# ---------------------------------------------------------------------------


def test_a_clean_dataset_and_a_tampered_record_keep_both_facts(
    dataset_report, provenance_reports, clean_shift
):
    """ADR-014 at the report level: one incident must not darken the other row."""
    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["tampered"],
        shift=clean_shift,
    )
    assert report.decision.disposition is AssuranceDisposition.QUARANTINE
    assert report.dataset_assurance.disposition == "ACCEPT"
    assert report.provenance_assurance.disposition == "QUARANTINE"
    assert report.distribution_assurance.disposition == "ACCEPT"


def test_a_declared_shift_over_a_clean_pipeline_accepts(
    dataset_report, provenance_reports, declared_shift
):
    """If this reviews, the tool is unusable in an operational deployment."""
    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["clean"],
        shift=declared_shift,
    )
    assert report.distribution_assurance.disposition == "ACCEPT"
    assert report.distribution_assurance.governing_rule == "RULE-SHIFT-020"


def test_an_undeclared_shift_reviews_and_never_quarantines(
    dataset_report, provenance_reports, unexplained_shift
):
    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["clean"],
        shift=unexplained_shift,
    )
    assert report.distribution_assurance.disposition == "REVIEW"
    assert report.decision.disposition is AssuranceDisposition.REVIEW


def test_shift_plus_a_cryptographic_failure_quarantines_on_the_crypto(
    dataset_report, provenance_reports, unexplained_shift
):
    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["tampered"],
        shift=unexplained_shift,
    )
    assert report.decision.disposition is AssuranceDisposition.QUARANTINE
    # The quarantine's lineage must lead to the provenance finding, not the shift.
    quarantining = [
        node for node in report.decision.lineage
        if node.disposition is AssuranceDisposition.QUARANTINE
    ]
    assert quarantining
    assert all(node.scope is Scope.PROVENANCE for node in quarantining)
    assert report.distribution_assurance.disposition == "REVIEW"


# ---------------------------------------------------------------------------
# The report contract
# ---------------------------------------------------------------------------


def test_the_report_carries_the_rule_table_it_executed(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    ids = {rule["id"] for rule in report.policy["rules"]}
    for outcome in report.decision.fired_rules:
        assert outcome.rule_id in ids


def test_the_report_names_what_was_not_assessed(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    assert report.decision.unassessed_areas
    for area in report.decision.unassessed_areas:
        assert area.reason
    classes = {a.area for a in report.decision.unassessed_areas if a.kind == "attack_class"}
    assert "model_backdoor" in classes
    assert "distribution_shift" in classes


def test_the_coverage_statement_declares_module_4(dataset_report, clean_shift):
    report, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "distribution_shift"
    )
    assert entry.coverage is Coverage.PARTIAL
    assert entry.detector == "distribution_shift"
    assert 4 in report.coverage.implemented_modules


def test_the_capability_matrix_is_populated(dataset_report, clean_shift):
    report, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    by_name = {e.capability: e for e in report.capabilities.entries}
    assert by_name["evidence_fusion"].coverage is Coverage.SUPPORTED
    assert by_name["evidence_dependency"].coverage is Coverage.SUPPORTED
    assert by_name["operational_drift"].coverage is Coverage.PARTIAL
    for entry in report.capabilities.entries:
        assert entry.reason


def test_the_capability_matrix_declares_an_unassessed_drift_check(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    entry = next(
        e for e in report.capabilities.entries if e.capability == "operational_drift"
    )
    assert entry.coverage is Coverage.NOT_ASSESSED
    assert "no reference population" in entry.reason


def test_every_fired_rule_has_lineage(dataset_report, provenance_reports, clean_shift):
    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["tampered"],
        shift=clean_shift,
    )
    rules_with_lineage = {node.rule_id for node in report.decision.lineage}
    fired = {outcome.rule_id for outcome in report.decision.fired_rules}
    assert fired == rules_with_lineage


def test_lineage_reaches_back_to_a_module_and_detector(provenance_reports):
    report, _ = assess_pipeline(Config(), provenance_report=provenance_reports["tampered"])
    cited = [node for node in report.decision.lineage if node.finding_id]
    assert cited
    node = cited[0]
    assert node.source_module == 3
    assert node.source_detector
    assert node.source_report_id


def test_the_markdown_rendering_is_generated_from_the_report(
    dataset_report, provenance_reports, clean_shift
):
    from cvtrust.reporting.assurance_render import render_assurance_markdown

    report, _ = assess_pipeline(
        Config(),
        dataset_report=dataset_report,
        provenance_report=provenance_reports["tampered"],
        shift=clean_shift,
    )
    markdown = render_assurance_markdown(report)
    assert report.decision.disposition.value in markdown
    assert "RULE-PROV-001" in markdown
    assert "## What was NOT assessed" in markdown
    assert "no trust score" in markdown.lower() or "no trust score" in str(report.limitations).lower()


def test_the_exit_code_distinguishes_clean_from_unexamined(dataset_report):
    report, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    assert exit_code_for(report) == 2  # NOT_ASSESSED, not 0


def test_implemented_modules_include_four():
    assert IMPLEMENTED_MODULES == (1, 2, 3, 4)
