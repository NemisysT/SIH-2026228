"""Module 4 reproducibility.

The claim the problem statement asks for is narrow and checkable: *the same
model, provenance records, reference population, configuration, policy version,
seed and software version must produce the same assurance decision and an
equivalent report digest*, with timestamps and runtime measurements excluded.

Three separate properties hold this up, and each can fail without the others
noticing:

**The measurement is reproducible.**  Every permutation null draws from a named
``RunContext`` stream, so two shift analyses over the same two populations
return the same p-values, not merely the same verdict.

**The decision is reproducible.**  Evidence ids are content-addressed, families
are a fixed table, and the rule set is evaluated in a fixed order, so the fired
rules and their order are stable.

**The report is comparable.**  ``stable_digest`` excludes exactly the fields
that legitimately move between runs.  A digest that changed whenever the clock
did would be unusable for regression, and one that ignored the policy version
would be dishonest.
"""

from __future__ import annotations

import pytest

from cvtrust.assurance.evidence import normalise
from cvtrust.assurance.fuse import FusionInputs, ModuleInput, fuse
from cvtrust.assurance.policy import AssurancePolicyEngine
from cvtrust.assurance_pipeline import assess_pipeline, characterise_shift
from cvtrust.core.config import Config
from cvtrust.core.context import DIGEST_EXCLUDED_FIELDS
from cvtrust.shift.context import OperationalContext

pytestmark = pytest.mark.slow


def run_shift(pair, config=None, seed=None):
    config = config or Config()
    if seed is not None:
        config = config.model_copy(update={"seed": seed})
    assessment, _ = characterise_shift(
        pair.reference_root,
        pair.current_root,
        config,
        reference_context=OperationalContext.from_mapping(pair.reference_context),
        current_context=OperationalContext.from_mapping(pair.current_context),
    )
    return assessment


@pytest.fixture(scope="module")
def dataset_report(tmp_path_factory, clean_root):
    from cvtrust.pipeline import analyse

    report, _, _ = analyse(clean_root, Config())
    path = tmp_path_factory.mktemp("m1-det") / "dataset.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The measurement
# ---------------------------------------------------------------------------


def test_the_same_two_populations_measure_identically(assurance_lab):
    """Not just the same verdict: the same statistics and the same p-values."""
    first = run_shift(assurance_lab.pair("operational_illumination"))
    second = run_shift(assurance_lab.pair("operational_illumination"))
    assert first.assessment_id == second.assessment_id
    assert first.verdict is second.verdict
    assert [m.metric for m in first.metrics] == [m.metric for m in second.metrics]
    for metric, other in zip(first.metrics, second.metrics, strict=True):
        assert metric.statistic == other.statistic, metric.metric
        assert metric.p_value == other.p_value, metric.metric
        assert metric.status is other.status, metric.metric


def test_the_assessment_id_is_content_addressed_not_a_counter(assurance_lab):
    """Two different comparisons must not collide, and must not be sequential."""
    first = run_shift(assurance_lab.pair("clean_baseline"))
    second = run_shift(assurance_lab.pair("operational_sensor"))
    assert first.assessment_id != second.assessment_id
    assert first.assessment_id.startswith("S-")


def test_the_reference_identity_is_stable_across_runs(clean_shift, assurance_lab):
    again = run_shift(assurance_lab.pair("clean_baseline"))
    assert again.reference["digest"] == clean_shift.reference["digest"]
    assert again.reference["reference_id"] == clean_shift.reference["reference_id"]


def test_a_different_seed_moves_the_p_values_and_not_the_verdict(assurance_lab):
    """Measured, not assumed.

    A permutation null is a Monte Carlo estimate, so a different seed is a
    different draw. The verdict is required to survive that; the p-values are
    NOT required to be identical, and asserting that they were would be
    asserting the seed did nothing.
    """
    pair = assurance_lab.pair("operational_illumination")
    default = run_shift(pair)
    other = run_shift(pair, seed=987654)
    assert other.verdict is default.verdict
    assert other.assessment_id != default.assessment_id


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def shift_finding(unexplained_shift):
    """A real Module 4 finding, emitted by the real factory."""
    from cvtrust.risk.calibration import CalibrationSet
    from cvtrust.risk.disposition import DispositionPolicy
    from cvtrust.shift.findings import findings_for_shift

    config = Config()
    findings = findings_for_shift(
        unexplained_shift,
        calibration=CalibrationSet.load(config.calibration_path),
        policy=DispositionPolicy(config.disposition),
        locator="lab://undeclared_illumination",
    )
    assert findings, "the unexplained-shift scenario must emit a finding"
    return findings[0]


def test_the_same_shift_emits_the_same_finding_id(unexplained_shift, shift_finding):
    """Finding identity is content-addressed upstream (ADR-003) and stays so."""
    from cvtrust.risk.calibration import CalibrationSet
    from cvtrust.risk.disposition import DispositionPolicy
    from cvtrust.shift.findings import findings_for_shift

    config = Config()
    again = findings_for_shift(
        unexplained_shift,
        calibration=CalibrationSet.load(config.calibration_path),
        policy=DispositionPolicy(config.disposition),
        locator="lab://undeclared_illumination",
    )
    assert [f.finding_id for f in again] == [shift_finding.finding_id]


def test_normalising_the_same_finding_twice_gives_the_same_evidence_id(shift_finding):
    first = normalise(shift_finding, source_module=4, source_report_id="R-fixed")
    second = normalise(shift_finding, source_module=4, source_report_id="R-fixed")
    assert first.evidence_id == second.evidence_id
    assert first.evidence_id.startswith("E-")


def test_the_same_finding_from_a_different_report_is_a_different_evidence_item(
    shift_finding,
):
    """Provenance of the observation is part of its identity.

    The same detector output cited from two different upstream reports is two
    citations, and collapsing them would let one report's finding silently
    stand in for another's.
    """
    a = normalise(shift_finding, source_module=4, source_report_id="R-one")
    b = normalise(shift_finding, source_module=4, source_report_id="R-two")
    assert a.evidence_id != b.evidence_id
    assert a.finding_id == b.finding_id


def test_normalisation_does_not_touch_the_finding(shift_finding):
    """Section 13 of the specification, asserted rather than assumed."""
    before = shift_finding.model_dump_json()
    normalise(shift_finding, source_module=4, source_report_id="R-one")
    assert shift_finding.model_dump_json() == before


def test_two_fusions_over_the_same_inputs_decide_identically(
    dataset_report, clean_shift
):
    first, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    second, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    assert first.decision.disposition is second.decision.disposition
    assert [r.rule_id for r in first.decision.fired_rules] == [
        r.rule_id for r in second.decision.fired_rules
    ]
    assert first.decision.decision_id == second.decision.decision_id


def test_the_order_findings_arrive_in_does_not_change_the_decision(dataset_report):
    """Evidence is a set of facts, not a stream.

    If reversing the input order moved the disposition, the engine would be
    order-dependent and two analysts running the same reports could disagree.
    """
    from cvtrust.assurance_pipeline import load_module_input

    module_input = load_module_input(dataset_report, module=1, expect_module="1")
    forward = fuse(
        FusionInputs(dataset=module_input), Config(), policy=AssurancePolicyEngine()
    )
    reversed_input = ModuleInput(
        module=1,
        findings=list(reversed(module_input.findings)),
        report_id=module_input.report_id,
        run_id=module_input.run_id,
        coverage=module_input.coverage,
        asset=module_input.asset,
    )
    backward = fuse(
        FusionInputs(dataset=reversed_input), Config(), policy=AssurancePolicyEngine()
    )
    assert forward.decision.disposition is backward.decision.disposition
    assert [r.rule_id for r in forward.decision.fired_rules] == [
        r.rule_id for r in backward.decision.fired_rules
    ]
    assert forward.decision.decision_id == backward.decision.decision_id


def test_the_evidence_summary_is_stable(dataset_report, clean_shift):
    first, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    second, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    assert first.evidence_summary == second.evidence_summary


# ---------------------------------------------------------------------------
# The report digest
# ---------------------------------------------------------------------------


def test_two_reports_over_the_same_inputs_share_a_stable_digest(
    dataset_report, clean_shift
):
    first, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    second, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    assert first.stable_digest() == second.stable_digest()
    # Measured: the run id is itself derived from seed, config hash and inputs,
    # so two runs of the same analysis share it. The digest is therefore not
    # carrying the weight of hiding a difference here -- the next test makes a
    # difference on purpose and shows the digest survives it.
    assert first.run.run_id == second.run.run_id
    assert first.report_id == second.report_id


def test_timestamps_and_timings_do_not_enter_the_digest(dataset_report, clean_shift):
    """The exclusion list, exercised rather than recited."""
    report, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    moved = report.model_copy(
        update={
            "generated_at": "2099-01-01T00:00:00Z",
            "run": report.run.model_copy(
                update={
                    "started_at": "2099-01-01T00:00:00Z",
                    "finished_at": "2099-01-01T00:00:01Z",
                    "duration_ms": 999_999,
                    "timings_ms": {"fusion": 999_999},
                }
            ),
        }
    )
    assert moved.stable_digest() == report.stable_digest()
    assert moved.generated_at != report.generated_at


def test_the_excluded_fields_are_the_ones_that_actually_move(
    dataset_report, clean_shift
):
    """A digest that ignored the policy version would be worse than none."""
    for volatile in ("generated_at", "started_at", "finished_at", "duration_ms",
                     "timings_ms"):
        assert volatile in DIGEST_EXCLUDED_FIELDS
    # Filesystem locations are excluded too: the same evidence assessed from a
    # different directory is the same evidence.
    assert "root" in DIGEST_EXCLUDED_FIELDS
    # Nothing that carries meaning is excluded.
    for load_bearing in ("policy_version", "disposition", "rule_id", "severity",
                         "confidence", "coverage", "verdict"):
        assert load_bearing not in DIGEST_EXCLUDED_FIELDS


def test_changing_the_evidence_changes_the_digest(
    dataset_report, clean_shift
):
    with_shift, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    without_shift, _ = assess_pipeline(Config(), dataset_report=dataset_report)
    assert with_shift.stable_digest() != without_shift.stable_digest()


def test_changing_the_policy_version_changes_the_digest(
    monkeypatch, dataset_report, clean_shift
):
    """The digest must bind the rules that produced it.

    Two runs that reach ACCEPT under different rule tables are not the same
    result, and a regression baseline that could not tell them apart would
    silently absorb a policy change.
    """
    before, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    monkeypatch.setattr(AssurancePolicyEngine, "version", "99.99-test")
    after, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    assert after.policy["policy_version"] == "99.99-test"
    assert after.stable_digest() != before.stable_digest()


def test_changing_the_configuration_changes_the_digest(dataset_report, clean_shift):
    strict = Config()
    strict = strict.model_copy(
        update={
            "assurance": strict.assurance.model_copy(
                update={"corroboration_min_confidence": 0.99}
            )
        }
    )
    default_report, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    strict_report, _ = assess_pipeline(
        strict, dataset_report=dataset_report, shift=clean_shift
    )
    assert strict_report.stable_digest() != default_report.stable_digest()


def test_the_report_round_trips_through_json_unchanged(dataset_report, clean_shift):
    """Serialisation must not be where reproducibility is lost."""
    import json

    from cvtrust.reporting.assurance_report import PipelineAssuranceReport

    report, _ = assess_pipeline(
        Config(), dataset_report=dataset_report, shift=clean_shift
    )
    restored = PipelineAssuranceReport.model_validate(
        json.loads(report.model_dump_json())
    )
    assert restored.stable_digest() == report.stable_digest()
    assert restored.decision.disposition is report.decision.disposition


# ---------------------------------------------------------------------------
# The lab
# ---------------------------------------------------------------------------


def test_the_assurance_lab_rebuilds_identically(tmp_path):
    """The synthetic corpora must be regenerable, or nothing above is checkable."""
    from cvtrust.attack_lab.assurance_scenarios import build_lab

    first = build_lab(tmp_path / "a", seed=11, per_class_per_contributor=2)
    second = build_lab(tmp_path / "b", seed=11, per_class_per_contributor=2)
    assert _digest_tree(first.baseline_root) == _digest_tree(second.baseline_root)
    for a, b in zip(first.pairs, second.pairs, strict=True):
        assert a.name == b.name
        assert _digest_tree(a.current_root) == _digest_tree(b.current_root), a.name


def _digest_tree(root) -> list[tuple[str, str]]:
    import hashlib
    from pathlib import Path

    out = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            out.append((
                str(path.relative_to(root)),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            ))
    return out
