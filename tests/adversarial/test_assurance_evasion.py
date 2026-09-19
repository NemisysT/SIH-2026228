"""Adversarial and false-positive behaviour of the assurance engine.

Sections 26 and 27 of the problem statement ask two questions that pull in
opposite directions, and this file answers both in one place on purpose,
because a system can only be judged on the pair:

*Does it escalate when it should?*  A real integrity failure must survive a
noisy run, a flood of irrelevant evidence, and a coincident legitimate shift.

*Does it stay quiet when it should?*  An unusual but legitimate condition — a
night collection, a new sensor, a small batch, a single over-eager detector,
five detectors that are really one detector — must not read as compromise.

The measurements that forced changes during development are recorded in the
docstrings of the tests that made them, not in a changelog, so the reason a
threshold has the value it has is next to the assertion that depends on it.
"""

from __future__ import annotations

import pytest

from cvtrust.assurance.evidence import build_graph
from cvtrust.assurance.families import EvidenceFamily
from cvtrust.assurance.policy import (
    AssuranceDisposition,
    AssurancePolicyEngine,
    PolicyState,
    Scope,
    overall,
)
from cvtrust.assurance_pipeline import assess_pipeline, characterise_shift
from cvtrust.core.config import Config
from cvtrust.core.evidence import (
    UNCALIBRATED_LIMITATION,
    ConfidenceBasis,
    Coverage,
    Severity,
)
from cvtrust.shift.characterize import ShiftAssessment, ShiftVerdict
from cvtrust.shift.context import OperationalContext

ENGINE = AssurancePolicyEngine()

ALL_SCOPES = {s: True for s in Scope}
NO_SCOPES = {s: False for s in Scope}


def state(evidence=(), *, shift=None, inputs=None, active=()):
    return PolicyState(
        graph=build_graph(list(evidence), extra_active_phenomena=list(active)),
        shift=shift,
        inputs=dict(inputs if inputs is not None else NO_SCOPES),
        coverage_gaps=(),
        accept_explained_shift=True,
    )


def fired(decisions) -> set[str]:
    return {o.rule_id for d in decisions for o in d.fired_rules}


def scope_of(decisions, scope):
    return next((d for d in decisions if d.scope is scope), None)


def shift_assessment(verdict: ShiftVerdict) -> ShiftAssessment:
    return ShiftAssessment(
        assessment_id="S-adv",
        verdict=verdict,
        statement=f"test assessment: {verdict.value}",
        reference={"reference_id": "REF-adv", "digest": "0" * 64, "sample_count": 120},
        current={"sample_count": 120},
        metrics=[],
    )


def run_shift(pair, config=None):
    assessment, _ = characterise_shift(
        pair.reference_root,
        pair.current_root,
        config or Config(),
        reference_context=OperationalContext.from_mapping(pair.reference_context),
        current_context=OperationalContext.from_mapping(pair.current_context),
    )
    return assessment


# ---------------------------------------------------------------------------
# 1. Correlated detectors are one phenomenon, not five
# ---------------------------------------------------------------------------


def test_five_detectors_in_one_family_are_one_unit_of_support(make_evidence):
    """The counting rule the whole fusion design rests on (section 15).

    Five near-duplicate detectors disagreeing about which pair is the duplicate
    is five reports of ONE phenomenon. Counting them as five independent
    observations would let a single noisy family manufacture corroboration.
    """
    evidence = [
        make_evidence(
            attack_class="near_duplicate_flood",
            detector=f"duplicate_detector_{i}",
            severity=Severity.HIGH,
            confidence=0.8,
            basis=ConfidenceBasis.STATISTICAL,
            discriminator=(f"pair-{i}",),
        )
        for i in range(5)
    ]
    graph = build_graph(evidence)
    assert len(graph.evidence) == 5
    assert len(graph.independent_families()) == 1
    group = graph.group(EvidenceFamily.DATASET_DUPLICATION)
    assert group.supporting == 5
    assert group.corroboration == 5  # five distinct detectors ...
    assert len(graph.independent_families()) == 1  # ... and one phenomenon


def test_the_same_detector_firing_repeatedly_does_not_corroborate_itself(
    make_evidence,
):
    """Twenty hits from one detector is one detector's opinion, twenty times."""
    evidence = [
        make_evidence(
            attack_class="near_duplicate_flood",
            detector="phash_duplicate",
            severity=Severity.HIGH,
            confidence=0.8,
            basis=ConfidenceBasis.STATISTICAL,
            discriminator=(f"pair-{i}",),
        )
        for i in range(20)
    ]
    graph = build_graph(evidence)
    assert graph.group(EvidenceFamily.DATASET_DUPLICATION).corroboration == 1


def test_independent_families_are_counted_separately(make_evidence):
    """The counting rule must not be so blunt that real corroboration vanishes."""
    graph = build_graph([
        make_evidence(attack_class="near_duplicate_flood", module=1),
        make_evidence(attack_class="label_flip", module=1),
        make_evidence(attack_class="model_backdoor", module=2),
    ])
    assert len(graph.independent_families()) == 3


# ---------------------------------------------------------------------------
# 2. One detector firing incorrectly
# ---------------------------------------------------------------------------


def test_a_single_statistical_detector_does_not_quarantine(make_evidence):
    """The false-positive budget: one uncorroborated statistical hit is REVIEW."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="label_flip",
                severity=Severity.HIGH,
                confidence=0.85,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.DATASET: True},
        )
    )
    dataset = scope_of(decisions, Scope.DATASET)
    assert dataset.disposition is AssuranceDisposition.REVIEW


def test_a_heuristic_uncalibrated_detector_cannot_drive_a_quarantine(make_evidence):
    """An uncalibrated score has no operational meaning (ADR-013)."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="model_backdoor",
                module=2,
                severity=Severity.CRITICAL,
                confidence=0.6,  # the schema cap for an uncalibrated score
                basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
                limitations=(UNCALIBRATED_LIMITATION,),
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True},
        )
    )
    model = scope_of(decisions, Scope.MODEL)
    assert model.disposition is not AssuranceDisposition.QUARANTINE


def test_a_detector_below_the_corroboration_floor_stays_visible(make_evidence):
    """Demoted is not deleted.

    Evidence under a floor must remain in the graph and in the lineage, or the
    report would answer 'nothing was observed' to a question whose real answer
    is 'something weak was observed and was not acted on'.
    """
    weak = make_evidence(
        attack_class="label_flip",
        severity=Severity.LOW,
        confidence=0.1,
        basis=ConfidenceBasis.STATISTICAL,
    )
    graph = build_graph([weak])
    item = graph.evidence[0]
    assert item.supports is False
    assert item.support_reason
    assert item.evidence_id in graph.group(EvidenceFamily.DATASET_LABELLING).evidence_ids


# ---------------------------------------------------------------------------
# 3. Severity and confidence are separate axes
# ---------------------------------------------------------------------------


def test_high_confidence_and_low_severity_does_not_escalate(make_evidence):
    """'We are very sure this barely matters' is not an emergency."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="metadata_inconsistency",
                severity=Severity.LOW,
                confidence=0.99,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.DATASET: True},
        )
    )
    assert scope_of(decisions, Scope.DATASET).disposition in (
        AssuranceDisposition.ACCEPT,
        AssuranceDisposition.REVIEW,
    )


def test_high_severity_and_moderate_confidence_is_reviewed_not_dismissed(
    make_evidence,
):
    """The symmetric error: discarding a serious possibility for being uncertain."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="model_backdoor",
                module=2,
                severity=Severity.CRITICAL,
                confidence=0.45,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True},
        )
    )
    model = scope_of(decisions, Scope.MODEL)
    assert model.disposition is AssuranceDisposition.REVIEW
    assert model.assessed


def test_severity_is_never_derived_from_confidence(make_evidence):
    """Section 17, checked on the evidence rather than argued in prose."""
    low_confidence_critical = make_evidence(
        attack_class="model_backdoor",
        module=2,
        severity=Severity.CRITICAL,
        confidence=0.35,
        basis=ConfidenceBasis.STATISTICAL,
    )
    high_confidence_low = make_evidence(
        attack_class="metadata_inconsistency",
        severity=Severity.LOW,
        confidence=0.97,
        basis=ConfidenceBasis.STATISTICAL,
    )
    assert low_confidence_critical.severity is Severity.CRITICAL
    assert high_confidence_low.severity is Severity.LOW
    graph = build_graph([low_confidence_critical, high_confidence_low])
    assert {e.severity for e in graph.evidence} == {Severity.CRITICAL, Severity.LOW}


# ---------------------------------------------------------------------------
# 4. Cryptographic evidence is not negotiable
# ---------------------------------------------------------------------------


def test_a_deterministic_failure_is_not_outvoted_by_clean_scopes(make_evidence):
    """Nine green checks do not average out one failed signature (ADR-014)."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="provenance_key_trust",
                module=3,
                severity=Severity.CRITICAL,
                basis=ConfidenceBasis.DETERMINISTIC,
            )],
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.NO_SHIFT_DETECTED),
        )
    )
    assert scope_of(decisions, Scope.PROVENANCE).disposition is (
        AssuranceDisposition.QUARANTINE
    )
    assert overall(decisions)[0] is AssuranceDisposition.QUARANTINE


def test_a_valid_signature_is_never_reported_as_a_trusted_model(make_evidence):
    """Section 31's prohibited conclusion, asserted on the text itself."""
    decisions = ENGINE.evaluate(
        state([], inputs={**NO_SCOPES, Scope.PROVENANCE: True})
    )
    provenance = scope_of(decisions, Scope.PROVENANCE)
    assert provenance.disposition is AssuranceDisposition.ACCEPT
    rationale = " ".join(o.rationale for o in provenance.fired_rules)
    assert "integrity of the RECORD" in rationale
    assert "says nothing about" in rationale


# ---------------------------------------------------------------------------
# 5. The two states the spec insists must both be expressible
# ---------------------------------------------------------------------------


def test_valid_provenance_and_a_suspicious_model_keeps_both(make_evidence):
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="model_backdoor",
                module=2,
                severity=Severity.HIGH,
                confidence=0.8,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True},
        )
    )
    assert scope_of(decisions, Scope.PROVENANCE).disposition is (
        AssuranceDisposition.ACCEPT
    )
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.REVIEW


def test_invalid_provenance_and_a_clean_model_keeps_both(make_evidence):
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="chain_truncation",
                module=3,
                severity=Severity.CRITICAL,
                basis=ConfidenceBasis.DETERMINISTIC,
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True},
        )
    )
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.ACCEPT
    assert scope_of(decisions, Scope.PROVENANCE).disposition is (
        AssuranceDisposition.QUARANTINE
    )
    assert "RULE-CONFLICT-001" in fired(decisions)


def test_the_conflict_is_stated_factually_and_not_resolved(make_evidence):
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="chain_truncation",
                module=3,
                severity=Severity.CRITICAL,
                basis=ConfidenceBasis.DETERMINISTIC,
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True},
        )
    )
    conflict = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-CONFLICT-001"
    )
    for banned in ("probably", "likely", "malicious actor", "attacker"):
        assert banned not in conflict.statement.lower()


# ---------------------------------------------------------------------------
# 6. Shift is never escalated on its own
# ---------------------------------------------------------------------------


def test_no_rule_escalates_on_shift_alone():
    """Section 11, over the whole verdict vocabulary rather than one case."""
    for verdict in ShiftVerdict:
        decisions = ENGINE.evaluate(
            state(
                [],
                shift=shift_assessment(verdict),
                inputs={**NO_SCOPES, Scope.DISTRIBUTION: True},
            )
        )
        distribution = scope_of(decisions, Scope.DISTRIBUTION)
        assert distribution is not None, verdict
        assert distribution.disposition is not AssuranceDisposition.QUARANTINE, verdict


def test_an_unexplained_shift_with_no_other_evidence_is_a_question(make_evidence):
    decisions = ENGINE.evaluate(
        state(
            [],
            shift=shift_assessment(
                ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT
            ),
            inputs={**NO_SCOPES, Scope.DISTRIBUTION: True},
        )
    )
    distribution = scope_of(decisions, Scope.DISTRIBUTION)
    assert distribution.disposition is AssuranceDisposition.REVIEW
    text = " ".join(o.rationale for o in distribution.fired_rules).lower()
    assert "attack" not in text or "not" in text


def test_a_shift_plus_independent_integrity_evidence_escalates_on_the_evidence(
    make_evidence,
):
    """The escalation is carried by the crypto, not by the shift.

    The distinction matters operationally: if the quarantine came from the
    shift, moving to a new sensor would quarantine a healthy pipeline.
    """
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="provenance_key_trust",
                module=3,
                severity=Severity.CRITICAL,
                basis=ConfidenceBasis.DETERMINISTIC,
            )],
            shift=shift_assessment(
                ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT
            ),
            inputs={**NO_SCOPES, Scope.PROVENANCE: True, Scope.DISTRIBUTION: True},
        )
    )
    assert overall(decisions)[0] is AssuranceDisposition.QUARANTINE
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is (
        AssuranceDisposition.REVIEW
    )


def test_an_explained_shift_still_confounds_the_label_family(make_evidence):
    """The shift is not an attack AND it is not nothing.

    A seasonal change makes label neighbourhoods unrepresentative, so a
    statistical label anomaly measured during one is marked confounded rather
    than counted as independent support.
    """
    graph = build_graph(
        [make_evidence(
            attack_class="label_flip",
            severity=Severity.HIGH,
            confidence=0.8,
            basis=ConfidenceBasis.STATISTICAL,
        )],
        extra_active_phenomena=[EvidenceFamily.DISTRIBUTION_SHIFT],
    )
    labelling = graph.group(EvidenceFamily.DATASET_LABELLING)
    assert labelling.confounded
    assert EvidenceFamily.DISTRIBUTION_SHIFT in labelling.active_confounders


def test_a_confounded_finding_is_not_a_refuted_one(make_evidence):
    """The hole RULE-DATA-004 was added to close.

    Before it, a dataset scope whose every finding was confounded by a
    coincident shift produced no rule at all and vanished from the report --
    which reads as 'nothing to say about the dataset' when the truth is 'there
    is a finding and we cannot separate it from the shift'.
    """
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="label_flip",
                severity=Severity.HIGH,
                confidence=0.8,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.DATASET: True, Scope.DISTRIBUTION: True},
            shift=shift_assessment(
                ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT
            ),
            active=[EvidenceFamily.DISTRIBUTION_SHIFT],
        )
    )
    dataset = scope_of(decisions, Scope.DATASET)
    assert dataset is not None
    assert dataset.disposition is AssuranceDisposition.REVIEW
    assert "RULE-DATA-004" in fired(decisions)


def test_per_sample_ood_reaches_a_rule_even_with_no_shift_analysis(make_evidence):
    """The other hole: evidence that reached no rule at all (RULE-SHIFT-050)."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="ood_insertion",
                severity=Severity.MEDIUM,
                confidence=0.7,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.DATASET: True},
        )
    )
    assert "RULE-SHIFT-050" in fired(decisions)
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is (
        AssuranceDisposition.REVIEW
    )


def test_the_same_ood_evidence_is_not_counted_twice_when_a_shift_ran(make_evidence):
    """RULE-SHIFT-050 is silenced when the population-level analysis exists."""
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="ood_insertion",
                severity=Severity.MEDIUM,
                confidence=0.7,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.DATASET: True, Scope.DISTRIBUTION: True},
            shift=shift_assessment(ShiftVerdict.NO_SHIFT_DETECTED),
        )
    )
    assert "RULE-SHIFT-050" not in fired(decisions)


# ---------------------------------------------------------------------------
# 7. Incomplete coverage cannot be washed out
# ---------------------------------------------------------------------------


def test_a_detector_that_never_ran_is_not_a_clean_detector(make_evidence):
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="model_backdoor",
                module=2,
                coverage=Coverage.NOT_ASSESSED,
                severity=Severity.CRITICAL,
                confidence=0.9,
                basis=ConfidenceBasis.STATISTICAL,
            )],
            inputs={**NO_SCOPES, Scope.MODEL: True},
        )
    )
    graph_item = state(
        [make_evidence(
            attack_class="model_backdoor",
            module=2,
            coverage=Coverage.NOT_ASSESSED,
            severity=Severity.CRITICAL,
            confidence=0.9,
            basis=ConfidenceBasis.STATISTICAL,
        )]
    ).graph.evidence[0]
    assert graph_item.supports is False
    assert "NOT_ASSESSED" in graph_item.support_reason
    assert scope_of(decisions, Scope.MODEL).disposition is not (
        AssuranceDisposition.QUARANTINE
    )


def test_three_clean_scopes_do_not_outvote_one_missing_one():
    """NOT_ASSESSED outranks ACCEPT in the strictness order, by design."""
    decisions = ENGINE.evaluate(
        state([], inputs={**ALL_SCOPES, Scope.MODEL: False})
    )
    assert overall(decisions)[0] is AssuranceDisposition.NOT_ASSESSED


def test_a_quarantine_still_outranks_a_gap(make_evidence):
    """A gap must not downgrade a real failure into an administrative note.

    NOT_ASSESSED sits above ACCEPT in the strictness order so that a missing
    scope cannot be read as a clean one -- but it must sit BELOW REVIEW and
    QUARANTINE, or an absent model report would soften a broken hash chain
    into 'incomplete'.
    """
    decisions = ENGINE.evaluate(
        state(
            [make_evidence(
                attack_class="chain_truncation",
                module=3,
                severity=Severity.CRITICAL,
                basis=ConfidenceBasis.DETERMINISTIC,
            )],
            inputs={**ALL_SCOPES, Scope.MODEL: False, Scope.DISTRIBUTION: False},
        )
    )
    disposition, scope_name = overall(decisions)
    assert disposition is AssuranceDisposition.QUARANTINE
    assert "provenance" in scope_name.lower()
    # ... and the gap is still reported, not swallowed by the escalation.
    assert scope_of(decisions, Scope.MODEL).disposition is (
        AssuranceDisposition.NOT_ASSESSED
    )


# ---------------------------------------------------------------------------
# 8. Volume
# ---------------------------------------------------------------------------


def test_a_flood_of_weak_evidence_does_not_manufacture_a_quarantine(make_evidence):
    """Two thousand near-duplicate hits are still one family's opinion.

    Without family grouping, an attacker who could induce many low-grade
    findings could drown a report -- or, worse, manufacture the appearance of
    corroboration across a pipeline that has none.
    """
    evidence = [
        make_evidence(
            attack_class="near_duplicate_flood",
            detector="phash_duplicate",
            severity=Severity.MEDIUM,
            confidence=0.55,
            basis=ConfidenceBasis.STATISTICAL,
            discriminator=(f"pair-{i}",),
        )
        for i in range(2000)
    ]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True})
    )
    dataset = scope_of(decisions, Scope.DATASET)
    assert dataset.disposition is not AssuranceDisposition.QUARANTINE
    assert len(fired(decisions)) < 10


def test_a_real_failure_survives_the_flood(make_evidence):
    """The symmetric check: volume must not bury the one thing that matters."""
    flood = [
        make_evidence(
            attack_class="near_duplicate_flood",
            detector="phash_duplicate",
            severity=Severity.MEDIUM,
            confidence=0.55,
            basis=ConfidenceBasis.STATISTICAL,
            discriminator=(f"pair-{i}",),
        )
        for i in range(2000)
    ]
    real = make_evidence(
        attack_class="provenance_key_trust",
        module=3,
        severity=Severity.CRITICAL,
        basis=ConfidenceBasis.DETERMINISTIC,
    )
    decisions = ENGINE.evaluate(
        state(
            [*flood, real],
            inputs={**NO_SCOPES, Scope.DATASET: True, Scope.PROVENANCE: True},
        )
    )
    assert overall(decisions)[0] is AssuranceDisposition.QUARANTINE
    citations = {
        reference
        for d in decisions
        for o in d.fired_rules
        for reference in o.evidence_ids
    }
    assert real.evidence_id in citations


def test_the_evidence_summary_stays_bounded_under_volume(make_evidence):
    """A summary that grows with the flood is not a summary."""
    from cvtrust.assurance.evidence import summarise_evidence

    graph = build_graph([
        make_evidence(
            attack_class="near_duplicate_flood",
            detector="phash_duplicate",
            confidence=0.55,
            basis=ConfidenceBasis.STATISTICAL,
            discriminator=(f"pair-{i}",),
        )
        for i in range(2000)
    ])
    summary = summarise_evidence(graph)
    assert summary["total"] == 2000
    assert summary["families_present"] == ["DATASET_DUPLICATION"]
    assert summary["independent_family_count"] == 1


# ---------------------------------------------------------------------------
# 9. False positives over real imagery
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_a_legitimate_terrain_change_is_not_escalated(assurance_lab):
    """A declared move from mixed terrain to desert.

    The single most likely operational event in this problem domain, and the
    one a naive 'shift means attack' rule would flag every time.
    """
    assessment = run_shift(assurance_lab.pair("operational_terrain"))
    assert assessment.verdict is ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT
    report, _ = assess_pipeline(Config(), shift=assessment)
    assert report.distribution_assurance.disposition in ("ACCEPT", "REVIEW")
    assert report.decision.disposition is not AssuranceDisposition.QUARANTINE


@pytest.mark.slow
def test_a_declared_sensor_swap_is_not_escalated(assurance_lab):
    assessment = run_shift(assurance_lab.pair("operational_sensor"))
    assert assessment.verdict is ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT


@pytest.mark.slow
def test_a_six_sample_batch_produces_no_conclusion_in_either_direction(
    assurance_lab,
):
    """A real shift the system must decline to report (section 9).

    Both errors are available here: claiming the shift (unsupportable) and
    reporting stability (false reassurance). The verdict is neither.
    """
    assessment = run_shift(assurance_lab.pair("small_current_batch"))
    assert assessment.verdict is ShiftVerdict.INSUFFICIENT_SAMPLE
    report, _ = assess_pipeline(Config(), shift=assessment)
    assert report.distribution_assurance.disposition == "NOT_ASSESSED"
    assert report.decision.disposition is not AssuranceDisposition.ACCEPT


@pytest.mark.slow
def test_no_declaration_at_all_is_not_reported_as_a_contradiction(assurance_lab):
    """Not filling in a form is not evidence of anything."""
    assessment = run_shift(assurance_lab.pair("no_context_declared"))
    assert assessment.verdict is ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT
    assert "neither explained nor contradicted" in assessment.context.statement


@pytest.mark.slow
def test_two_clean_draws_do_not_produce_a_shift(clean_shift):
    """The headline false-positive rate, measured over real feature vectors."""
    assert clean_shift.verdict is ShiftVerdict.NO_SHIFT_DETECTED
    report, _ = assess_pipeline(Config(), shift=clean_shift)
    assert report.distribution_assurance.disposition == "ACCEPT"
