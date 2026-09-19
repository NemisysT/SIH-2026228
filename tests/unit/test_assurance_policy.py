"""The assurance policy engine: every rule, and every thing it refuses to do.

Two kinds of test here.  The first checks that each rule fires on the evidence
it documents and not otherwise.  The second — the more important kind — checks
the *prohibitions*: no score, no weighting, no escalation on shift alone, no
ACCEPT for a scope nobody looked at.
"""

from __future__ import annotations

import pytest

from cvtrust.assurance.decision import confidence_summary, severity_summary
from cvtrust.assurance.evidence import build_graph
from cvtrust.assurance.families import EvidenceFamily
from cvtrust.assurance.policy import (
    DISPOSITION_ORDER,
    RULES,
    AssuranceDisposition,
    AssurancePolicyEngine,
    PolicyState,
    Scope,
    overall,
)
from cvtrust.core.evidence import ConfidenceBasis, Coverage, Severity
from cvtrust.shift.characterize import ShiftAssessment, ShiftVerdict

ALL_SCOPES = {
    Scope.DATASET: True,
    Scope.MODEL: True,
    Scope.PROVENANCE: True,
    Scope.DISTRIBUTION: True,
}
NO_SCOPES = {s: False for s in ALL_SCOPES}


def state(
    evidence=(),
    *,
    shift=None,
    inputs=None,
    accept_explained_shift=True,
    active=(),
):
    return PolicyState(
        graph=build_graph(list(evidence), extra_active_phenomena=list(active)),
        shift=shift,
        inputs=dict(inputs if inputs is not None else NO_SCOPES),
        coverage_gaps=(),
        accept_explained_shift=accept_explained_shift,
    )


def fired(decisions) -> set[str]:
    return {o.rule_id for d in decisions for o in d.fired_rules}


def scope_of(decisions, scope: Scope):
    for decision in decisions:
        if decision.scope is scope:
            return decision
    return None


ENGINE = AssurancePolicyEngine()


def shift_assessment(verdict: ShiftVerdict) -> ShiftAssessment:
    """A minimal assessment carrying only the verdict the rules read."""
    return ShiftAssessment(
        assessment_id="S-test",
        verdict=verdict,
        statement=f"test assessment: {verdict.value}",
        reference={"reference_id": "REF-test", "digest": "0" * 64, "sample_count": 100},
        current={"sample_count": 100},
        metrics=[],
    )


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------


def test_every_rule_is_fully_described():
    """A rule whose description has drifted from its predicate is worse than none."""
    for rule in RULES:
        described = rule.describe()
        assert described["id"] == rule.rule_id
        assert described["if"], rule.rule_id
        assert described["rationale"], rule.rule_id
        assert described["then"] in {d.value for d in AssuranceDisposition}
        assert callable(rule.evaluate)


def test_rule_ids_are_unique():
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_the_rule_table_is_emitted_for_the_report():
    described = ENGINE.describe()
    assert described["policy_version"]
    assert len(described["rules"]) == len(RULES)
    assert "distinct evidence family" in described["counting_unit"]
    assert "no trust score" in described["no_scoring"]


def test_a_rule_cannot_report_an_id_or_scope_other_than_its_own(make_evidence):
    decisions = ENGINE.evaluate(state(inputs=NO_SCOPES))
    for decision in decisions:
        for outcome in decision.fired_rules:
            rule = next(r for r in RULES if r.rule_id == outcome.rule_id)
            assert outcome.scope is rule.scope


# ---------------------------------------------------------------------------
# NOT_ASSESSED is never ACCEPT
# ---------------------------------------------------------------------------


def test_nothing_supplied_is_not_assessed_not_accept():
    decisions = ENGINE.evaluate(state(inputs=NO_SCOPES))
    disposition, rationale = overall(decisions)
    assert disposition is AssuranceDisposition.NOT_ASSESSED
    assert "establishes nothing" in rationale
    assert fired(decisions) == {
        "RULE-DATA-000",
        "RULE-MODEL-000",
        "RULE-PROV-000",
        "RULE-SHIFT-000",
    }


def test_an_unassessed_scope_prevents_an_overall_accept(make_evidence):
    """One clean scan of one scope is not a clean pipeline."""
    decisions = ENGINE.evaluate(
        state(inputs={**NO_SCOPES, Scope.DATASET: True})
    )
    assert scope_of(decisions, Scope.DATASET).disposition is AssuranceDisposition.ACCEPT
    disposition, rationale = overall(decisions)
    assert disposition is AssuranceDisposition.NOT_ASSESSED
    assert "would present partial coverage as a clean pipeline" in rationale


def test_accept_is_reachable_only_with_every_scope_assessed():
    decisions = ENGINE.evaluate(
        state(inputs=ALL_SCOPES, shift=shift_assessment(ShiftVerdict.NO_SHIFT_DETECTED))
    )
    assert overall(decisions)[0] is AssuranceDisposition.ACCEPT


def test_not_assessed_outranks_accept_but_not_review():
    assert (
        DISPOSITION_ORDER[AssuranceDisposition.ACCEPT]
        < DISPOSITION_ORDER[AssuranceDisposition.NOT_ASSESSED]
        < DISPOSITION_ORDER[AssuranceDisposition.REVIEW]
        < DISPOSITION_ORDER[AssuranceDisposition.QUARANTINE]
    )


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_a_broken_signature_quarantines(make_evidence):
    evidence = [
        make_evidence(
            attack_class="inference_tampering",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.PROVENANCE: True}))
    assert "RULE-PROV-001" in fired(decisions)
    assert scope_of(decisions, Scope.PROVENANCE).disposition is AssuranceDisposition.QUARANTINE


def test_an_unauthorised_key_quarantines_even_with_a_valid_signature(make_evidence):
    evidence = [
        make_evidence(
            attack_class="provenance_key_trust",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.PROVENANCE: True}))
    assert "RULE-PROV-002" in fired(decisions)


def test_clean_provenance_says_nothing_about_the_model(make_evidence):
    decisions = ENGINE.evaluate(state(inputs={**NO_SCOPES, Scope.PROVENANCE: True}))
    outcome = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-PROV-010"
    )
    assert "says nothing about the quality of the inference" in outcome.rationale


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def test_an_identity_mismatch_quarantines(make_evidence):
    evidence = [
        make_evidence(
            attack_class="model_substitution",
            module=2,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.CRITICAL,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True}))
    assert "RULE-MODEL-001" in fired(decisions)
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.QUARANTINE


def test_uncalibrated_backdoor_evidence_cannot_quarantine(make_evidence):
    """Quarantine on a statistical indicator requires MEASURED evidence quality."""
    evidence = [
        make_evidence(
            attack_class="model_backdoor",
            module=2,
            basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
            confidence=0.60,
            severity=Severity.CRITICAL,
            limitations=(
                "uncalibrated: no measured precision exists for this detector "
                "version; confidence is a documented prior, not an empirical rate",
            ),
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True}))
    assert "RULE-MODEL-002" not in fired(decisions)
    assert "RULE-MODEL-003" in fired(decisions)
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.REVIEW


def test_calibrated_backdoor_evidence_can_quarantine(make_evidence):
    evidence = [
        make_evidence(
            attack_class="model_backdoor",
            module=2,
            basis=ConfidenceBasis.CALIBRATED,
            confidence=0.92,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True}))
    assert "RULE-MODEL-002" in fired(decisions)


def test_calibrated_but_low_confidence_backdoor_evidence_does_not_quarantine(make_evidence):
    evidence = [
        make_evidence(
            attack_class="model_backdoor",
            module=2,
            basis=ConfidenceBasis.CALIBRATED,
            confidence=0.55,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True}))
    assert "RULE-MODEL-002" not in fired(decisions)
    assert "RULE-MODEL-003" in fired(decisions)


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


def test_deterministic_dataset_integrity_quarantines(make_evidence):
    evidence = [
        make_evidence(
            attack_class="dataset_tamper",
            module=1,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True}))
    assert "RULE-DATA-001" in fired(decisions)


def test_statistical_dataset_evidence_alone_reviews_rather_than_quarantines(make_evidence):
    evidence = [
        make_evidence(
            attack_class="label_flip",
            module=1,
            basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True}))
    assert "RULE-DATA-002" in fired(decisions)
    assert "RULE-DATA-003" not in fired(decisions)
    assert scope_of(decisions, Scope.DATASET).disposition is AssuranceDisposition.REVIEW


def test_dataset_evidence_corroborated_by_an_independent_family_quarantines(make_evidence):
    evidence = [
        make_evidence(
            attack_class="label_flip",
            module=1,
            basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99,
            severity=Severity.HIGH,
        ),
        make_evidence(
            attack_class="inference_tampering",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.HIGH,
        ),
    ]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True, Scope.PROVENANCE: True})
    )
    assert "RULE-DATA-003" in fired(decisions)
    outcome = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-DATA-003"
    )
    assert outcome.observation["counting_unit"] == "distinct evidence family, not finding"


def test_corroboration_from_the_same_family_does_not_escalate(make_evidence):
    """Two label detectors are one phenomenon, not corroboration."""
    evidence = [
        make_evidence(
            attack_class="label_flip",
            detector="label_consistency",
            module=1,
            basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99,
            severity=Severity.HIGH,
        ),
        make_evidence(
            attack_class="systematic_mislabel",
            detector="systematic_mislabel",
            module=1,
            basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99,
            severity=Severity.HIGH,
        ),
    ]
    decisions = ENGINE.evaluate(state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True}))
    assert "RULE-DATA-003" not in fired(decisions)
    assert scope_of(decisions, Scope.DATASET).disposition is AssuranceDisposition.REVIEW


def test_dataset_evidence_wholly_explained_by_a_shift_reaches_a_rule(make_evidence):
    """The hole the lab found: a scope must never fall through every rule."""
    evidence = [
        make_evidence(
            attack_class="label_flip",
            module=1,
            basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(
            evidence,
            inputs={**NO_SCOPES, Scope.DATASET: True},
            active=[EvidenceFamily.DISTRIBUTION_SHIFT],
        )
    )
    assert "RULE-DATA-004" in fired(decisions)
    assert "RULE-DATA-002" not in fired(decisions)
    assert "RULE-DATA-003" not in fired(decisions)
    assert scope_of(decisions, Scope.DATASET) is not None
    assert scope_of(decisions, Scope.DATASET).disposition is AssuranceDisposition.REVIEW


def test_confounded_dataset_evidence_is_explained_not_refuted(make_evidence):
    evidence = [
        make_evidence(
            attack_class="label_flip", module=1, basis=ConfidenceBasis.STATISTICAL,
            confidence=0.99, severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(
            evidence,
            inputs={**NO_SCOPES, Scope.DATASET: True},
            active=[EvidenceFamily.DISTRIBUTION_SHIFT],
        )
    )
    outcome = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-DATA-004"
    )
    assert "is not a refuted one" in outcome.rationale
    assert "preserved and reported" in outcome.statement


# ---------------------------------------------------------------------------
# Distribution shift — the prohibitions
# ---------------------------------------------------------------------------


def test_no_reference_population_is_not_assessed():
    decisions = ENGINE.evaluate(state(inputs={**NO_SCOPES, Scope.DISTRIBUTION: False}))
    assert "RULE-SHIFT-000" in fired(decisions)
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.NOT_ASSESSED


def test_an_unresolved_shift_is_not_assessed_not_clean():
    decisions = ENGINE.evaluate(
        state(
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.INSUFFICIENT_SAMPLE),
        )
    )
    assert "RULE-SHIFT-001" in fired(decisions)
    assert "RULE-SHIFT-010" not in fired(decisions)
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.NOT_ASSESSED


def test_a_declared_operational_change_accepts():
    decisions = ENGINE.evaluate(
        state(
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT),
        )
    )
    assert "RULE-SHIFT-020" in fired(decisions)
    assert overall(decisions)[0] is AssuranceDisposition.ACCEPT


def test_a_higher_assurance_posture_can_review_a_declared_change():
    decisions = ENGINE.evaluate(
        state(
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT),
            accept_explained_shift=False,
        )
    )
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.REVIEW


def test_an_unexplained_shift_reviews_and_never_quarantines():
    for verdict in (
        ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT,
        ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED,
        ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT,
    ):
        decisions = ENGINE.evaluate(state(inputs=ALL_SCOPES, shift=shift_assessment(verdict)))
        assert "RULE-SHIFT-030" in fired(decisions), verdict
        assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.REVIEW
        assert overall(decisions)[0] is not AssuranceDisposition.QUARANTINE


def test_no_shift_rule_can_ever_produce_a_quarantine():
    """The single hardest constraint in the brief, asserted structurally."""
    shift_rules = [r for r in RULES if r.scope is Scope.DISTRIBUTION]
    assert shift_rules
    for rule in shift_rules:
        assert rule.disposition is not AssuranceDisposition.QUARANTINE, rule.rule_id


def test_shift_plus_independent_evidence_is_still_only_review(make_evidence):
    """The conjunction changes the analyst's ordering, not the classification."""
    evidence = [
        make_evidence(
            attack_class="inference_tampering",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
            severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(
            evidence,
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT),
        )
    )
    assert "RULE-SHIFT-040" in fired(decisions)
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.REVIEW
    # The QUARANTINE comes from provenance, on provenance evidence.
    assert scope_of(decisions, Scope.PROVENANCE).disposition is AssuranceDisposition.QUARANTINE
    outcome = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-SHIFT-040"
    )
    assert "maliciousness is NOT inferred from shift" in outcome.observation["note"]


def test_shift_does_not_corroborate_itself(make_evidence):
    """Per-sample OOD is the same family as the population shift."""
    evidence = [make_evidence(attack_class="ood_insertion", module=1, severity=Severity.HIGH)]
    decisions = ENGINE.evaluate(
        state(
            evidence,
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT),
        )
    )
    assert "RULE-SHIFT-040" not in fired(decisions)
    assert "RULE-SHIFT-030" in fired(decisions)


def test_per_sample_ood_with_no_population_assessment_reaches_a_rule(make_evidence):
    """The rule the shipped lab corpus cannot exercise, covered here instead."""
    evidence = [make_evidence(attack_class="ood_insertion", module=1, severity=Severity.MEDIUM)]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.DATASET: True}, shift=None)
    )
    assert "RULE-SHIFT-050" in fired(decisions)
    assert scope_of(decisions, Scope.DISTRIBUTION).disposition is AssuranceDisposition.REVIEW


def test_a_supplied_shift_assessment_silences_the_per_sample_rule(make_evidence):
    """Both firing would count one phenomenon twice."""
    evidence = [make_evidence(attack_class="ood_insertion", module=1, severity=Severity.MEDIUM)]
    decisions = ENGINE.evaluate(
        state(
            evidence,
            inputs=ALL_SCOPES,
            shift=shift_assessment(ShiftVerdict.NO_SHIFT_DETECTED),
        )
    )
    assert "RULE-SHIFT-050" not in fired(decisions)


# ---------------------------------------------------------------------------
# Conflict preservation, and the absence of a score
# ---------------------------------------------------------------------------


def test_disagreement_between_evidence_classes_is_recorded(make_evidence):
    evidence = [
        make_evidence(
            attack_class="model_backdoor", module=2, basis=ConfidenceBasis.CALIBRATED,
            confidence=0.7, severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True})
    )
    assert "RULE-CONFLICT-001" in fired(decisions)
    outcome = next(
        o for d in decisions for o in d.fired_rules if o.rule_id == "RULE-CONFLICT-001"
    )
    assert "are not combined" in outcome.statement


def test_the_conflict_rule_cannot_change_an_outcome():
    """It carries ACCEPT so it can neither raise nor lower a disposition."""
    rule = next(r for r in RULES if r.rule_id == "RULE-CONFLICT-001")
    assert rule.disposition is AssuranceDisposition.ACCEPT


def test_a_suspicious_model_with_valid_provenance_keeps_both_facts(make_evidence):
    """ADR-014's second row: the two must not be mapped onto one value."""
    evidence = [
        make_evidence(
            attack_class="model_substitution", module=2,
            basis=ConfidenceBasis.DETERMINISTIC, severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True})
    )
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.QUARANTINE
    assert scope_of(decisions, Scope.PROVENANCE).disposition is AssuranceDisposition.ACCEPT


def test_a_clean_model_with_invalid_provenance_keeps_both_facts(make_evidence):
    """ADR-014's third row: the opposite state, and the opposite action."""
    evidence = [
        make_evidence(
            attack_class="inference_tampering", module=3,
            basis=ConfidenceBasis.DETERMINISTIC, severity=Severity.HIGH,
        )
    ]
    decisions = ENGINE.evaluate(
        state(evidence, inputs={**NO_SCOPES, Scope.MODEL: True, Scope.PROVENANCE: True})
    )
    assert scope_of(decisions, Scope.MODEL).disposition is AssuranceDisposition.ACCEPT
    assert scope_of(decisions, Scope.PROVENANCE).disposition is AssuranceDisposition.QUARANTINE


def test_confidence_is_reported_per_basis_and_never_pooled(make_evidence):
    graph = build_graph(
        [
            make_evidence(attack_class="inference_tampering", module=3,
                          basis=ConfidenceBasis.DETERMINISTIC),
            make_evidence(attack_class="model_backdoor", module=2,
                          basis=ConfidenceBasis.CALIBRATED, confidence=0.72),
        ]
    )
    summary = confidence_summary(graph)
    assert set(summary["by_basis"]) == {"DETERMINISTIC", "CALIBRATED"}
    assert "never pooled" in summary["note"]
    assert "mean" not in {k.lower() for k in summary}


def test_severity_is_reported_independently_of_confidence(make_evidence):
    graph = build_graph(
        [
            make_evidence(attack_class="model_substitution", module=2,
                          severity=Severity.LOW, basis=ConfidenceBasis.DETERMINISTIC),
        ]
    )
    summary = severity_summary(graph)
    assert summary["highest"] == "LOW"
    assert "Neither is derived from the other" in summary["note"]


def test_no_rule_computes_a_weighted_combination():
    """A static guarantee over the EXECUTABLE policy code, not its prose.

    Scanning the source text would match the docstring that explains why there
    are no weights, so this walks the syntax tree instead and looks for the two
    shapes a hidden weighting actually takes: arithmetic on a float literal, and
    an identifier named like a score.
    """
    import ast
    import inspect

    import cvtrust.assurance.policy as policy_module

    tree = ast.parse(inspect.getsource(policy_module))
    # Strip docstrings and bare string expressions: prose is not code.
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Div)):
            for side in (node.left, node.right):
                if isinstance(side, ast.Constant) and isinstance(side.value, float):
                    offenders.append(
                        f"line {node.lineno}: arithmetic on a float literal "
                        f"{side.value}"
                    )
        if isinstance(node, ast.Name) and node.id in {
            "trust_score", "risk_score", "security_score", "maliciousness_score",
            "weight", "weights", "overall_score",
        }:
            offenders.append(f"line {node.lineno}: identifier {node.id!r}")
        if isinstance(node, ast.Attribute) and node.attr in {
            "trust_score", "risk_score", "overall_score",
        }:
            offenders.append(f"line {node.lineno}: attribute {node.attr!r}")
    assert not offenders, "scoring arithmetic in the policy engine: " + "; ".join(
        offenders
    )


def test_no_report_schema_carries_an_aggregate_score():
    """The prohibition, enforced over every Module 4 schema's field names."""
    from cvtrust.assurance.decision import AssuranceDecision
    from cvtrust.assurance.evidence import EvidenceGraph, EvidenceGroup
    from cvtrust.assurance.policy import RuleOutcome, ScopeDecision
    from cvtrust.reporting.assurance_report import (
        PipelineAssuranceReport,
        ScopeSummary,
    )
    from cvtrust.shift.characterize import ShiftAssessment

    forbidden = {
        "score", "trust_score", "risk_score", "security_score",
        "maliciousness_score", "overall_score", "trust_percentage",
        "integrity_score", "confidence_score", "weight", "weights",
    }
    for model in (
        PipelineAssuranceReport, ScopeSummary, AssuranceDecision, EvidenceGraph,
        EvidenceGroup, RuleOutcome, ScopeDecision, ShiftAssessment,
    ):
        overlap = forbidden & set(model.model_fields)
        assert not overlap, f"{model.__name__} carries {overlap}"
