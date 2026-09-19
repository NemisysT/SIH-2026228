"""Evidence normalisation, families and the prevention of double counting.

The central property under test: **a family contributes at most one unit of
independent support, however many findings or detectors it holds.**  Everything
else in this file exists to make sure that property cannot be reached by
deleting evidence.
"""

from __future__ import annotations

import pytest

from cvtrust.assurance.evidence import build_graph, normalise, summarise_evidence
from cvtrust.assurance.families import (
    CONFOUNDED_BY,
    FAMILY_OF,
    EvidenceClass,
    EvidenceFamily,
    classify,
    describe_families,
)
from cvtrust.core.evidence import ConfidenceBasis, Coverage, Severity
from cvtrust.risk.coverage import ATTACK_CLASS_REGISTRY


# ---------------------------------------------------------------------------
# The tables
# ---------------------------------------------------------------------------


def test_every_known_attack_class_has_a_declared_family():
    """Adding a detector without deciding its family is a test failure.

    Otherwise a new attack class would silently become UNCLASSIFIED, get no
    confounding relationships, and start corroborating everything.
    """
    missing = sorted(set(ATTACK_CLASS_REGISTRY) - set(FAMILY_OF))
    assert not missing, f"attack classes with no evidence family: {missing}"


def test_every_family_has_a_declared_confounding_row():
    missing = [f for f in EvidenceFamily if f not in CONFOUNDED_BY]
    assert not missing, f"families with no confounding declaration: {missing}"


def test_module_1_ood_and_module_4_shift_are_the_same_family():
    """The load-bearing entry in the whole table.

    Per-sample OOD and population-level shift answer different questions about
    one phenomenon. Letting them corroborate each other would turn a season
    change into two independent concerns.
    """
    assert classify("ood_insertion")[0] is EvidenceFamily.DISTRIBUTION_SHIFT
    assert classify("distribution_shift")[0] is EvidenceFamily.DISTRIBUTION_SHIFT


def test_label_evidence_is_confounded_by_shift_and_nothing_else_is():
    assert CONFOUNDED_BY[EvidenceFamily.DATASET_LABELLING] == (
        EvidenceFamily.DISTRIBUTION_SHIFT,
    )
    for family in (
        EvidenceFamily.PROVENANCE_INTEGRITY,
        EvidenceFamily.PROVENANCE_TRUST,
        EvidenceFamily.PROVENANCE_REPLAY,
        EvidenceFamily.MODEL_BACKDOOR,
        EvidenceFamily.MODEL_TAMPERING,
        EvidenceFamily.MODEL_IDENTITY,
        EvidenceFamily.DATASET_DUPLICATION,
    ):
        assert CONFOUNDED_BY[family] == (), (
            f"{family.value} must not be confoundable: a model is measured "
            "against a FIXED probe battery and a signature is a deterministic "
            "fact, so nothing in the field explains either away"
        )


def test_the_tables_are_printed_for_the_analyst():
    described = describe_families()
    assert "at most one unit of independent support" in described["principle"]
    assert "never deleted" in described["confounding_note"]
    families = {entry["family"] for entry in described["families"]}
    assert EvidenceFamily.DISTRIBUTION_SHIFT.value in families


# ---------------------------------------------------------------------------
# Normalisation preserves the original
# ---------------------------------------------------------------------------


def test_normalisation_never_changes_a_confidence_or_a_basis(make_evidence):
    evidence = make_evidence(
        attack_class="inference_tampering", basis=ConfidenceBasis.DETERMINISTIC
    )
    assert evidence.confidence == 1.0
    assert evidence.confidence_basis is ConfidenceBasis.DETERMINISTIC


def test_a_cryptographic_fact_is_never_turned_into_a_statistical_one(make_evidence):
    """ADR-014, enforced rather than reviewed."""
    evidence = make_evidence(
        attack_class="inference_tampering",
        basis=ConfidenceBasis.DETERMINISTIC,
        module=3,
    )
    graph = build_graph([evidence])
    assert graph.evidence[0].confidence_basis is ConfidenceBasis.DETERMINISTIC
    assert graph.evidence[0].confidence == 1.0
    summary = summarise_evidence(graph)
    assert summary["by_confidence_basis"]["DETERMINISTIC"] == 1


def test_the_raw_observation_travels_with_the_evidence(make_evidence):
    evidence = make_evidence(attack_class="label_flip")
    assert "test_observation" in evidence.raw_observation
    assert evidence.raw_observation["test_observation"]["value"] == 1


def test_lineage_points_back_to_the_module_and_detector(make_evidence):
    evidence = make_evidence(attack_class="label_flip", module=1, detector="label_consistency")
    assert evidence.lineage.source_module == 1
    assert evidence.lineage.source_detector == "label_consistency"
    assert evidence.lineage.source_report_id == "R-test"
    assert evidence.evidence_id.startswith("E-")


def test_the_evidence_id_is_content_addressed(make_evidence):
    """Two fusion runs over the same inputs must be diffable."""
    first = make_evidence(attack_class="label_flip", asset_id="s1")
    second = make_evidence(attack_class="label_flip", asset_id="s1")
    assert first.evidence_id == second.evidence_id
    assert first.evidence_id != make_evidence(
        attack_class="label_flip", asset_id="s2"
    ).evidence_id


# ---------------------------------------------------------------------------
# Grouping and double counting
# ---------------------------------------------------------------------------


def test_many_findings_in_one_family_are_one_phenomenon(make_evidence):
    evidence = [
        make_evidence(attack_class="label_flip", asset_id=f"s{i}", discriminator=(str(i),))
        for i in range(50)
    ]
    graph = build_graph(evidence)
    assert len(graph.evidence) == 50
    assert graph.independent_families() == [EvidenceFamily.DATASET_LABELLING]


def test_two_detectors_in_one_family_raise_corroboration_not_the_count(make_evidence):
    evidence = [
        make_evidence(attack_class="label_flip", detector="label_consistency"),
        make_evidence(attack_class="systematic_mislabel", detector="systematic_mislabel"),
    ]
    graph = build_graph(evidence)
    group = graph.group(EvidenceFamily.DATASET_LABELLING)
    assert group.corroboration == 2
    assert len(graph.independent_families()) == 1


def test_three_detectors_reacting_to_one_shift_are_not_three_attacks(make_evidence):
    """The scenario the whole mechanism exists for.

    A domain shift makes the OOD detector fire, makes label neighbourhoods
    unrepresentative so the label detector fires, and moves the population so
    the shift characteriser fires. One Tuesday in November, three detectors.
    """
    evidence = [
        make_evidence(attack_class="ood_insertion", detector="ood", module=1),
        make_evidence(attack_class="label_flip", detector="label_consistency", module=1),
        make_evidence(attack_class="distribution_shift", detector="distribution_shift", module=4),
    ]
    graph = build_graph(evidence)
    assert graph.independent_families() == [EvidenceFamily.DISTRIBUTION_SHIFT]
    label = graph.group(EvidenceFamily.DATASET_LABELLING)
    assert label.confounded
    assert not label.counts_as_independent_support()


def test_confounded_evidence_is_kept_and_reported_never_deleted(make_evidence):
    evidence = [
        make_evidence(attack_class="distribution_shift", module=4),
        make_evidence(attack_class="label_flip", module=1),
    ]
    graph = build_graph(evidence)
    assert len(graph.evidence) == 2
    label = [e for e in graph.evidence if e.attack_class == "label_flip"][0]
    assert label.supports  # still above the floor
    assert label.active_confounders == (EvidenceFamily.DISTRIBUTION_SHIFT,)
    assert not label.independent()


def test_an_explained_shift_still_confounds_even_at_info_severity(make_evidence):
    """The subtle case the fusion engine declares explicitly.

    A shift the declared context explains raises only an INFO finding, which
    never clears the corroboration floor. It is still a real phenomenon that
    makes label neighbourhoods unrepresentative, so the caller declares the
    family active regardless.
    """
    evidence = [
        make_evidence(
            attack_class="distribution_shift", severity=Severity.INFO, module=4
        ),
        make_evidence(attack_class="label_flip", severity=Severity.HIGH, module=1),
    ]
    without = build_graph(evidence)
    assert not without.group(EvidenceFamily.DATASET_LABELLING).confounded

    with_declaration = build_graph(
        evidence, extra_active_phenomena=[EvidenceFamily.DISTRIBUTION_SHIFT]
    )
    assert with_declaration.group(EvidenceFamily.DATASET_LABELLING).confounded


def test_provenance_evidence_is_never_confounded_by_a_shift(make_evidence):
    """No amount of drift forges a signature."""
    evidence = [
        make_evidence(attack_class="distribution_shift", module=4),
        make_evidence(
            attack_class="inference_tampering",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
        ),
    ]
    graph = build_graph(evidence)
    provenance = graph.group(EvidenceFamily.PROVENANCE_INTEGRITY)
    assert not provenance.confounded
    assert provenance.counts_as_independent_support()


def test_model_evidence_is_never_confounded_by_a_shift(make_evidence):
    """Module 2 measures against a FIXED battery, not against operating data.

    Listing shift as a confounder here would be a plausible-sounding excuse for
    exactly the evidence an adversary most wants discounted.
    """
    evidence = [
        make_evidence(attack_class="distribution_shift", module=4),
        make_evidence(attack_class="model_backdoor", module=2),
    ]
    graph = build_graph(evidence)
    assert graph.group(EvidenceFamily.MODEL_BACKDOOR).counts_as_independent_support()


# ---------------------------------------------------------------------------
# The corroboration floors
# ---------------------------------------------------------------------------


def test_low_severity_evidence_is_context_not_support(make_evidence):
    evidence = make_evidence(attack_class="label_flip", severity=Severity.LOW)
    graph = build_graph([evidence], min_severity=Severity.MEDIUM)
    assert not graph.evidence[0].supports
    assert "below the corroboration floor" in graph.evidence[0].support_reason
    assert graph.independent_families() == []


def test_context_evidence_stays_in_the_report(make_evidence):
    evidence = make_evidence(attack_class="label_flip", severity=Severity.INFO)
    graph = build_graph([evidence])
    assert len(graph.evidence) == 1
    assert summarise_evidence(graph)["context_only"] == 1


def test_a_deterministic_fact_is_exempt_from_the_confidence_floor(make_evidence):
    """1.0 from a digest comparison is not on the same scale as 0.72 from a detector."""
    evidence = make_evidence(
        attack_class="inference_tampering", basis=ConfidenceBasis.DETERMINISTIC
    )
    graph = build_graph([evidence], min_confidence=0.99)
    assert graph.evidence[0].supports
    assert graph.floors["deterministic_exempt_from_confidence_floor"] is True


def test_uncalibrated_evidence_below_the_confidence_floor_is_context(make_evidence):
    evidence = make_evidence(
        attack_class="model_backdoor",
        basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
        confidence=0.2,
        limitations=(
            "uncalibrated: no measured precision exists for this detector "
            "version; confidence is a documented prior, not an empirical rate",
        ),
    )
    graph = build_graph([evidence], min_confidence=0.30)
    assert not graph.evidence[0].supports


def test_unassessed_coverage_is_never_support(make_evidence):
    """A check that did not run is a gap, not evidence of anything."""
    evidence = make_evidence(
        attack_class="model_backdoor",
        coverage=Coverage.NOT_ASSESSED,
        severity=Severity.CRITICAL,
    )
    graph = build_graph([evidence])
    assert not graph.evidence[0].supports
    assert "did not run" in graph.evidence[0].support_reason


# ---------------------------------------------------------------------------
# The summary carries no score
# ---------------------------------------------------------------------------


def test_the_evidence_summary_contains_no_aggregate_score(make_evidence):
    graph = build_graph([make_evidence(attack_class="label_flip")])
    summary = summarise_evidence(graph)
    forbidden = {"score", "trust", "risk", "overall", "total_score", "confidence"}
    assert not (forbidden & set(summary)), summary.keys()
    assert "It is not a score" in summary["note"]


def test_evidence_classes_are_kept_distinct(make_evidence):
    evidence = [
        make_evidence(attack_class="label_flip", module=1),
        make_evidence(attack_class="model_backdoor", module=2),
        make_evidence(
            attack_class="inference_tampering",
            module=3,
            basis=ConfidenceBasis.DETERMINISTIC,
        ),
        make_evidence(attack_class="distribution_shift", module=4),
    ]
    summary = summarise_evidence(build_graph(evidence))
    by_class = summary["by_evidence_class"]
    assert by_class[EvidenceClass.DATA_INTEGRITY.value] == 1
    assert by_class[EvidenceClass.MODEL_INTEGRITY.value] == 1
    assert by_class[EvidenceClass.PROVENANCE_INTEGRITY.value] == 1
    assert by_class[EvidenceClass.DISTRIBUTION_SHIFT.value] == 1
