"""Declared context: a claim checked against an observation, never believed.

The distinction these tests defend is the one the problem statement asks for
and the one it is easiest to get quietly wrong — between *the declaration
predicts this movement* and *the declaration is true*.
"""

from __future__ import annotations

import pytest

from cvtrust.shift.context import (
    CONTEXT_DIMENSIONS,
    ContextExplanation,
    OperationalContext,
    diff_context,
    explain_shift,
)
from cvtrust.shift.reference import ReferenceMode, ReferenceTrust

BASE = OperationalContext(
    season="summer", terrain="mixed", sensor="sensor_a", illumination="daylight"
)


def explain(current: OperationalContext, shares: dict[str, float], *, shift=True):
    return explain_shift(
        reference_context=BASE,
        current_context=current,
        block_shares=shares,
        shift_detected=shift,
    )


def test_no_shift_means_there_is_nothing_to_explain():
    result = explain(BASE, {"colour": 1.0}, shift=False)
    assert result.explanation is ContextExplanation.NOT_APPLICABLE


def test_nothing_declared_is_not_the_same_as_unexplained():
    """A missing declaration is a missing input, not a suspicious one.

    Collapsing the two would punish an operator for not filling in a form, and
    would make the report unable to distinguish 'they said nothing changed and
    it did' from 'nobody said anything'.
    """
    result = explain_shift(
        reference_context=OperationalContext(),
        current_context=OperationalContext(),
        block_shares={"colour": 1.0},
        shift_detected=True,
    )
    assert result.explanation is ContextExplanation.NO_CONTEXT_DECLARED
    assert "neither explained nor contradicted" in result.statement
    assert "missing input, not a suspicious one" in result.statement


def test_a_declaration_that_predicts_the_movement_is_consistent():
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"colour": 0.9, "acquisition": 0.1})
    assert result.explanation is ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT
    assert not result.unexplained_blocks


def test_consistency_is_never_reported_as_confirmation():
    """The load-bearing sentence in the whole module."""
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"colour": 1.0})
    assert "not thereby confirmed" in result.statement
    assert any("not confirmation" in limitation for limitation in result.limitations)
    assert any(
        "engineered to move the same views" in limitation
        for limitation in result.limitations
    )


def test_an_identical_declaration_against_a_moved_population_is_unexplained():
    result = explain(BASE, {"colour": 1.0})
    assert result.explanation is ContextExplanation.UNEXPLAINED
    assert "predicts no change and the population changed" in result.statement


def test_an_unexplained_residual_is_named_not_summarised():
    """A declaration that covers part of the movement leaves a named remainder."""
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"colour": 0.5, "structure": 0.5})
    assert result.explanation is ContextExplanation.PARTIALLY_EXPLAINED
    assert result.unexplained_blocks == ("structure",)
    assert "structure" in result.statement


def test_a_movement_entirely_outside_the_prediction_is_unexplained():
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"structure": 1.0})
    assert result.explanation is ContextExplanation.UNEXPLAINED


def test_a_view_below_the_share_threshold_does_not_count_as_moved():
    """A 97%-explained movement is not 'partially explained' on a rounding tail."""
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"colour": 0.97, "structure": 0.03})
    assert result.explanation is ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT


def test_the_explanation_table_is_carried_in_the_evidence():
    """An analyst must be able to argue with the heuristic, so it is printed."""
    current = BASE.model_copy(update={"sensor": "sensor_b"})
    result = explain(current, {"gradient": 0.8, "colour": 0.2})
    assert "explanation_table" in result.observation
    assert set(result.observation["explanation_table"]) == set(CONTEXT_DIMENSIONS)


def test_a_sensor_change_predicts_gradient_movement():
    """Corrected after measurement: softer optics IS an edge-statistics change.

    The original table predicted acquisition, dct and colour only, and reported
    a legitimate, declared platform swap as partially unexplained because 81% of
    its displacement landed in the gradient view.
    """
    assert "gradient" in CONTEXT_DIMENSIONS["sensor"]["explains"]
    current = BASE.model_copy(update={"sensor": "sensor_b"})
    result = explain(current, {"gradient": 0.81, "colour": 0.17, "structure": 0.02})
    assert result.explanation is ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT


def test_the_resolution_limit_is_stated_on_every_explanation():
    """Illumination, season and terrain are not distinguishable here, and it says so."""
    current = BASE.model_copy(update={"season": "winter"})
    result = explain(current, {"colour": 1.0})
    assert any(
        "does not identify which declared change occurred" in limitation
        for limitation in result.limitations
    )


def test_the_declaration_is_always_marked_unvalidated():
    current = BASE.model_copy(update={"illumination": "low"})
    result = explain(current, {"colour": 1.0})
    assert result.observation["declaration_validated"] is False
    assert any("claim by the supplying side" in l for l in result.limitations)


def test_declared_only_on_one_side_counts_as_a_declared_change():
    result = explain_shift(
        reference_context=OperationalContext(),
        current_context=OperationalContext(illumination="low"),
        block_shares={"colour": 1.0},
        shift_detected=True,
    )
    assert result.delta.declared_only_on_one_side == ("illumination",)
    assert result.explanation is ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT


def test_unknown_declared_fields_never_explain_anything():
    """Free-form context is recorded for the analyst and is not interpretable."""
    current = OperationalContext.from_mapping(
        {**BASE.declared(), "platform_serial": "X-42"}
    )
    result = explain(current, {"colour": 1.0})
    assert current.extra == {"platform_serial": "X-42"}
    assert result.explanation is ContextExplanation.UNEXPLAINED


def test_diff_context_separates_changed_from_unchanged():
    delta = diff_context(BASE, BASE.model_copy(update={"terrain": "desert"}))
    assert delta.changed == ("terrain",)
    assert set(delta.unchanged) == {"illumination", "season", "sensor"}


# ---------------------------------------------------------------------------
# Reference identity and contamination
# ---------------------------------------------------------------------------


def test_every_reference_mode_carries_its_own_caveat(clean_shift):
    assert clean_shift.reference["mode"] == ReferenceMode.DECLARED_CORPUS.value
    caveat = clean_shift.reference["caveat"]
    assert "own integrity was not established" in caveat
    assert "contaminated" in caveat


def test_reference_trust_defaults_to_unknown_and_is_never_inferred(clean_shift):
    assert clean_shift.reference["trust"] == ReferenceTrust.UNKNOWN.value
    assert clean_shift.reference["provenance_validated"] is False


def test_the_reference_has_a_content_identity(clean_shift):
    assert clean_shift.reference["reference_id"].startswith("REF-")
    assert len(clean_shift.reference["digest"]) == 64


def test_the_feature_space_is_bound_into_the_reference_identity():
    """Same images, different extractor, different reference.

    Letting the two share an identity would let a reviewer compare two
    incomparable runs and conclude the drift had changed.
    """
    from cvtrust.shift.reference import population_digest

    digests = ["a" * 64, "b" * 64]
    first = population_digest(digests, {"name": "classical", "version": "1.0", "dim": 614})
    second = population_digest(digests, {"name": "torch_cnn", "version": "1.0", "dim": 512})
    assert first != second


def test_a_reference_assumption_is_always_present_in_the_assessment(clean_shift):
    assert any("contaminated" in a for a in clean_shift.assumptions)
    assert any("not an attack" in l for l in clean_shift.limitations)
