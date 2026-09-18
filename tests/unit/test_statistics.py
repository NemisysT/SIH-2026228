"""Statistical primitives behind every STATISTICAL and CALIBRATED confidence."""

from __future__ import annotations

import numpy as np
import pytest

from cvtrust.risk.statistics import (
    benjamini_hochberg,
    binomial_greater_pvalue,
    distance_weighted_disagreement,
    empirical_pvalue,
    empirical_quantile_threshold,
    wilson_lower_bound,
)


def test_wilson_bound_is_conservative_with_little_support():
    """Same measured precision, far less evidence -> far lower confidence."""
    assert wilson_lower_bound(4, 4) < wilson_lower_bound(400, 400)
    assert 0.0 < wilson_lower_bound(4, 4) < 1.0


def test_wilson_bound_handles_the_degenerate_ends():
    assert wilson_lower_bound(0, 0) == 0.0
    assert wilson_lower_bound(0, 10) == 0.0
    assert wilson_lower_bound(10, 10) < 1.0


def test_wilson_bound_never_exceeds_the_point_estimate():
    for successes, trials in [(1, 3), (7, 10), (50, 60), (99, 100)]:
        assert wilson_lower_bound(successes, trials) <= successes / trials


def test_binomial_pvalue_detects_elevated_rates():
    assert binomial_greater_pvalue(30, 40, 0.05) < 1e-20
    assert binomial_greater_pvalue(2, 40, 0.05) > 0.2


def test_binomial_pvalue_floors_a_zero_null_rate():
    """A zero baseline must not yield infinite significance."""
    value = binomial_greater_pvalue(5, 50, 0.0)
    assert 0.0 < value <= 1.0


def test_benjamini_hochberg_is_monotone_and_bounded():
    pvalues = [0.001, 0.008, 0.04, 0.2, 0.9]
    qvalues = benjamini_hochberg(pvalues)
    assert all(0.0 <= q <= 1.0 for q in qvalues)
    assert qvalues == sorted(qvalues)
    assert all(q >= p for p, q in zip(pvalues, qvalues))


def test_benjamini_hochberg_preserves_input_order():
    pvalues = [0.9, 0.001, 0.04]
    qvalues = benjamini_hochberg(pvalues)
    assert qvalues[1] < qvalues[2] < qvalues[0]


def test_benjamini_hochberg_handles_the_empty_case():
    assert benjamini_hochberg([]) == []


def test_multiplicity_correction_actually_suppresses_noise():
    """500 null tests should yield no discovery at q < 0.05."""
    rng = np.random.default_rng(0)
    pvalues = list(rng.uniform(0, 1, 500))
    assert sum(1 for q in benjamini_hochberg(pvalues) if q < 0.05) == 0


def test_quantile_threshold_matches_the_stated_false_positive_rate():
    rng = np.random.default_rng(1)
    reference = rng.normal(size=10_000)
    threshold = empirical_quantile_threshold(reference, 0.01)
    assert 0.005 <= float((reference > threshold).mean()) <= 0.015


def test_empirical_pvalue_is_strictly_positive():
    reference = np.arange(100.0)
    assert empirical_pvalue(1e9, reference) > 0.0
    assert empirical_pvalue(-1.0, reference) == pytest.approx(1.0)


def test_disagreement_is_zero_when_the_neighbourhood_agrees():
    distances = np.array([0.1, 0.2, 0.3])
    assert distance_weighted_disagreement(distances, ["a", "a", "a"], "a") == 0.0


def test_disagreement_is_one_when_no_neighbour_agrees():
    distances = np.array([0.1, 0.2, 0.3])
    assert distance_weighted_disagreement(distances, ["b", "b", "b"], "a") == 1.0


def test_close_neighbours_count_for_more_than_distant_ones():
    near_disagrees = distance_weighted_disagreement(
        np.array([0.01, 0.9]), ["b", "a"], "a"
    )
    far_disagrees = distance_weighted_disagreement(
        np.array([0.01, 0.9]), ["a", "b"], "a"
    )
    assert near_disagrees > far_disagrees
