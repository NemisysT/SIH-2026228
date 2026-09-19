"""The shift metrics, and the sample floors that stop them overclaiming.

The tests that matter most here are the *negative* ones: a metric that reports
a shift between two draws from the same process, or that reports a confident
verdict from six samples, is worse than no metric at all.
"""

from __future__ import annotations

import numpy as np
import pytest

from cvtrust.shift.metrics import (
    MetricStatus,
    categorical_shift,
    covariance_shift,
    energy_distance_test,
    jensen_shannon_divergence,
    marginal_psi,
    mean_shift,
    population_stability_index,
)


def rng(seed: int = 7) -> np.random.Generator:
    return np.random.default_rng(seed)


def gaussian(n: int, dim: int, *, shift: float = 0.0, scale: float = 1.0, seed: int = 0):
    return np.random.default_rng(seed).normal(shift, scale, (n, dim))


# ---------------------------------------------------------------------------
# Energy distance
# ---------------------------------------------------------------------------


def test_the_energy_test_finds_nothing_between_two_draws_from_one_process():
    result = energy_distance_test(
        gaussian(120, 8, seed=1), gaussian(120, 8, seed=2), rng=rng(), permutations=199
    )
    assert result.status is MetricStatus.ASSESSED
    assert not result.significant
    assert result.p_value > 0.01


def test_the_energy_test_finds_a_location_shift():
    result = energy_distance_test(
        gaussian(120, 8, seed=1),
        gaussian(120, 8, shift=1.0, seed=2),
        rng=rng(),
        permutations=199,
    )
    assert result.fired()
    assert result.p_value <= 0.01


def test_the_energy_test_finds_a_scale_change_with_the_mean_held_fixed():
    """The reason this test exists rather than a mean comparison.

    A population that spread out around the same centre is a real change that a
    location test cannot see. Energy distance is consistent against all
    alternatives, and this is the case that proves it matters.
    """
    result = energy_distance_test(
        gaussian(150, 6, scale=1.0, seed=1),
        gaussian(150, 6, scale=2.2, seed=2),
        rng=rng(),
        permutations=199,
    )
    assert result.fired()


def test_a_tiny_current_population_is_insufficient_not_clean():
    """The single most important behaviour in this module.

    5000 reference samples against 3 current ones: the permutation test stays
    *valid* and has no power at all, so a non-significant result would be
    reported as reassurance it has not earned.
    """
    result = energy_distance_test(
        gaussian(500, 8, seed=1),
        gaussian(3, 8, shift=5.0, seed=2),
        rng=rng(),
        min_per_side=20,
        permutations=199,
    )
    assert result.status is MetricStatus.INSUFFICIENT_SAMPLE
    assert result.statistic is None
    assert result.significant is None
    assert "20" in result.reason


def test_an_unresolvable_permutation_budget_is_refused():
    result = energy_distance_test(
        gaussian(60, 4, seed=1), gaussian(60, 4, seed=2), rng=rng(), permutations=10
    )
    assert result.status is MetricStatus.NOT_ASSESSED


def test_mismatched_feature_spaces_are_refused_rather_than_compared():
    result = energy_distance_test(
        gaussian(60, 4, seed=1), gaussian(60, 8, seed=2), rng=rng(), permutations=199
    )
    assert result.status is MetricStatus.NOT_ASSESSED
    assert "feature space" in result.reason


def test_the_energy_test_reports_what_it_capped_and_what_it_had():
    result = energy_distance_test(
        gaussian(900, 4, seed=1),
        gaussian(900, 4, seed=2),
        rng=rng(),
        permutations=199,
        max_per_side=100,
    )
    assert result.observation["reference_used"] == 100
    assert result.observation["reference_available"] == 900
    assert result.observation["p_value_resolution"] == pytest.approx(1 / 200)


def test_the_energy_test_is_deterministic_for_a_seed():
    left, right = gaussian(80, 5, seed=1), gaussian(80, 5, shift=0.4, seed=2)
    first = energy_distance_test(left, right, rng=rng(11), permutations=199)
    second = energy_distance_test(left, right, rng=rng(11), permutations=199)
    assert first.p_value == second.p_value
    assert first.statistic == second.statistic


# ---------------------------------------------------------------------------
# Mean shift — characterisation, not a test
# ---------------------------------------------------------------------------


def test_mean_shift_makes_no_decision():
    """It has no ``significant`` value, and that is the contract."""
    result = mean_shift(gaussian(60, 4, seed=1), gaussian(60, 4, shift=3.0, seed=2))
    assert result.status is MetricStatus.ASSESSED
    assert result.significant is None
    assert result.statistic > 0


def test_mean_shift_attributes_movement_to_the_block_that_moved():
    reference = np.zeros((60, 10))
    current = np.zeros((60, 10))
    current[:, 5:] = 4.0
    result = mean_shift(
        reference, current, blocks=(("first", 0, 5), ("second", 5, 10))
    )
    shares = result.observation["block_contributions"]
    assert shares["second"]["share_of_squared_displacement"] == pytest.approx(1.0)
    assert result.observation["dominant_block"] == "second"


def test_mean_shift_refuses_a_population_too_small_to_have_a_centre():
    result = mean_shift(gaussian(60, 4, seed=1), gaussian(3, 4, seed=2))
    assert result.status is MetricStatus.INSUFFICIENT_SAMPLE


# ---------------------------------------------------------------------------
# Covariance shift
# ---------------------------------------------------------------------------


def test_covariance_shift_is_quiet_on_two_draws_from_one_process():
    """The regression that motivated cross-fitting.

    An in-sample principal basis made every current population look contracted;
    measured on the real corpus it reported a log-det ratio of -2.35 between two
    clean draws. This asserts the corrected form stays quiet.
    """
    result = covariance_shift(
        gaussian(200, 12, seed=1),
        gaussian(200, 12, seed=2),
        rng=rng(),
        components=4,
        permutations=199,
    )
    assert result.status is MetricStatus.ASSESSED
    assert not result.significant


def test_covariance_shift_finds_a_genuine_spread_change():
    result = covariance_shift(
        gaussian(200, 12, scale=1.0, seed=1),
        gaussian(200, 12, scale=3.0, seed=2),
        rng=rng(),
        components=4,
        permutations=199,
    )
    assert result.fired()
    assert result.statistic > 0  # expanded


def test_covariance_shift_needs_twice_the_reference_because_it_cross_fits():
    result = covariance_shift(
        gaussian(30, 12, seed=1),
        gaussian(200, 12, seed=2),
        rng=rng(),
        components=4,
        samples_per_component=5,
        permutations=199,
    )
    assert result.status is MetricStatus.INSUFFICIENT_SAMPLE
    assert result.requirement["min_reference_samples"] == 40


def test_covariance_shift_refuses_a_space_narrower_than_its_components():
    result = covariance_shift(
        gaussian(200, 3, seed=1), gaussian(200, 3, seed=2), rng=rng(), components=8
    )
    assert result.status is MetricStatus.NOT_ASSESSED


# ---------------------------------------------------------------------------
# Marginal PSI
# ---------------------------------------------------------------------------


def test_psi_is_zero_for_a_distribution_against_itself():
    values = np.random.default_rng(3).normal(size=400)
    value, _ = population_stability_index(values, values, bins=10)
    assert value == pytest.approx(0.0, abs=1e-9)


def test_psi_survives_a_category_absent_from_the_current_population():
    """The ``ln(0)`` failure mode, floored rather than infinite."""
    reference = np.concatenate([np.zeros(200), np.ones(200)])
    current = np.zeros(200)
    value, detail = population_stability_index(reference, current, bins=4)
    assert np.isfinite(value)
    assert detail["empty_current_bins"] >= 1


def test_marginal_psi_does_not_fire_on_two_draws_from_one_process():
    """The measured correction: the conventional 0.25 band is unusable here.

    Splitting a clean 144-sample reference in half and taking the largest PSI
    across 23 quantities measured a mean of 0.49 — twice the "major shift" band.
    The decision therefore comes from a permutation null, and this asserts the
    null does its job.
    """
    names = tuple(f"q{i}" for i in range(12))
    result = marginal_psi(
        gaussian(150, 12, seed=1),
        gaussian(150, 12, seed=2),
        names=names,
        rng=rng(),
        permutations=199,
    )
    assert result.status is MetricStatus.ASSESSED
    assert not result.significant, result.interpretation


def test_marginal_psi_finds_a_quantity_that_actually_moved():
    names = tuple(f"q{i}" for i in range(6))
    reference = gaussian(200, 6, seed=1)
    current = gaussian(200, 6, seed=2)
    current[:, 2] += 4.0
    result = marginal_psi(
        reference, current, names=names, rng=rng(), permutations=199
    )
    assert result.fired()
    assert "q2" in result.observation["exceeded"]


def test_marginal_psi_corrects_for_multiplicity():
    names = tuple(f"q{i}" for i in range(6))
    reference = gaussian(200, 6, seed=1)
    current = gaussian(200, 6, seed=2)
    current[:, 0] += 4.0
    result = marginal_psi(
        reference, current, names=names, rng=rng(), permutations=199
    )
    quantities = result.observation["quantities"]
    assert all("q_value" in q for q in quantities.values() if q.get("psi") is not None)
    assert quantities["q0"]["q_value"] <= quantities["q1"]["q_value"]


def test_marginal_psi_refuses_a_sample_too_small_for_its_bins():
    result = marginal_psi(
        gaussian(20, 4, seed=1),
        gaussian(20, 4, seed=2),
        names=("a", "b", "c", "d"),
        rng=rng(),
        bins=10,
        min_per_bin=5,
    )
    assert result.status is MetricStatus.INSUFFICIENT_SAMPLE


def test_marginal_psi_reports_a_constant_quantity_as_unassessed_not_stable():
    reference = gaussian(200, 3, seed=1)
    current = gaussian(200, 3, seed=2)
    reference[:, 1] = 0.5
    current[:, 1] = 0.5
    result = marginal_psi(
        reference, current, names=("a", "b", "c"), rng=rng(), permutations=199
    )
    assert result.observation["quantities"]["b"]["band"] == "NOT_ASSESSED"


def test_the_psi_band_is_reported_but_is_not_the_decision():
    """A value the folklore calls 'major shift' that the null calls ordinary."""
    names = tuple(f"q{i}" for i in range(20))
    result = marginal_psi(
        gaussian(60, 20, seed=1),
        gaussian(60, 20, seed=2),
        names=names,
        rng=rng(),
        bins=10,
        min_per_bin=5,
        permutations=199,
    )
    assert result.status is MetricStatus.ASSESSED
    assert "do not decide anything" in result.observation["reporting_band_note"]
    assert not result.significant


# ---------------------------------------------------------------------------
# Categorical shift
# ---------------------------------------------------------------------------


def test_jensen_shannon_is_finite_on_disjoint_support():
    """The reason KL was rejected: a new class is the normal case, not an error."""
    value = jensen_shannon_divergence(np.array([10.0, 0.0]), np.array([0.0, 10.0]))
    assert value == pytest.approx(1.0)


def test_an_identical_class_mix_is_not_a_shift():
    counts = {"a": 40, "b": 30, "c": 30}
    result = categorical_shift(counts, counts, label="class", rng=rng())
    assert result.status is MetricStatus.ASSESSED
    assert result.statistic == pytest.approx(0.0)
    assert not result.significant


def test_a_reversed_class_mix_is_a_shift():
    result = categorical_shift(
        {"a": 90, "b": 10}, {"a": 10, "b": 90}, label="class", rng=rng()
    )
    assert result.fired()
    assert result.p_value <= 0.01


def test_a_new_category_is_named_rather_than_collapsed():
    result = categorical_shift(
        {"a": 100}, {"a": 60, "b": 40}, label="class", rng=rng()
    )
    assert result.observation["appeared"] == ["b"]
    assert result.fired()


def test_a_small_categorical_sample_is_insufficient():
    result = categorical_shift(
        {"a": 5, "b": 5}, {"a": 1}, label="class", rng=rng(), min_per_side=20
    )
    assert result.status is MetricStatus.INSUFFICIENT_SAMPLE


def test_a_tiny_but_real_categorical_difference_is_not_significant_at_low_n():
    """Small counts should not manufacture significance."""
    result = categorical_shift(
        {"a": 12, "b": 10}, {"a": 10, "b": 12}, label="class", rng=rng(),
        min_per_side=20,
    )
    assert result.status is MetricStatus.ASSESSED
    assert not result.significant


# ---------------------------------------------------------------------------
# The shared contract
# ---------------------------------------------------------------------------


def test_no_metric_reports_a_statistic_it_could_not_support():
    """A number without support is never emitted, whatever the metric."""
    tiny_left, tiny_right = gaussian(4, 6, seed=1), gaussian(4, 6, seed=2)
    results = [
        energy_distance_test(tiny_left, tiny_right, rng=rng(), permutations=199),
        mean_shift(tiny_left, tiny_right),
        covariance_shift(tiny_left, tiny_right, rng=rng(), components=4),
        marginal_psi(
            tiny_left, tiny_right, names=tuple("abcdef"), rng=rng(), permutations=199
        ),
        categorical_shift({"a": 2}, {"a": 2}, label="class", rng=rng()),
    ]
    for result in results:
        assert result.status is not MetricStatus.ASSESSED
        assert result.statistic is None
        assert result.p_value is None
        assert result.significant is None
        assert "not a statement that the distribution is stable" in result.interpretation or (
            "Absence of a result is not a clean result" in result.interpretation
        )


def test_every_metric_records_what_it_required_and_what_it_got():
    result = energy_distance_test(
        gaussian(500, 4, seed=1), gaussian(3, 4, seed=2), rng=rng(), permutations=199
    )
    assert result.requirement["reference_samples"] == 500
    assert result.requirement["current_samples"] == 3
    assert result.requirement["min_samples_per_side"] == 20


def test_the_permutation_budget_is_scaled_to_the_multiplicity():
    """The defect no threshold review would have caught.

    With B permutations the finest p is 1/(B+1), and Benjamini-Hochberg
    multiplies the smallest by the number of tests. At B=199 and 23 quantities
    the best achievable q is 0.115, so alpha=0.01 was unreachable BY
    CONSTRUCTION -- measured on a quantity displaced four standard deviations,
    PSI 5.31, reported not significant.
    """
    names = tuple(f"q{i}" for i in range(23))
    reference = gaussian(200, 23, seed=1)
    current = gaussian(200, 23, seed=2)
    current[:, 3] += 4.0
    result = marginal_psi(
        reference, current, names=names, rng=rng(), permutations=199, alpha=0.01
    )
    assert result.requirement["permutations_requested"] == 199
    assert result.requirement["permutations_used"] == 2299  # ceil(23 / 0.01) - 1
    assert result.requirement["significance_resolvable_after_correction"]
    assert result.fired()
    assert "q3" in result.observation["exceeded"]


def test_an_unresolvable_budget_says_so_rather_than_reporting_no_shift():
    """Capping below what the multiplicity needs must not read as 'stable'."""
    names = tuple(f"q{i}" for i in range(23))
    reference = gaussian(200, 23, seed=1)
    current = gaussian(200, 23, seed=2)
    current[:, 3] += 4.0
    result = marginal_psi(
        reference,
        current,
        names=names,
        rng=rng(),
        permutations=199,
        max_permutations=199,
        alpha=0.01,
    )
    assert not result.observation["significance_resolvable_after_correction"]
    assert not result.significant
    assert "could NOT be resolved" in result.interpretation
    assert "not a finding of stability" in result.interpretation
