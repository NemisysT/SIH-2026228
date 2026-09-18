"""Reference battery and behavioural metrics.

The battery's determinism is load-bearing: every behavioural claim in Module 2
is scoped to a battery digest, and a digest that is not reproducible makes every
such claim unverifiable.
"""

from __future__ import annotations

import numpy as np
import pytest

from cvtrust.models.battery import (
    BORDERLINE,
    CLEAN,
    DEFAULT_TRIGGER_FAMILY,
    OOD,
    PERTURBATION,
    TRIGGER_PROBE,
    apply_trigger,
    build_battery,
)
from cvtrust.models.behaviour import js_divergence


# ---------------------------------------------------------------------------
# Determinism and structure
# ---------------------------------------------------------------------------


def test_the_battery_is_reproducible_for_a_fixed_seed_and_spec():
    first = build_battery(seed=7, input_shape=(3, 32, 32), clean_per_class=2,
                          borderline_pairs=2, ood_count=2, trigger_bases=2)
    second = build_battery(seed=7, input_shape=(3, 32, 32), clean_per_class=2,
                           borderline_pairs=2, ood_count=2, trigger_bases=2)
    assert first.digest == second.digest
    assert np.array_equal(first.tensor, second.tensor)
    assert [p.probe_id for p in first.probes] == [p.probe_id for p in second.probes]


def test_a_different_seed_changes_the_battery_digest():
    a = build_battery(seed=1, input_shape=(3, 32, 32), clean_per_class=2,
                      borderline_pairs=1, ood_count=1, trigger_bases=1)
    b = build_battery(seed=2, input_shape=(3, 32, 32), clean_per_class=2,
                      borderline_pairs=1, ood_count=1, trigger_bases=1)
    assert a.digest != b.digest


def test_a_different_spec_changes_the_battery_digest():
    a = build_battery(seed=1, input_shape=(3, 32, 32), clean_per_class=2,
                      borderline_pairs=1, ood_count=1, trigger_bases=1)
    b = build_battery(seed=1, input_shape=(3, 32, 32), clean_per_class=3,
                      borderline_pairs=1, ood_count=1, trigger_bases=1)
    assert a.digest != b.digest


def test_the_battery_matches_the_declared_input_shape():
    battery = build_battery(seed=1, input_shape=(3, 64, 64), clean_per_class=1,
                            borderline_pairs=1, ood_count=1, trigger_bases=1)
    assert battery.tensor.shape[1:] == (3, 64, 64)
    assert battery.tensor.dtype == np.float32


def test_a_single_channel_model_gets_a_single_channel_battery():
    battery = build_battery(seed=1, input_shape=(1, 28, 28), clean_per_class=1,
                            borderline_pairs=1, ood_count=1, trigger_bases=1)
    assert battery.tensor.shape[1:] == (1, 28, 28)


def test_every_probe_category_is_present():
    battery = build_battery(seed=3, input_shape=(3, 32, 32))
    categories = {probe.category for probe in battery.probes}
    assert categories == {CLEAN, BORDERLINE, PERTURBATION, OOD, TRIGGER_PROBE}


def test_probe_values_stay_in_the_unit_range():
    battery = build_battery(seed=3, input_shape=(3, 32, 32))
    assert battery.tensor.min() >= 0.0
    assert battery.tensor.max() <= 1.0


def test_each_probe_carries_its_own_digest():
    battery = build_battery(seed=3, input_shape=(3, 32, 32), clean_per_class=2,
                            borderline_pairs=1, ood_count=1, trigger_bases=1)
    digests = [p.digest for p in battery.probes]
    assert all(len(d) == 64 for d in digests)


# ---------------------------------------------------------------------------
# Pairing — what makes the metamorphic and trigger metrics computable
# ---------------------------------------------------------------------------


def test_perturbation_probes_pair_back_to_a_clean_source():
    battery = build_battery(seed=5, input_shape=(3, 32, 32))
    pairs = battery.metamorphic_pairs()
    assert pairs, "metamorphic consistency needs pairs to measure"
    for source, perturbed, meta in pairs:
        assert battery.probes[source].category == CLEAN
        assert battery.probes[perturbed].category == PERTURBATION
        assert "kind" in meta


def test_trigger_probes_pair_back_to_a_clean_source():
    battery = build_battery(seed=5, input_shape=(3, 32, 32))
    pairs = battery.trigger_pairs()
    assert pairs
    for source, triggered, meta in pairs:
        assert battery.probes[source].category == CLEAN
        assert battery.probes[triggered].category == TRIGGER_PROBE
        assert "position" in meta and "pattern" in meta


def test_a_perturbation_actually_changes_its_source():
    """A no-op transformation would make consistency trivially 1.0."""
    battery = build_battery(seed=5, input_shape=(3, 32, 32))
    for source, perturbed, _ in battery.metamorphic_pairs():
        assert not np.array_equal(battery.tensor[source], battery.tensor[perturbed])


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------


def test_a_trigger_changes_only_its_patch_region():
    base = np.full((3, 32, 32), 0.5, dtype=np.float32)
    stamped = apply_trigger(
        base, {"position": "bottom_right", "size_fraction": 0.25, "pattern": "white"}
    )
    changed = np.any(stamped != base, axis=0)
    rows, cols = np.nonzero(changed)
    # Confined to the bottom-right quadrant.
    assert rows.min() >= 16 and cols.min() >= 16
    assert changed.mean() < 0.15


@pytest.mark.parametrize("spec", DEFAULT_TRIGGER_FAMILY)
def test_every_declared_trigger_is_applicable_and_bounded(spec):
    base = np.full((3, 32, 32), 0.5, dtype=np.float32)
    stamped = apply_trigger(base, spec)
    assert stamped.shape == base.shape
    assert stamped.min() >= 0.0 and stamped.max() <= 1.0
    assert not np.array_equal(stamped, base)


def test_trigger_opacity_scales_the_change():
    """The blended-trigger family depends on opacity behaving linearly."""
    base = np.full((3, 32, 32), 0.0, dtype=np.float32)
    spec = {"position": "centre", "size_fraction": 0.5, "pattern": "white"}
    faint = apply_trigger(base, {**spec, "opacity": 0.1})
    full = apply_trigger(base, {**spec, "opacity": 1.0})
    assert faint.sum() < full.sum()
    assert faint.max() == pytest.approx(0.1, abs=1e-6)


def test_applying_a_trigger_is_deterministic():
    base = np.linspace(0, 1, 3 * 32 * 32, dtype=np.float32).reshape(3, 32, 32)
    spec = {"position": "top_left", "size_fraction": 0.2, "pattern": "checker"}
    assert np.array_equal(apply_trigger(base, spec), apply_trigger(base, spec))


# ---------------------------------------------------------------------------
# Jensen-Shannon divergence
# ---------------------------------------------------------------------------


def test_js_divergence_is_zero_for_identical_distributions():
    p = np.array([[0.2, 0.3, 0.5]])
    assert js_divergence(p, p)[0] == pytest.approx(0.0, abs=1e-12)


def test_js_divergence_is_one_bit_for_disjoint_distributions():
    """The bound that makes JS comparable across models."""
    p = np.array([[1.0, 0.0]])
    q = np.array([[0.0, 1.0]])
    assert js_divergence(p, q)[0] == pytest.approx(1.0, abs=1e-9)


def test_js_divergence_is_symmetric():
    p = np.array([[0.7, 0.2, 0.1]])
    q = np.array([[0.1, 0.6, 0.3]])
    assert js_divergence(p, q)[0] == pytest.approx(js_divergence(q, p)[0], abs=1e-12)


def test_js_divergence_is_finite_at_zero_probability():
    """The specific reason KL is not used: KL would be infinite here."""
    p = np.array([[0.5, 0.5, 0.0]])
    q = np.array([[0.0, 0.5, 0.5]])
    value = js_divergence(p, q)[0]
    assert np.isfinite(value)
    assert 0.0 <= value <= 1.0


def test_js_divergence_stays_within_its_bounds_on_random_inputs():
    rng = np.random.default_rng(0)
    p = rng.dirichlet(np.ones(6), size=50)
    q = rng.dirichlet(np.ones(6), size=50)
    values = js_divergence(p, q)
    assert np.all(values >= 0.0) and np.all(values <= 1.0)
