"""Parameter statistics, peer grouping and trigger representation."""

from __future__ import annotations

import numpy as np
import pytest

from cvtrust.models.base import ParameterTensor
from cvtrust.models.params import (
    analyse_parameters,
    compare_parameters,
    non_finite_weights,
    peer_group_of,
    peer_outliers,
    tensor_stats,
)


def tensor(name, values, op_type="Conv", dtype="float32"):
    array = np.asarray(values, dtype=np.float64)
    return ParameterTensor(
        name=name, dtype=dtype, shape=array.shape, values=array,
        owner=name.rsplit(".", 1)[0] if "." in name else None, op_type=op_type,
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def test_tensor_stats_match_numpy():
    values = np.array([1.0, 2.0, 3.0, 4.0])
    stats = tensor_stats(tensor("w", values))
    assert stats.mean == pytest.approx(values.mean())
    assert stats.std == pytest.approx(values.std())
    assert stats.l1_norm == pytest.approx(np.abs(values).sum())
    assert stats.l2_norm == pytest.approx(np.linalg.norm(values))
    assert stats.max_abs == pytest.approx(4.0)


def test_sparsity_counts_near_zero_weights():
    stats = tensor_stats(tensor("w", [0.0, 0.0, 1.0, 2.0]))
    assert stats.sparsity == pytest.approx(0.5)


def test_stats_survive_non_finite_weights_without_propagating_them():
    stats = tensor_stats(tensor("w", [1.0, 2.0, np.nan, np.inf]))
    assert stats.non_finite == 2
    assert np.isfinite(stats.mean) and np.isfinite(stats.std)


def test_an_entirely_non_finite_tensor_does_not_raise():
    stats = tensor_stats(tensor("w", [np.nan, np.nan]))
    assert stats.non_finite == 2
    assert stats.mean == 0.0


def test_non_finite_weights_are_reported_per_tensor():
    result = non_finite_weights([
        tensor("a", [1.0, 2.0]),
        tensor("b", [np.nan, 1.0]),
        tensor("c", [np.inf, np.inf]),
    ])
    assert result["total_non_finite"] == 3
    names = {entry["tensor"] for entry in result["affected_tensors"]}
    assert names == {"b", "c"}


def test_analyse_parameters_rolls_up_by_operator_type():
    analysis = analyse_parameters([
        tensor("c1.weight", np.ones((2, 2)), op_type="Conv"),
        tensor("c2.weight", np.ones((2, 2)) * 2, op_type="Conv"),
        tensor("fc.weight", np.ones((3,)), op_type="Gemm"),
    ])
    assert analysis["tensor_count"] == 3
    assert analysis["parameter_count"] == 11
    assert set(analysis["by_op_type"]) == {"Conv", "Gemm"}


# ---------------------------------------------------------------------------
# Peer grouping — the fix for a measured false-positive source
# ---------------------------------------------------------------------------


def test_peer_group_separates_parameter_roles_within_an_operator_type():
    """BatchNorm scales and running variances are not comparable quantities."""
    weight = tensor_stats(tensor("bn.weight", [1.0], op_type="BatchNorm2d"))
    variance = tensor_stats(tensor("bn.running_var", [1.0], op_type="BatchNorm2d"))
    assert peer_group_of(weight) != peer_group_of(variance)
    assert peer_group_of(weight) == "BatchNorm2d/weight"


def test_peer_group_falls_back_to_rank_for_exporter_chosen_names():
    kernel = tensor_stats(tensor("onnx::Conv_47", np.ones((4, 3, 3, 3)), op_type="Conv"))
    bias = tensor_stats(tensor("onnx::Conv_48", np.ones(4), op_type="Conv"))
    assert peer_group_of(kernel) == "Conv/rank4"
    assert peer_group_of(bias) == "Conv/rank1"


def test_peer_screening_is_silent_on_a_homogeneous_model():
    rng = np.random.default_rng(0)
    tensors = [
        tensor(f"c{i}.weight", rng.normal(0, 0.1, (4, 4)), op_type="Conv")
        for i in range(8)
    ]
    assert peer_outliers(tensors)["n_outliers"] == 0


def test_peer_screening_false_alarm_rate_is_measured_not_assumed():
    """Reproduces the simulation behind DEFAULT_PEER_Z.

    Every peer group here is drawn from one distribution, so every flag is a
    false alarm by construction. The conventional 3.5 threshold fires on roughly
    a third of clean groups, which is why this project does not use it.
    """
    from cvtrust.models.params import DEFAULT_PEER_Z

    def false_alarm_rate(z: float, n: int, trials: int = 200) -> float:
        hits = 0
        for seed in range(trials):
            rng = np.random.default_rng(seed)
            group = [
                tensor(f"c{i}.weight", rng.normal(0, 0.1, (4, 4)), op_type="Conv")
                for i in range(n)
            ]
            if peer_outliers(group, z_threshold=z)["n_outliers"]:
                hits += 1
        return hits / trials

    assert false_alarm_rate(3.5, 8) > 0.15, "the conventional threshold is unusable here"
    assert false_alarm_rate(DEFAULT_PEER_Z, 8) <= 0.05
    assert false_alarm_rate(DEFAULT_PEER_Z, 12) <= 0.05


def test_the_finite_sample_mad_correction_is_applied():
    from cvtrust.models.params import mad_finite_sample_factor

    # Biased low at small n, converging to 1 as n grows.
    assert mad_finite_sample_factor(6) > 1.1
    assert mad_finite_sample_factor(100) == pytest.approx(1.0, abs=0.01)


def test_peer_screening_flags_a_tensor_far_from_its_peers():
    rng = np.random.default_rng(0)
    tensors = [
        tensor(f"c{i}.weight", rng.normal(0, 0.1, (4, 4)), op_type="Conv")
        for i in range(8)
    ]
    tensors.append(tensor("c6.weight", np.full((4, 4), 5000.0), op_type="Conv"))
    result = peer_outliers(tensors)
    assert result["n_outliers"] >= 1
    assert result["outliers"][0]["tensor"] == "c6.weight"


def test_peer_screening_skips_groups_too_small_to_estimate_and_says_so():
    """A handful of peers cannot support a median/MAD outlier call."""
    tensors = [
        tensor("a.weight", [1.0], op_type="Conv"),
        tensor("b.weight", [2.0], op_type="Conv"),
        tensor("c.weight", [900.0], op_type="Conv"),
    ]
    result = peer_outliers(tensors)
    assert result["n_outliers"] == 0
    assert result["skipped_small_groups"], "a skipped group must be reported"


def test_peer_screening_always_carries_its_interpretation_limit():
    result = peer_outliers([tensor("a.weight", [1.0])])
    assert "not evidence of a backdoor" in result["interpretation_limit"]


# ---------------------------------------------------------------------------
# Reference comparison
# ---------------------------------------------------------------------------


def test_identical_weights_compare_as_identical():
    left = [tensor("w", np.ones((3, 3)))]
    right = [tensor("w", np.ones((3, 3)))]
    result = compare_parameters(left, right)
    assert result["changed_tensors"] == 0
    assert result["identical_tensors"] == 1


def test_a_single_changed_tensor_is_localised_and_named():
    left = [
        tensor("a", np.ones((4, 4))),
        tensor("b", np.ones((4, 4)) * 5.0),
    ]
    right = [
        tensor("a", np.ones((4, 4))),
        tensor("b", np.ones((4, 4))),
    ]
    result = compare_parameters(left, right)
    assert result["changed_tensors"] == 1
    assert result["changed"][0]["name"] == "b"
    assert result["concentration"]["pattern"] == "localised"


def test_a_broad_small_change_reads_as_distributed():
    """The shape of a fine-tune, as distinct from a targeted edit."""
    rng = np.random.default_rng(1)
    right = [tensor(f"t{i}", np.ones((8, 8))) for i in range(6)]
    left = [
        tensor(f"t{i}", np.ones((8, 8)) + rng.normal(0, 0.01, (8, 8)))
        for i in range(6)
    ]
    result = compare_parameters(left, right)
    assert result["changed_tensors"] == 6
    assert result["concentration"]["pattern"] == "distributed"


def test_comparison_separates_structural_from_value_differences():
    left = [tensor("a", np.ones((2, 3))), tensor("only_left", np.ones(2))]
    right = [tensor("a", np.ones((3, 2))), tensor("only_right", np.ones(2))]
    result = compare_parameters(left, right)
    assert result["reshaped_tensors"][0]["name"] == "a"
    assert result["only_in_supplied"] == ["only_left"]
    assert result["only_in_reference"] == ["only_right"]


def test_cosine_similarity_is_reported_for_a_changed_tensor():
    left = [tensor("w", [1.0, 0.0])]
    right = [tensor("w", [0.0, 1.0])]
    result = compare_parameters(left, right)
    assert result["changed"][0]["cosine_similarity"] == pytest.approx(0.0, abs=1e-9)


def test_the_shipped_config_default_matches_the_measured_threshold():
    """The threshold an analyst reads must be the threshold the code uses."""
    from cvtrust.core.config import Config
    from cvtrust.models.params import DEFAULT_PEER_Z

    assert Config().model.parameters.peer_z_threshold == DEFAULT_PEER_Z
