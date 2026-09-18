"""White-box parameter statistics.

What this module may and may not conclude
-----------------------------------------
It may conclude: *these weights differ from the reference's, here, by this
much*, or *this tensor's statistics are far from those of its architectural
peers*.

It may **not** conclude: *therefore the model is backdoored*.  There is no
published result establishing that unusual weight statistics imply a backdoor,
and plenty of benign causes produce them — quantisation-aware training, a
different initialisation scheme, a layer that legitimately saturates, aggressive
weight decay, a fine-tune on a small dataset.  Everything here is therefore
emitted as a ``PARAMETER ANOMALY INDICATOR``: supporting evidence that qualifies
another finding, never a standalone verdict.

Two comparison regimes, with very different evidential weight
-------------------------------------------------------------
**Against a trusted reference** the comparison is *deterministic*: tensor
digests either match or they do not, and where they do not, the per-tensor
relative L2 delta and cosine similarity localise the change to specific layers.
That is a fact, and it is reported with ``DETERMINISTIC`` confidence.

**Without a reference** all that is available is a peer comparison: how far is
this tensor's statistic from the other tensors of the same operator type in the
same model?  A robust z-score (median and MAD, not mean and standard deviation,
because the outlier we are looking for would inflate a standard deviation and
hide itself) gives a screening signal only, and it is reported as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

from ..core.logging import get_logger
from .base import ParameterTensor

log = get_logger("models.params")

PARAMETER_ANALYSIS_VERSION = "1.0"

#: Robust z-score above which a tensor statistic is called out as a peer-group
#: outlier.
#:
#: **Not the conventional 3.5**, and the difference is measured rather than
#: chosen.  Iglewicz & Hoaglin's 3.5 is the operating point for a *single*
#: statistic on a reasonably large sample.  This screening tests **four**
#: statistics per peer group on groups that are often smaller than ten tensors,
#: and both departures inflate the false-alarm rate badly.
#:
#: Simulated against the null (peer groups drawn from one distribution, so every
#: flag is a false alarm), 400 draws per cell:
#:
#: ===========  =========  =========  =========  =========
#: group size   z = 3.5    z = 5.0    z = 6.0    z = 8.0
#: ===========  =========  =========  =========  =========
#: 6            0.350      0.150      0.090      0.033
#: 8            0.360      0.102      0.050      0.018
#: 12           0.290      0.065      0.013      0.000
#: 20           0.280      0.035      0.013      0.000
#: ===========  =========  =========  =========  =========
#:
#: At 3.5 roughly a third of clean models would carry a parameter-anomaly
#: finding, which is precisely the behaviour that destroys an analyst's trust in
#: a tool.  8.0 holds the family-wise false-alarm rate at or below ~3% across the
#: group sizes real architectures produce, and is the default for that reason.
#: The simulation is reproduced by
#: ``tests/unit/test_model_params.py::test_peer_screening_false_alarm_rate_is_measured``.
DEFAULT_PEER_Z = 8.0

#: Scale factor making MAD a consistent estimator of sigma for a normal sample,
#: asymptotically.
MAD_TO_SIGMA = 1.4826

#: Minimum peers before a median/MAD outlier call is attempted at all.
MIN_PEER_GROUP = 6


def mad_finite_sample_factor(n: int) -> float:
    """Croux & Rousseeuw (1992) finite-sample correction for the MAD.

    ``MAD × 1.4826`` is only asymptotically a consistent estimator of sigma.  At
    the sample sizes a peer group actually has — six to twenty tensors — it is
    biased *low*, which inflates every z-score computed from it and manufactures
    outliers.  This factor removes that bias.
    """
    table = {2: 1.196, 3: 1.495, 4: 1.363, 5: 1.206, 6: 1.200, 7: 1.140,
             8: 1.129, 9: 1.107}
    if n in table:
        return table[n]
    return n / (n - 0.8) if n > 1 else 1.0


@dataclass(frozen=True, slots=True)
class TensorStats:
    """Summary statistics for one weight tensor."""

    name: str
    op_type: str | None
    owner: str | None
    dtype: str
    shape: tuple[int, ...]
    count: int
    mean: float
    std: float
    l1_norm: float
    l2_norm: float
    max_abs: float
    sparsity: float
    kurtosis: float
    fraction_beyond_6_sigma: float
    non_finite: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "op_type": self.op_type,
            "dtype": self.dtype,
            "shape": list(self.shape),
            "count": self.count,
            "mean": round(self.mean, 8),
            "std": round(self.std, 8),
            "l1_norm": round(self.l1_norm, 6),
            "l2_norm": round(self.l2_norm, 6),
            "max_abs": round(self.max_abs, 6),
            "sparsity": round(self.sparsity, 6),
            "kurtosis": round(self.kurtosis, 6),
            "fraction_beyond_6_sigma": round(self.fraction_beyond_6_sigma, 8),
            "non_finite": self.non_finite,
        }


def tensor_stats(tensor: ParameterTensor) -> TensorStats:
    values = np.asarray(tensor.values, dtype=np.float64).reshape(-1)
    finite_mask = np.isfinite(values)
    non_finite = int(values.size - int(finite_mask.sum()))
    finite = values[finite_mask]
    if finite.size == 0:
        return TensorStats(
            name=tensor.name, op_type=tensor.op_type, owner=tensor.owner,
            dtype=tensor.dtype, shape=tuple(int(d) for d in tensor.shape),
            count=int(values.size), mean=0.0, std=0.0, l1_norm=0.0, l2_norm=0.0,
            max_abs=0.0, sparsity=1.0, kurtosis=0.0, fraction_beyond_6_sigma=0.0,
            non_finite=non_finite,
        )

    mean = float(np.mean(finite))
    std = float(np.std(finite))
    centred = finite - mean
    # Excess kurtosis. Heavy tails are the statistic most often cited as a
    # weight-tampering signal, and it is reported precisely because it is easy
    # to over-read: a legitimately sparse layer has heavy tails too.
    kurtosis = (
        float(np.mean(centred**4) / (std**4)) - 3.0 if std > 1e-12 else 0.0
    )
    beyond = float(np.mean(np.abs(centred) > 6.0 * std)) if std > 1e-12 else 0.0
    return TensorStats(
        name=tensor.name,
        op_type=tensor.op_type,
        owner=tensor.owner,
        dtype=tensor.dtype,
        shape=tuple(int(d) for d in tensor.shape),
        count=int(values.size),
        mean=mean,
        std=std,
        l1_norm=float(np.sum(np.abs(finite))),
        l2_norm=float(np.linalg.norm(finite)),
        max_abs=float(np.max(np.abs(finite))),
        sparsity=float(np.mean(np.abs(finite) < 1e-8)),
        kurtosis=kurtosis,
        fraction_beyond_6_sigma=beyond,
        non_finite=non_finite,
    )


def analyse_parameters(tensors: Sequence[ParameterTensor]) -> dict[str, Any]:
    """Layer-wise statistics plus the model-level roll-up."""
    stats = [tensor_stats(t) for t in tensors]
    total = sum(s.count for s in stats)
    return {
        "analysis_version": PARAMETER_ANALYSIS_VERSION,
        "tensor_count": len(stats),
        "parameter_count": total,
        "non_finite_total": sum(s.non_finite for s in stats),
        "global": {
            "mean_l2_norm": round(
                float(np.mean([s.l2_norm for s in stats])) if stats else 0.0, 6
            ),
            "max_abs_weight": round(max((s.max_abs for s in stats), default=0.0), 6),
            "mean_sparsity": round(
                float(np.mean([s.sparsity for s in stats])) if stats else 0.0, 6
            ),
        },
        "tensors": [s.as_dict() for s in stats],
        "by_op_type": _by_op_type(stats),
    }


def _by_op_type(stats: Sequence[TensorStats]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[TensorStats]] = {}
    for stat in stats:
        groups.setdefault(stat.op_type or "unknown", []).append(stat)
    return {
        op: {
            "n": len(members),
            "parameter_count": sum(m.count for m in members),
            "median_l2_norm": round(float(np.median([m.l2_norm for m in members])), 6),
            "median_kurtosis": round(float(np.median([m.kurtosis for m in members])), 6),
        }
        for op, members in sorted(groups.items())
    }


def compare_parameters(
    supplied: Sequence[ParameterTensor], reference: Sequence[ParameterTensor]
) -> dict[str, Any]:
    """Per-tensor comparison against a trusted reference.

    This is the strongest evidence Module 2 can produce about modification short
    of a digest mismatch, because it localises: not "the model changed" but
    "``features.3.weight`` changed by a relative L2 of 0.31 and nothing else
    did".  Structural differences (missing, added or reshaped tensors) are
    reported separately from value differences, because they mean different
    things.
    """
    left = {t.name: t for t in supplied}
    right = {t.name: t for t in reference}

    only_supplied = sorted(set(left) - set(right))
    only_reference = sorted(set(right) - set(left))
    shared = sorted(set(left) & set(right))

    reshaped: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    identical = 0

    for name in shared:
        # Compare the DECLARED shapes, not the flattened buffers. A (2,3) and a
        # (3,2) tensor flatten to the same length, so comparing flattened shapes
        # silently misses a reshape — which is a structural change, and exactly
        # the kind this function exists to separate from a value change.
        if tuple(left[name].shape) != tuple(right[name].shape):
            reshaped.append({
                "name": name,
                "supplied_shape": list(left[name].shape),
                "reference_shape": list(right[name].shape),
            })
            continue
        a = np.asarray(left[name].values, dtype=np.float64).reshape(-1)
        b = np.asarray(right[name].values, dtype=np.float64).reshape(-1)
        if a.shape != b.shape:
            reshaped.append({
                "name": name,
                "supplied_shape": list(left[name].shape),
                "reference_shape": list(right[name].shape),
            })
            continue
        if np.array_equal(a, b):
            identical += 1
            continue
        delta = a - b
        reference_norm = float(np.linalg.norm(b))
        delta_norm = float(np.linalg.norm(delta))
        denominator = float(np.linalg.norm(a)) * reference_norm
        cosine = float(np.dot(a, b) / denominator) if denominator > 1e-12 else 0.0
        changed_mask = np.abs(delta) > 1e-8
        changed.append({
            "name": name,
            "op_type": left[name].op_type,
            "count": int(a.size),
            "changed_elements": int(changed_mask.sum()),
            "changed_fraction": round(float(changed_mask.mean()), 8),
            "relative_l2_delta": round(
                delta_norm / reference_norm if reference_norm > 1e-12 else float("inf"), 8
            ),
            "absolute_l2_delta": round(delta_norm, 8),
            "max_absolute_delta": round(float(np.max(np.abs(delta))), 8),
            "cosine_similarity": round(cosine, 8),
        })

    changed.sort(key=lambda entry: -entry["relative_l2_delta"])
    return {
        "analysis_version": PARAMETER_ANALYSIS_VERSION,
        "comparable": True,
        "shared_tensors": len(shared),
        "identical_tensors": identical,
        "changed_tensors": len(changed),
        "reshaped_tensors": reshaped,
        "only_in_supplied": only_supplied,
        "only_in_reference": only_reference,
        "changed": changed,
        "total_changed_elements": sum(c["changed_elements"] for c in changed),
        "max_relative_l2_delta": (
            max((c["relative_l2_delta"] for c in changed), default=0.0)
        ),
        "concentration": _change_concentration(changed),
    }


def _change_concentration(changed: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Is the modification spread across the model, or focused on one tensor?

    The distinction matters for interpretation and is therefore measured rather
    than eyeballed: a fine-tune moves *every* tensor a little, while a targeted
    weight edit moves one tensor a lot.  Neither is proof of anything, but they
    are different observations and the report should not blur them.
    """
    if not changed:
        return {"pattern": "none", "n_changed": 0}
    deltas = np.asarray([c["absolute_l2_delta"] for c in changed], dtype=np.float64)
    total = float(deltas.sum())
    top_share = float(deltas.max() / total) if total > 0 else 0.0
    if len(changed) == 1 or top_share > 0.80:
        pattern = "localised"
        reading = ("the change is concentrated in a single tensor, which is the "
                   "shape of a targeted edit rather than of retraining")
    elif len(changed) > 3 and top_share < 0.40:
        pattern = "distributed"
        reading = ("the change is spread across many tensors, which is the shape "
                   "of retraining or fine-tuning rather than of a targeted edit")
    else:
        pattern = "mixed"
        reading = "the change is neither clearly localised nor clearly distributed"
    return {
        "pattern": pattern,
        "n_changed": len(changed),
        "top_tensor": changed[0]["name"],
        "top_tensor_share_of_total_delta": round(top_share, 6),
        "reading": reading,
    }


#: Parameter-name suffixes that identify a tensor's *role* within its layer.
#: Grouping on operator type alone is not enough, and the failure is not
#: subtle: a ``BatchNorm`` layer contributes a scale near 1, a bias near 0, a
#: running mean on the scale of the activations and a running variance on their
#: square. Pooled into one "BatchNorm" peer group, those four roles have a
#: median and MAD that describe nothing, and a clean model produces a stream of
#: "outliers" that are only outliers with respect to a group they were never
#: comparable to. Measured on a clean lab model, role-blind grouping reported 8
#: peer outliers where role-aware grouping reports none.
_ROLE_SUFFIXES: tuple[str, ...] = (
    "weight", "bias", "running_mean", "running_var", "num_batches_tracked",
    "scale", "zero_point", "gamma", "beta",
)


def peer_group_of(stat: TensorStats) -> str:
    """The peer group a tensor is compared within: ``<op_type>/<role>``.

    Role is taken from the parameter name's last component where it is one of
    the conventional names, and from the tensor's rank otherwise (a rank-4
    tensor is a kernel, a rank-1 tensor is a vector) — which keeps ONNX
    initializers, whose names are exporter-chosen, in sensible groups too.
    """
    op_type = stat.op_type or "unknown"
    tail = stat.name.rsplit(".", 1)[-1].lower()
    if tail in _ROLE_SUFFIXES:
        return f"{op_type}/{tail}"
    return f"{op_type}/rank{len(stat.shape)}"


def peer_outliers(
    tensors: Sequence[ParameterTensor], *, z_threshold: float = DEFAULT_PEER_Z
) -> dict[str, Any]:
    """Reference-free screening: tensors far from their architectural peers.

    Each tensor is compared to the other tensors of the same **operator type and
    parameter role** in the same model.  A convolution kernel and a batch-norm
    scale have no reason to share a scale, and neither do a batch-norm scale and
    a batch-norm running variance — see :data:`_ROLE_SUFFIXES` for why the
    second half of that sentence is the one that actually mattered.

    Median and MAD are used rather than mean and standard deviation: the outlier
    we are looking for is, by construction, in the sample, and it would inflate a
    standard deviation enough to hide itself.

    The output is explicitly a **screening signal**.  A peer outlier with no
    corroborating behavioural evidence is a statement about weight statistics,
    and the finding built from it says exactly that.
    """
    stats = [tensor_stats(t) for t in tensors]
    groups: dict[str, list[TensorStats]] = {}
    for stat in stats:
        groups.setdefault(peer_group_of(stat), []).append(stat)

    findings: list[dict[str, Any]] = []
    for group_key, members in sorted(groups.items()):
        # Below MIN_PEER_GROUP peers a median/MAD estimate is not stable enough
        # to call anything an outlier, so the group is skipped and said to be
        # skipped rather than guessed at.
        if len(members) < MIN_PEER_GROUP:
            continue
        correction = mad_finite_sample_factor(len(members))
        for metric in ("l2_norm", "max_abs", "kurtosis", "sparsity"):
            values = np.asarray([getattr(m, metric) for m in members], dtype=np.float64)
            median = float(np.median(values))
            mad = float(np.median(np.abs(values - median)))
            if mad <= 1e-12:
                continue
            # MAD * 1.4826 * b_n estimates sigma under normality with the
            # finite-sample bias removed, so the score is on the familiar z
            # scale and the measured threshold above means what it says.
            scores = (values - median) / (mad * MAD_TO_SIGMA * correction)
            for member, score in zip(members, scores):
                if abs(float(score)) >= z_threshold:
                    findings.append({
                        "tensor": member.name,
                        "peer_group": group_key,
                        "op_type": member.op_type or "unknown",
                        "metric": metric,
                        "value": round(float(getattr(member, metric)), 8),
                        "peer_median": round(median, 8),
                        "peer_mad": round(mad, 8),
                        "robust_z": round(float(score), 4),
                        "peer_group_size": len(members),
                        "mad_finite_sample_factor": round(correction, 4),
                    })
    findings.sort(key=lambda f: -abs(f["robust_z"]))
    skipped = {
        op: len(m) for op, m in sorted(groups.items()) if len(m) < MIN_PEER_GROUP
    }
    return {
        "analysis_version": PARAMETER_ANALYSIS_VERSION,
        "method": "robust z-score (median/MAD, scaled by 1.4826) within "
                  "(operator type, parameter role) peer groups",
        "z_threshold": z_threshold,
        "min_peer_group": MIN_PEER_GROUP,
        "measured_null_false_alarm_rate": (
            "<= ~0.03 family-wise at this threshold, simulated against peer "
            "groups drawn from a single distribution; see DEFAULT_PEER_Z"
        ),
        "outliers": findings,
        "n_outliers": len(findings),
        "peer_groups": {op: len(m) for op, m in sorted(groups.items())},
        "skipped_small_groups": skipped,
        "interpretation_limit": (
            "a peer outlier is a statement about weight statistics within this "
            "model. It is not evidence of a backdoor: quantisation-aware "
            "training, a different initialisation, weight decay and a saturated "
            "layer all produce peer outliers in clean models."
        ),
    }


def non_finite_weights(tensors: Sequence[ParameterTensor]) -> dict[str, Any]:
    """NaN/Inf weights — a deterministic defect, not a statistical one.

    Separated from the statistical path because the claim is of a different
    kind: a NaN weight is a fact about the artifact, it will produce undefined
    behaviour at inference, and it deserves confidence 1.0.
    """
    affected: list[dict[str, Any]] = []
    for tensor in tensors:
        values = np.asarray(tensor.values, dtype=np.float64)
        if not np.issubdtype(values.dtype, np.floating):
            continue
        bad = ~np.isfinite(values)
        count = int(bad.sum())
        if count:
            affected.append({
                "tensor": tensor.name,
                "non_finite_elements": count,
                "total_elements": int(values.size),
                "nan": int(np.isnan(values).sum()),
                "inf": int(np.isinf(values).sum()),
            })
    return {
        "affected_tensors": affected,
        "total_non_finite": sum(a["non_finite_elements"] for a in affected),
    }
