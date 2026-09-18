"""Statistical primitives used to justify confidence and severity.

Everything here is standard and deliberately boring.  The point is that when a
finding says "confidence 0.91", the number traces to one of these functions
applied to values that appear verbatim in the finding's evidence.
"""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np
from scipy import stats

#: One-sided z for a 95% bound.  Used for the Wilson interval that turns a
#: measured precision (k correct out of n flagged) into a conservative
#: confidence: with few observations the bound stays low, which is the
#: behaviour we want from a calibration measured on a small attack-lab run.
Z_95_ONE_SIDED = 1.6448536269514722


def wilson_lower_bound(successes: int, trials: int, z: float = Z_95_ONE_SIDED) -> float:
    """Lower bound of the Wilson score interval for a binomial proportion.

    Preferred over the normal approximation because it stays inside ``[0, 1]``
    and behaves correctly at ``k = 0`` and ``k = n``, both of which occur
    routinely in a small calibration bin.
    """
    if trials <= 0:
        return 0.0
    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = phat + z * z / (2 * trials)
    margin = z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
    return max(0.0, min(1.0, (centre - margin) / denominator))


def binomial_greater_pvalue(successes: int, trials: int, p_null: float) -> float:
    """One-sided ``P(X >= successes)`` under ``Binomial(trials, p_null)``.

    Used for "does this contributor flag at a higher rate than the rest of the
    cohort?".  A tiny ``p_null`` floor avoids a degenerate zero-probability null
    when no other contributor was flagged at all — in that case the honest
    statement is "much higher than a small baseline", not "infinitely
    significant".
    """
    if trials <= 0:
        return 1.0
    p_null = min(max(p_null, 1e-6), 1.0 - 1e-9)
    return float(stats.binomtest(successes, trials, p_null, alternative="greater").pvalue)


def benjamini_hochberg(pvalues: Sequence[float]) -> list[float]:
    """Benjamini-Hochberg adjusted p-values (q-values).

    Every detector in this system runs many tests at once — one per contributor,
    one per (declared, suggested) label pair.  Without correction, a dataset
    with many contributors would manufacture "significant" findings by sheer
    multiplicity, which is precisely the false-positive behaviour that destroys
    an analyst's trust in the tool.  BH controls the false discovery rate, which
    is the relevant error notion here: we care what fraction of reported
    findings are wrong, not whether any single one could be.
    """
    m = len(pvalues)
    if m == 0:
        return []
    order = np.argsort(np.asarray(pvalues, dtype=float), kind="stable")
    ranked = np.asarray(pvalues, dtype=float)[order]
    adjusted = ranked * m / (np.arange(1, m + 1))
    # Enforce monotonicity from the largest p downwards.
    adjusted = np.minimum.accumulate(adjusted[::-1])[::-1]
    adjusted = np.clip(adjusted, 0.0, 1.0)
    out = np.empty(m, dtype=float)
    out[order] = adjusted
    return [float(v) for v in out]


def mahalanobis_scores(
    points: np.ndarray, mean: np.ndarray, precision: np.ndarray
) -> np.ndarray:
    """Squared Mahalanobis distance of each row of ``points``."""
    centred = points - mean
    return np.einsum("ij,jk,ik->i", centred, precision, centred)


def empirical_quantile_threshold(scores: np.ndarray, target_fpr: float) -> float:
    """Threshold at the ``1 - target_fpr`` quantile of reference scores.

    This is what gives an OOD threshold a stated meaning: "flags at most
    ``target_fpr`` of reference-distribution samples", rather than "0.85,
    because that looked about right".
    """
    if scores.size == 0:
        return float("inf")
    return float(np.quantile(scores, 1.0 - target_fpr, method="higher"))


def empirical_pvalue(score: float, reference: np.ndarray) -> float:
    """Fraction of reference scores at least as extreme, with a +1 correction.

    The ``(count + 1) / (n + 1)`` form keeps the p-value strictly positive: with
    ``n`` reference points we cannot honestly claim evidence finer than
    ``1 / (n + 1)``.
    """
    if reference.size == 0:
        return 1.0
    count = int(np.count_nonzero(reference >= score))
    return (count + 1) / (reference.size + 1)


def distance_weighted_disagreement(
    distances: np.ndarray, neighbour_labels: Sequence[str], own_label: str
) -> float:
    """Neighbourhood label disagreement, weighted by proximity.

    Model-free label-noise screening in the Edited-Nearest-Neighbour tradition
    (Wilson 1972): a sample whose neighbourhood consistently carries a different
    label is more likely mislabelled than a sample sitting inside its own class.
    Distance weighting (``1 / (d + eps)``) means a close neighbour with a
    different label counts for more than a far one, which matters at class
    boundaries where unweighted voting is nearly a coin flip.

    Returns a value in ``[0, 1]``; 0 means every weighted neighbour agrees.
    """
    if len(neighbour_labels) == 0:
        return 0.0
    weights = 1.0 / (np.asarray(distances, dtype=float) + 1e-6)
    total = float(weights.sum())
    if total <= 0:
        return 0.0
    agreeing = float(
        sum(w for w, label in zip(weights, neighbour_labels) if label == own_label)
    )
    return max(0.0, min(1.0, 1.0 - agreeing / total))
