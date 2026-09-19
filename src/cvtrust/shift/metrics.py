"""Distribution-shift metrics: a small, justified set, each with a sample floor.

Why these five and not fifteen
------------------------------
Adding detectors is the cheapest way to make a tool look thorough and the
fastest way to make it useless: every extra metric is another number an analyst
must learn to ignore, and metrics that measure the same thing manufacture the
appearance of independent corroboration.  So this module implements **five**
methods, each answering a question none of the others answers, and documents
what was rejected and why (``docs/research.md`` §24–30).

============================  ==================================================
method                        the question it answers
============================  ==================================================
``energy_distance``           Did the joint feature distribution move at all?
                              Multivariate, parameter-free, permutation-tested.
``mean_shift``                *Where* did it move, and in which view of the
                              image?  This is the characterisation, not a test.
``covariance_shift``          Did the population's *spread* change, with the
                              centre held fixed?  A sensor whose noise floor
                              rose moves this and not the mean.
``marginal_psi``              Which named physical quantity moved?  Reported in
                              units an analyst can check against the imagery.
``categorical_js``            Did the class mix, or a categorical acquisition
                              attribute, change?
============================  ==================================================

The sample floor is the point
-----------------------------
A shift metric that reports "major shift" from three current samples against a
five-thousand-sample reference is worse than no metric: it is a confident number
with no support, and an analyst who acts on it once will discount the tool
forever.  Every function here therefore returns a :class:`MetricResult` whose
``status`` is one of ``ASSESSED`` / ``INSUFFICIENT_SAMPLE`` / ``NOT_ASSESSED``,
carries the requirement it checked and the value it got, and **never** reports a
statistic as a conclusion when the requirement was not met.

Determinism
-----------
Every randomised step (subsampling, permutation) draws from a
:class:`numpy.random.Generator` supplied by the caller, which the pipeline
derives from the run seed.  Nothing here touches global RNG state, so two runs
with the same seed produce the same p-value.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

METRIC_VERSION = "1.0"

#: Below this a permutation p-value cannot be resolved: with ``B``
#: permutations the smallest attainable value is ``1 / (B + 1)``.
_MIN_PERMUTATIONS = 99


class MetricStatus(str, Enum):
    """Whether a metric actually produced a usable answer.

    ``INSUFFICIENT_SAMPLE`` and ``NOT_ASSESSED`` are kept apart deliberately:
    the first means "this method is applicable here and there is not enough
    data", whose remedy is more data; the second means "this method could not
    be applied at all", whose remedy is a different input.  Collapsing them
    sends the analyst after the wrong thing.
    """

    ASSESSED = "ASSESSED"
    INSUFFICIENT_SAMPLE = "INSUFFICIENT_SAMPLE"
    NOT_ASSESSED = "NOT_ASSESSED"


class MetricResult(BaseModel):
    """One metric's answer, with everything needed to disbelieve it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str
    version: str = METRIC_VERSION
    status: MetricStatus
    #: The metric's own statistic.  ``None`` whenever ``status`` is not
    #: ``ASSESSED`` — a statistic without support is not reported as a number.
    statistic: float | None = None
    p_value: float | None = None
    #: Whether the metric's own decision rule fired.  ``None`` when the metric
    #: has no decision rule (``mean_shift`` characterises, it does not decide).
    significant: bool | None = None
    interpretation: str
    #: What the method required and what it was given, so the sample-sufficiency
    #: decision is auditable rather than asserted.
    requirement: dict[str, Any] = Field(default_factory=dict)
    observation: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None

    def assessed(self) -> bool:
        return self.status is MetricStatus.ASSESSED

    def fired(self) -> bool:
        """Assessed *and* its own decision rule said yes."""
        return self.status is MetricStatus.ASSESSED and bool(self.significant)


def _insufficient(
    metric: str, requirement: dict[str, Any], reason: str
) -> MetricResult:
    return MetricResult(
        metric=metric,
        status=MetricStatus.INSUFFICIENT_SAMPLE,
        interpretation=(
            "Not enough data to support a claim either way. This is not a "
            "statement that the distribution is stable."
        ),
        requirement=requirement,
        reason=reason,
    )


def _not_assessed(metric: str, reason: str, **requirement: Any) -> MetricResult:
    return MetricResult(
        metric=metric,
        status=MetricStatus.NOT_ASSESSED,
        interpretation=(
            "This method could not be applied to the inputs supplied. Absence "
            "of a result is not a clean result."
        ),
        requirement=requirement,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# 1. Energy distance, permutation-tested — the multivariate omnibus test
# ---------------------------------------------------------------------------


def _pairwise(points: np.ndarray) -> np.ndarray:
    """Euclidean distance matrix, computed stably.

    The ``|x|^2 + |y|^2 - 2x.y`` expansion is fast and, on L2-normalised
    vectors where the two terms nearly cancel, can go slightly negative from
    rounding; the clip keeps ``sqrt`` real without changing any distance that
    was ever meaningfully positive.
    """
    square = np.einsum("ij,ij->i", points, points)
    gram = points @ points.T
    squared = square[:, None] + square[None, :] - 2.0 * gram
    np.maximum(squared, 0.0, out=squared)
    return np.sqrt(squared)


def _energy_statistic(distances: np.ndarray, mask: np.ndarray) -> float:
    """``(nm/(n+m)) * (2 E|X-Y| - E|X-X'| - E|Y-Y'|)`` from a pooled matrix.

    Computed from a precomputed pooled distance matrix and a boolean mask, so a
    permutation costs two index selections rather than a re-computation of
    hundreds of thousands of distances.
    """
    n = int(mask.sum())
    m = int(mask.size - n)
    if n < 2 or m < 2:
        return float("nan")
    a = distances[np.ix_(mask, mask)]
    b = distances[np.ix_(~mask, ~mask)]
    cross = distances[np.ix_(mask, ~mask)]
    # Within-group means exclude the zero diagonal: including n self-distances
    # of zero biases the within-group term downward by a factor of (n-1)/n,
    # which inflates the statistic on small samples — exactly where we can least
    # afford an optimistic bias.
    within_a = a.sum() / (n * (n - 1))
    within_b = b.sum() / (m * (m - 1))
    between = cross.mean()
    return float((n * m / (n + m)) * (2.0 * between - within_a - within_b))


def energy_distance_test(
    reference: np.ndarray,
    current: np.ndarray,
    *,
    rng: np.random.Generator,
    permutations: int = 999,
    alpha: float = 0.01,
    min_per_side: int = 20,
    max_per_side: int = 400,
) -> MetricResult:
    """Two-sample energy test (Székely & Rizzo) with a permutation null.

    Chosen as the *primary* shift test for three reasons that matter in an
    air-gapped assurance tool:

    * it is **consistent against all alternatives** — a change in spread,
      shape or modality with the mean held fixed is still detected, which a
      mean-comparison test is blind to;
    * it is **parameter-free**.  Maximum Mean Discrepancy with a Gaussian
      kernel is the same family (Sejdinovic et al. 2013 showed energy distance
      is MMD for a particular kernel) but adds a bandwidth, and a bandwidth
      chosen without tuning data is an unaccountable knob in a system whose
      whole claim is that its thresholds have stated meanings;
    * its p-value comes from a **permutation null**, which is valid at small
      sample sizes without any distributional assumption.

    What it cannot do, stated rather than discovered later: a permutation test
    stays *valid* as the current sample shrinks but loses *power*, so a
    non-significant result from a small current population says nothing at all.
    That is why ``min_per_side`` exists and why falling below it yields
    ``INSUFFICIENT_SAMPLE`` rather than a comfortable "no shift detected".
    """
    metric = "energy_distance"
    requirement = {
        "min_samples_per_side": min_per_side,
        "reference_samples": int(reference.shape[0]),
        "current_samples": int(current.shape[0]),
        "permutations": permutations,
    }
    if reference.ndim != 2 or current.ndim != 2 or reference.shape[1] != current.shape[1]:
        return _not_assessed(
            metric,
            "reference and current feature matrices do not share a dimension; "
            "the two populations were not embedded in the same feature space",
            **requirement,
        )
    if permutations < _MIN_PERMUTATIONS:
        return _not_assessed(
            metric,
            f"permutations={permutations} cannot resolve a p-value finer than "
            f"{1 / (permutations + 1):.3g}; at least {_MIN_PERMUTATIONS} are required",
            **requirement,
        )
    if reference.shape[0] < min_per_side or current.shape[0] < min_per_side:
        return _insufficient(
            metric,
            requirement,
            f"a permutation energy test needs at least {min_per_side} samples on "
            f"each side to have any power; reference has {reference.shape[0]} and "
            f"current has {current.shape[0]}. The test would remain valid and "
            "would detect nothing, which is not the same as finding nothing",
        )

    ref_sub, ref_taken = _subsample(reference, max_per_side, rng)
    cur_sub, cur_taken = _subsample(current, max_per_side, rng)
    pooled = np.vstack([ref_sub, cur_sub])
    distances = _pairwise(pooled)

    n = ref_sub.shape[0]
    total = pooled.shape[0]
    observed_mask = np.zeros(total, dtype=bool)
    observed_mask[:n] = True
    observed = _energy_statistic(distances, observed_mask)

    null = np.empty(permutations, dtype=float)
    for index in range(permutations):
        order = rng.permutation(total)
        mask = np.zeros(total, dtype=bool)
        mask[order[:n]] = True
        null[index] = _energy_statistic(distances, mask)

    # (count + 1) / (B + 1): with B permutations we cannot honestly claim
    # evidence finer than 1/(B+1), and the +1 keeps the p-value strictly
    # positive and the test exact.
    p_value = float((np.count_nonzero(null >= observed) + 1) / (permutations + 1))
    significant = p_value <= alpha

    # A normalised effect size: the observed statistic expressed in units of the
    # null's own spread. Reported because a p-value at n=400 says "detectable",
    # not "large", and an analyst needs to tell a meaningful move from a
    # technically-significant one.
    null_sd = float(null.std(ddof=1)) if permutations > 1 else 0.0
    effect = float((observed - null.mean()) / null_sd) if null_sd > 1e-12 else None

    return MetricResult(
        metric=metric,
        status=MetricStatus.ASSESSED,
        statistic=round(float(observed), 6),
        p_value=round(p_value, 6),
        significant=bool(significant),
        interpretation=(
            f"The current population differs from the reference population in the "
            f"joint feature distribution (permutation p = {p_value:.4g} "
            f"<= alpha {alpha:g})."
            if significant
            else f"No joint-distribution difference was resolved at alpha {alpha:g} "
            f"(permutation p = {p_value:.4g}). This bounds the shift the test "
            f"could see at this sample size; it does not establish stability."
        ),
        requirement=requirement,
        observation={
            "statistic": round(float(observed), 6),
            "null_mean": round(float(null.mean()), 6),
            "null_sd": round(null_sd, 6),
            "effect_size_null_sd": None if effect is None else round(effect, 4),
            "p_value": round(p_value, 6),
            "alpha": alpha,
            "permutations": permutations,
            "p_value_resolution": round(1.0 / (permutations + 1), 8),
            "reference_used": ref_taken,
            "current_used": cur_taken,
            "reference_available": int(reference.shape[0]),
            "current_available": int(current.shape[0]),
            "dimension": int(reference.shape[1]),
        },
    )


def _subsample(
    points: np.ndarray, cap: int, rng: np.random.Generator
) -> tuple[np.ndarray, int]:
    """Deterministically cap a population, recording how many were used.

    The energy test needs a pooled pairwise distance matrix, which is quadratic;
    a five-thousand-sample reference would cost 25 million distances per
    permutation-free pass and far more across the null.  Capping is a cost
    decision and is *reported* as one — the observation carries both the number
    used and the number available, so nobody reads a capped run as a full one.
    """
    if points.shape[0] <= cap:
        return points, int(points.shape[0])
    index = rng.choice(points.shape[0], size=cap, replace=False)
    index.sort()
    return points[index], int(cap)


# ---------------------------------------------------------------------------
# 2. Mean / location shift, attributed to feature blocks
# ---------------------------------------------------------------------------


def mean_shift(
    reference: np.ndarray,
    current: np.ndarray,
    *,
    blocks: Sequence[tuple[str, int, int]] = (),
    min_per_side: int = 8,
) -> MetricResult:
    """Displacement of the population centre, normalised and attributed.

    This is deliberately **not** a hypothesis test, and it carries
    ``significant=None`` to say so.  Its job is characterisation: a p-value
    tells an analyst that something moved, and this tells them *what* — how far
    the centre travelled relative to the reference's own spread, and which view
    of the image the movement lives in.

    The normalisation is the displacement divided by the reference's mean
    per-dimension standard deviation, so the number is comparable across
    feature spaces of different scale.  The block attribution is the share of
    the squared displacement falling in each block, which is what makes
    "the movement is in colour and acquisition" — an illumination or sensor
    story — distinguishable from "the movement is in structure and gradient" —
    a content or terrain story.

    That attribution is a **heuristic reading of a feature space**, not a
    calibrated inference, and every finding built on it says so.
    """
    metric = "mean_shift"
    requirement = {
        "min_samples_per_side": min_per_side,
        "reference_samples": int(reference.shape[0]),
        "current_samples": int(current.shape[0]),
    }
    if reference.shape[0] < min_per_side or current.shape[0] < min_per_side:
        return _insufficient(
            metric,
            requirement,
            f"a population centre estimated from fewer than {min_per_side} samples "
            "is dominated by sampling noise",
        )

    ref_mean = reference.mean(axis=0)
    cur_mean = current.mean(axis=0)
    delta = cur_mean - ref_mean
    displacement = float(np.linalg.norm(delta))
    scale = float(np.mean(reference.std(axis=0, ddof=1)))
    normalised = displacement / scale if scale > 1e-12 else None

    contributions: dict[str, dict[str, float]] = {}
    squared = delta**2
    total = float(squared.sum())
    for name, start, end in blocks:
        block_energy = float(squared[start:end].sum())
        contributions[name] = {
            "share_of_squared_displacement": round(
                block_energy / total if total > 1e-24 else 0.0, 4
            ),
            "displacement": round(float(np.sqrt(block_energy)), 6),
        }

    dominant = (
        max(contributions, key=lambda k: contributions[k]["share_of_squared_displacement"])
        if contributions
        else None
    )
    return MetricResult(
        metric=metric,
        status=MetricStatus.ASSESSED,
        statistic=round(displacement, 6),
        significant=None,
        interpretation=(
            f"The population centre moved {displacement:.4g} in feature space"
            + (
                f" ({normalised:.2f} reference standard deviations)"
                if normalised is not None
                else ""
            )
            + (
                f", predominantly in the '{dominant}' view "
                f"({contributions[dominant]['share_of_squared_displacement']:.0%} of "
                "the squared displacement)."
                if dominant
                else "."
            )
            + " Magnitude and direction only: this metric makes no claim about "
            "whether the movement is significant or what caused it."
        ),
        requirement=requirement,
        observation={
            "displacement": round(displacement, 6),
            "displacement_in_reference_sd": (
                None if normalised is None else round(normalised, 4)
            ),
            "reference_mean_sd": round(scale, 6),
            "block_contributions": contributions,
            "dominant_block": dominant,
        },
    )


# ---------------------------------------------------------------------------
# 3. Covariance / spread shift
# ---------------------------------------------------------------------------


def covariance_shift(
    reference: np.ndarray,
    current: np.ndarray,
    *,
    rng: np.random.Generator,
    components: int = 8,
    samples_per_component: int = 5,
    permutations: int = 199,
    alpha: float = 0.01,
) -> MetricResult:
    """Change in the population's *spread*, with the centre removed.

    A mean comparison is blind to a population that occupies the same centre
    over a different volume — a sensor whose noise floor rose, a collection
    protocol that became more heterogeneous, a class that acquired a second
    mode.  The statistic is the log ratio of generalised variances,
    ``log det(Sigma_current) - log det(Sigma_reference)``, in a reference-fitted
    principal subspace.

    Two things about how it is computed were **forced by measurement**, and
    both are the same lesson Module 1 learned about its OOD thresholds
    (``docs/research.md`` §"Measured corrections" item 2):

    **The basis is cross-fitted.**  A basis fitted on the whole reference is, by
    construction, the set of directions in which *that sample* varies most, so
    the reference's own projected variance is optimistic and every current
    population looks contracted.  Measured on two independently generated clean
    corpora, the in-sample form gave a log-det ratio of **-2.35** — a confident
    report of a large contraction between two populations drawn from the same
    process.  Splitting the reference, fitting the basis on one half and
    comparing the *other* half against the current population took the same
    measurement to **+0.56**.  The basis is still fitted on reference data only,
    so the current population never defines the directions used to judge it.

    **The threshold is a permutation null, not a constant.**  Even cross-fitted,
    +0.56 on a clean pair would have crossed the 0.5 operating point this
    function originally carried.  There is no principled constant here: the
    sampling distribution of a log-det ratio depends on the sample sizes, the
    dimension and the covariance structure, none of which are fixed.  So the
    null is generated by permuting the pooled projected points between the two
    group sizes, which is cheap because the projection is already low
    dimensional, and the decision rule is a p-value at the same ``alpha`` the
    omnibus test uses.
    """
    metric = "covariance_shift"
    needed = components * samples_per_component
    # Twice, because half the reference is spent fitting the basis.
    reference_needed = 2 * needed
    requirement = {
        "components": components,
        "samples_per_component": samples_per_component,
        "min_reference_samples": reference_needed,
        "min_current_samples": needed,
        "reference_samples": int(reference.shape[0]),
        "current_samples": int(current.shape[0]),
        "alpha": alpha,
        "permutations": permutations,
        "threshold_basis": "permutation null over the pooled projected points; "
        "no constant operating point is used",
        "basis_fitting": "cross-fitted: the principal basis is fitted on one half "
        "of the reference and both compared populations are held out of it",
    }
    if reference.shape[1] < components:
        return _not_assessed(
            metric,
            f"feature space has {reference.shape[1]} dimensions, fewer than the "
            f"{components} principal components requested",
            **requirement,
        )
    if permutations < _MIN_PERMUTATIONS:
        return _not_assessed(
            metric,
            f"permutations={permutations} cannot resolve a p-value finer than "
            f"{1 / (permutations + 1):.3g}",
            **requirement,
        )
    if reference.shape[0] < reference_needed or current.shape[0] < needed:
        return _insufficient(
            metric,
            requirement,
            f"a cross-fitted {components}-dimensional covariance needs at least "
            f"{reference_needed} reference samples (half are spent fitting the "
            f"basis) and {needed} current samples; reference has "
            f"{reference.shape[0]} and current has {current.shape[0]}",
        )

    order = rng.permutation(reference.shape[0])
    half = reference.shape[0] // 2
    fit_rows, held_rows = order[:half], order[half:]
    basis, centre = _fit_principal_basis(reference[fit_rows], components)
    held = (reference[held_rows] - centre) @ basis
    projected_current = (current - centre) @ basis

    observed = _log_det_ratio(held, projected_current)
    if observed is None:
        return _not_assessed(
            metric,
            "a projected covariance is singular, so the generalised variance is "
            "undefined; this usually means a population spans fewer directions "
            "than the number of components, which exact duplicates can cause",
            **requirement,
        )

    pooled = np.vstack([held, projected_current])
    n_held = held.shape[0]
    null = np.empty(permutations, dtype=float)
    drawn = 0
    for _ in range(permutations):
        shuffled = rng.permutation(pooled.shape[0])
        value = _log_det_ratio(
            pooled[shuffled[:n_held]], pooled[shuffled[n_held:]]
        )
        if value is None:  # pragma: no cover - degenerate permutation
            continue
        null[drawn] = abs(value)
        drawn += 1
    if drawn < _MIN_PERMUTATIONS:  # pragma: no cover - degenerate population
        return _not_assessed(
            metric,
            "too many permutations produced a singular covariance to form a null "
            "distribution",
            **requirement,
        )
    null = null[:drawn]
    p_value = float((np.count_nonzero(null >= abs(observed)) + 1) / (drawn + 1))
    significant = p_value <= alpha

    direction = "expanded" if observed > 0 else "contracted"
    return MetricResult(
        metric=metric,
        status=MetricStatus.ASSESSED,
        statistic=round(float(observed), 6),
        p_value=round(p_value, 6),
        significant=bool(significant),
        interpretation=(
            f"The population's spread {direction}: the generalised variance of "
            f"the current population is {np.exp(observed):.3g} times the "
            f"reference's over {components} cross-fitted principal directions "
            + (
                f"(permutation p = {p_value:.4g} <= alpha {alpha:g})."
                if significant
                else f"(permutation p = {p_value:.4g}, not resolved at alpha "
                f"{alpha:g}; a ratio of this size is within what resampling the "
                "same two populations produces)."
            )
        ),
        requirement=requirement,
        observation={
            "log_det_ratio": round(float(observed), 6),
            "generalised_variance_ratio": round(float(np.exp(observed)), 6),
            "p_value": round(p_value, 6),
            "null_median_abs": round(float(np.median(null)), 6),
            "null_p95_abs": round(float(np.quantile(null, 0.95)), 6),
            "permutations_used": drawn,
            "p_value_resolution": round(1.0 / (drawn + 1), 8),
            "components": components,
            "reference_held_out": int(n_held),
            "reference_used_for_basis": int(half),
            "explained_variance_ratio": round(
                float(_explained(reference[fit_rows], basis, centre)), 4
            ),
        },
    )


def _log_det_ratio(left: np.ndarray, right: np.ndarray) -> float | None:
    """``log det cov(right) - log det cov(left)``, or ``None`` if singular."""
    if left.shape[0] <= left.shape[1] or right.shape[0] <= right.shape[1]:
        return None
    left_sign, left_logdet = np.linalg.slogdet(np.cov(left, rowvar=False))
    right_sign, right_logdet = np.linalg.slogdet(np.cov(right, rowvar=False))
    if left_sign <= 0 or right_sign <= 0:
        return None
    return float(right_logdet - left_logdet)


def _fit_principal_basis(
    reference: np.ndarray, components: int
) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic PCA basis fitted on the reference population only.

    Eigenvector signs are arbitrary but irrelevant here: every quantity computed
    in this basis (covariance determinant, correlation norm) is invariant to a
    per-axis sign flip.  ``eigh`` on a symmetric matrix is deterministic for a
    given input on a given LAPACK build.
    """
    mean = reference.mean(axis=0)
    centred = reference - mean
    covariance = np.cov(centred, rowvar=False)
    eigenvalues, eigenvectors = np.linalg.eigh(covariance)
    order = np.argsort(eigenvalues)[::-1][:components]
    return eigenvectors[:, order], mean


def _explained(reference: np.ndarray, basis: np.ndarray, mean: np.ndarray) -> float:
    centred = reference - mean
    total = float((centred**2).sum())
    kept = float(((centred @ basis) ** 2).sum())
    return kept / total if total > 1e-24 else 0.0


# ---------------------------------------------------------------------------
# 4. Marginal shift on named physical quantities
# ---------------------------------------------------------------------------

#: The conventional PSI reading bands, kept for **interpretation only**.
#:
#: These come from credit-risk model-monitoring practice and no published study
#: calibrates them for image acquisition statistics.  They were measured to be
#: unusable as a decision rule at this project's sample sizes: splitting a clean
#: 144-sample reference in half and taking the largest PSI across the 23 named
#: quantities gives a **mean of 0.49 and a 95th percentile of 0.65**, both far
#: above the 0.25 "major shift" band.  A fixed band would therefore have fired
#: on every clean pair the system ever saw.
#:
#: The band is still reported, because practitioners read PSI in these terms and
#: removing it would make the number harder to interpret, not easier.  It is a
#: label attached to the value; the decision comes from the permutation null.
PSI_BANDS: tuple[tuple[float, str], ...] = (
    (0.10, "no material shift"),
    (0.25, "moderate shift"),
    (float("inf"), "major shift"),
)


def population_stability_index(
    reference: np.ndarray,
    current: np.ndarray,
    *,
    bins: int = 10,
) -> tuple[float, dict[str, Any]]:
    """PSI between two 1-D samples, binned on **reference** quantiles.

    ``PSI = sum (c_i - r_i) * ln(c_i / r_i)`` over bin proportions.

    Quantile binning on the reference (rather than equal-width binning on the
    pooled range) keeps the metric from being dominated by one outlier
    stretching the range: it gives roughly equal reference mass per bin, which
    is the condition under which the ratio ``c_i / r_i`` is stable.

    Empty bins are the metric's well-known failure mode — ``ln(0)`` is why PSI
    is so often reported as infinite in practice.  Proportions are floored at
    ``1 / (2n)``, half of one observation, which is the conventional continuity
    correction, and the floor is recorded rather than hidden inside the number.
    """
    edges = np.quantile(reference, np.linspace(0.0, 1.0, bins + 1))
    # Collapse duplicate edges: a quantity that is constant over most of the
    # reference (a fixed JPEG quality, a saturated channel) produces repeated
    # edges, and np.histogram would then create zero-width bins.
    edges = np.unique(edges)
    if edges.size < 3:
        return float("nan"), {"usable_bins": int(edges.size) - 1}
    edges = edges.copy()
    edges[0], edges[-1] = -np.inf, np.inf

    ref_counts, _ = np.histogram(reference, bins=edges)
    cur_counts, _ = np.histogram(current, bins=edges)
    ref_floor = 1.0 / (2.0 * reference.size)
    cur_floor = 1.0 / (2.0 * current.size)
    ref_p = np.maximum(ref_counts / reference.size, ref_floor)
    cur_p = np.maximum(cur_counts / current.size, cur_floor)
    value = float(np.sum((cur_p - ref_p) * np.log(cur_p / ref_p)))
    return value, {
        "usable_bins": int(edges.size) - 1,
        "reference_counts": [int(c) for c in ref_counts],
        "current_counts": [int(c) for c in cur_counts],
        "empty_current_bins": int(np.count_nonzero(cur_counts == 0)),
        "proportion_floor_reference": round(ref_floor, 8),
        "proportion_floor_current": round(cur_floor, 8),
    }


def marginal_psi(
    reference: np.ndarray,
    current: np.ndarray,
    *,
    names: Sequence[str],
    rng: np.random.Generator,
    bins: int = 10,
    min_per_bin: int = 5,
    permutations: int = 199,
    max_permutations: int = 4999,
    alpha: float = 0.01,
    reporting_band: float = 0.25,
) -> MetricResult:
    """PSI per named physical quantity, permutation-tested and BH-corrected.

    Applied to the **un-normalised acquisition statistics** — mean luminance,
    noise floor, focus, saturation, entropy, edge density — because those are
    quantities an analyst can go and check against the imagery.  Running PSI
    across all 614 embedding coordinates instead would be a multiplicity
    disaster dressed up as thoroughness.

    Two corrections, both measured rather than assumed:

    **The decision is a permutation p-value, not a PSI band.**  See
    :data:`PSI_BANDS`: at these sample sizes the conventional 0.25 band fires on
    a clean reference split in half, so using it as a rule would have made every
    clean run report a major marginal shift.  The null is built by permuting the
    pooled samples between the two group sizes and recomputing the same
    statistic, so it absorbs the sample size, the binning and the quantity's own
    distribution.

    **The 23 tests are multiplicity-corrected.**  Twenty-three marginals at a 1%
    rate would give roughly one "significant" quantity per clean run by chance.
    Benjamini-Hochberg across the quantities controls the false discovery rate,
    which is the relevant error notion: what matters is the fraction of reported
    marginals that are wrong, not whether any single one could be.

    **The permutation budget is scaled to the multiplicity**, which a first
    revision of this function got wrong in a way no threshold review would have
    caught.  With ``B`` permutations the finest attainable p-value is
    ``1/(B+1)``, and Benjamini-Hochberg multiplies the smallest one by the
    number of tests.  At ``B = 199`` and 23 quantities, the best achievable
    q-value is ``0.005 x 23 = 0.115`` — so **no marginal could ever be
    significant at alpha = 0.01, however large its shift**.  Measured: a
    quantity displaced by four standard deviations, PSI 5.31, reported not
    significant.  The budget is therefore raised to ``ceil(m/alpha)`` before the
    null is drawn, and if ``max_permutations`` caps it below that, the result
    says in ``observation`` that significance was not resolvable rather than
    reporting a quiet "no".
    """
    metric = "marginal_psi"
    needed = bins * min_per_bin
    requirement = {
        "bins": bins,
        "min_samples_per_bin": min_per_bin,
        "min_samples_per_side": needed,
        "reference_samples": int(reference.shape[0]),
        "current_samples": int(current.shape[0]),
        "alpha": alpha,
        "permutations": permutations,
        "multiple_testing": "Benjamini-Hochberg across the named quantities",
        "threshold_basis": "permutation null per quantity; the PSI band is "
        "reported as interpretation and is NOT the decision rule",
        "quantities_tested": len(names),
    }
    if reference.size == 0 or current.size == 0 or not names:
        return _not_assessed(
            metric,
            "the feature extractor exposed no named physical acquisition "
            "statistics, so there is no interpretable marginal to test",
            **requirement,
        )
    if permutations < _MIN_PERMUTATIONS:
        return _not_assessed(
            metric,
            f"permutations={permutations} cannot resolve a p-value finer than "
            f"{1 / (permutations + 1):.3g}",
            **requirement,
        )
    if reference.shape[0] < needed or current.shape[0] < needed:
        return _insufficient(
            metric,
            requirement,
            f"PSI with {bins} bins needs at least {needed} samples per side for "
            f"roughly {min_per_bin} per bin; reference has {reference.shape[0]} "
            f"and current has {current.shape[0]}. Below that the ratio in a "
            "sparse bin is noise amplified by a logarithm",
        )

    # Scale the budget to the multiplicity BEFORE drawing the null. See the
    # docstring: at 199 permutations and 23 quantities the smallest achievable
    # BH-adjusted q is 0.115, so alpha = 0.01 is unreachable by construction.
    required = int(np.ceil(len(names) / alpha)) - 1
    effective = int(min(max(permutations, required), max_permutations))
    resolvable = (len(names) / (effective + 1)) <= alpha
    requirement = {
        **requirement,
        "permutations_requested": permutations,
        "permutations_used": effective,
        "permutations_required_for_alpha": required,
        "max_permutations": max_permutations,
        "significance_resolvable_after_correction": resolvable,
    }
    permutations = effective

    n_reference = reference.shape[0]
    pooled = np.vstack([reference, current])
    total = pooled.shape[0]
    # One permutation ordering shared across all quantities, so the joint
    # structure of the acquisition statistics is preserved in the null: the
    # quantities are correlated (luminance percentiles especially), and
    # permuting each independently would build a null for a population that
    # does not exist.
    orders = [rng.permutation(total) for _ in range(permutations)]

    per_quantity: dict[str, dict[str, Any]] = {}
    tested: list[str] = []
    p_values: list[float] = []
    for column, name in enumerate(names):
        ref_column = reference[:, column]
        cur_column = current[:, column]
        value, detail = population_stability_index(ref_column, cur_column, bins=bins)
        if not np.isfinite(value):
            per_quantity[name] = {
                "psi": None,
                "band": "NOT_ASSESSED",
                "reason": "the reference distribution of this quantity is "
                "effectively constant, so quantile bins collapse",
                **detail,
            }
            continue
        pooled_column = pooled[:, column]
        null = np.empty(permutations, dtype=float)
        usable = 0
        for order in orders:
            left = pooled_column[order[:n_reference]]
            right = pooled_column[order[n_reference:]]
            candidate, _ = population_stability_index(left, right, bins=bins)
            if np.isfinite(candidate):
                null[usable] = candidate
                usable += 1
        if usable < _MIN_PERMUTATIONS:  # pragma: no cover - degenerate quantity
            per_quantity[name] = {
                "psi": round(value, 6),
                "band": "NOT_ASSESSED",
                "reason": "too many permutations produced collapsed bins to form "
                "a null distribution",
                **detail,
            }
            continue
        null = null[:usable]
        p_value = float((np.count_nonzero(null >= value) + 1) / (usable + 1))
        tested.append(name)
        p_values.append(p_value)
        per_quantity[name] = {
            "psi": round(value, 6),
            "band": _psi_band(value),
            "p_value": round(p_value, 6),
            "null_median": round(float(np.median(null)), 6),
            "null_p95": round(float(np.quantile(null, 0.95)), 6),
            "permutations_used": usable,
            "reference_mean": round(float(ref_column.mean()), 6),
            "current_mean": round(float(cur_column.mean()), 6),
            "relative_mean_change": (
                round(
                    float(
                        (cur_column.mean() - ref_column.mean())
                        / abs(ref_column.mean())
                    ),
                    4,
                )
                if abs(float(ref_column.mean())) > 1e-12
                else None
            ),
            **detail,
        }

    if not tested:
        return _not_assessed(
            metric,
            "every named quantity was effectively constant in the reference "
            "population, so no PSI could be computed",
            **requirement,
        )

    from ..risk.statistics import benjamini_hochberg

    q_values = benjamini_hochberg(p_values)
    for name, q_value in zip(tested, q_values):
        per_quantity[name]["q_value"] = round(float(q_value), 6)

    exceeded = sorted(name for name, q in zip(tested, q_values) if q <= alpha)
    scored = {k: v for k, v in per_quantity.items() if v.get("psi") is not None}
    worst_name = max(scored, key=lambda k: scored[k]["psi"])
    worst = float(scored[worst_name]["psi"])
    best_q = min(q_values) if q_values else 1.0

    return MetricResult(
        metric=metric,
        status=MetricStatus.ASSESSED,
        statistic=round(worst, 6),
        p_value=round(float(best_q), 6),
        significant=bool(exceeded),
        interpretation=(
            f"{len(exceeded)} of {len(tested)} named acquisition quantities moved "
            f"beyond what resampling these two populations produces "
            f"({', '.join(exceeded)}), at a Benjamini-Hochberg-adjusted "
            f"q <= {alpha:g}. The largest PSI is '{worst_name}' at {worst:.3f} "
            f"({_psi_band(worst)})."
            if exceeded
            else (
                f"Significance could NOT be resolved: {effective} permutations "
                f"over {len(tested)} quantities cannot produce a "
                f"Benjamini-Hochberg-adjusted q below alpha {alpha:g}. The "
                f"largest PSI is '{worst_name}' at {worst:.3f} "
                f"({_psi_band(worst)}); this is not a finding of stability."
                if not resolvable
                else f"No named acquisition quantity moved beyond what resampling "
                f"these two populations produces (smallest adjusted q = "
                f"{best_q:.3g} against alpha {alpha:g}). The largest PSI is "
                f"'{worst_name}' at {worst:.3f} ({_psi_band(worst)}), which the "
                "conventional band would call a "
                f"'{_psi_band(worst)}' and the null says is ordinary at this "
                "sample size."
            )
        ),
        requirement=requirement,
        observation={
            "max_psi": round(worst, 6),
            "max_psi_quantity": worst_name,
            "min_q_value": round(float(best_q), 6),
            "exceeded": exceeded,
            "quantities": per_quantity,
            "reporting_bands": {str(limit): label for limit, label in PSI_BANDS},
            "reporting_band_note": "the PSI bands are credit-risk monitoring "
            "folklore and were MEASURED to fire on a clean reference split in "
            "half at these sample sizes. They label the value; they do not "
            "decide anything.",
            "reporting_band_threshold": reporting_band,
            "permutations_used": effective,
            "significance_resolvable_after_correction": resolvable,
            "smallest_achievable_q": round(len(tested) / (effective + 1), 6),
        },
    )


def _psi_band(value: float) -> str:
    for limit, label in PSI_BANDS:
        if value < limit:
            return label
    return PSI_BANDS[-1][1]  # pragma: no cover - the last band is unbounded


# ---------------------------------------------------------------------------
# 5. Categorical distribution shift - classes and declared metadata
# ---------------------------------------------------------------------------


def jensen_shannon_divergence(p: np.ndarray, q: np.ndarray) -> float:
    """JSD in bits: symmetric, bounded in ``[0, 1]``, finite on disjoint support.

    Chosen over KL divergence for one decisive reason: a class present in the
    current population and absent from the reference (or the reverse) is the
    *normal* case in a multi-contributor pipeline, and KL is infinite there.  An
    infinite divergence is not a measurement, and a system that reports one has
    stopped being able to rank its own observations.
    """
    p = np.asarray(p, dtype=float)
    q = np.asarray(q, dtype=float)
    p = p / max(p.sum(), 1e-24)
    q = q / max(q.sum(), 1e-24)
    m = 0.5 * (p + q)
    return float(0.5 * _kl(p, m) + 0.5 * _kl(q, m))


def _kl(p: np.ndarray, q: np.ndarray) -> float:
    mask = p > 0
    return float(np.sum(p[mask] * np.log2(p[mask] / q[mask])))


def categorical_shift(
    reference_counts: Mapping[str, int],
    current_counts: Mapping[str, int],
    *,
    label: str,
    rng: np.random.Generator,
    min_per_side: int = 20,
    permutations: int = 199,
    alpha: float = 0.01,
) -> MetricResult:
    """Jensen-Shannon divergence between two categorical distributions, tested.

    The divergence alone has no natural operating point — 0.03 bits is a large
    change over two categories and a trivial one over fifty — so the decision
    comes from a permutation test of homogeneity: pool the category labels,
    reassign them to the two group sizes, recompute.  That is an exact test of
    "were these two samples drawn from the same categorical distribution", valid
    at small counts where a chi-square approximation is not.

    Used for the class mix and for categorical acquisition metadata.  The
    metadata case carries a caveat the class case does not, and the caller is
    required to record it: a declared sensor name is a *claim by the
    contributor*, so a metadata distribution that does not move establishes only
    that the claims did not move.
    """
    metric = f"categorical_js.{label}"
    categories = sorted(set(reference_counts) | set(current_counts))
    ref_total = int(sum(reference_counts.values()))
    cur_total = int(sum(current_counts.values()))
    requirement = {
        "min_samples_per_side": min_per_side,
        "reference_samples": ref_total,
        "current_samples": cur_total,
        "alpha": alpha,
        "permutations": permutations,
        "threshold_basis": "permutation test of homogeneity over the pooled "
        "category labels; no constant divergence threshold is used",
        "categories": len(categories),
    }
    if not categories:
        return _not_assessed(
            metric, f"no {label} values were available on either side", **requirement
        )
    if permutations < _MIN_PERMUTATIONS:
        return _not_assessed(
            metric,
            f"permutations={permutations} cannot resolve a p-value finer than "
            f"{1 / (permutations + 1):.3g}",
            **requirement,
        )
    if ref_total < min_per_side or cur_total < min_per_side:
        return _insufficient(
            metric,
            requirement,
            f"a categorical comparison over {len(categories)} categories needs at "
            f"least {min_per_side} observations per side; reference has "
            f"{ref_total} and current has {cur_total}",
        )

    ref_vector = np.array([reference_counts.get(c, 0) for c in categories], dtype=float)
    cur_vector = np.array([current_counts.get(c, 0) for c in categories], dtype=float)
    divergence = jensen_shannon_divergence(ref_vector, cur_vector)

    pooled = np.repeat(np.arange(len(categories)), (ref_vector + cur_vector).astype(int))
    null = np.empty(permutations, dtype=float)
    for index in range(permutations):
        shuffled = rng.permutation(pooled)
        left = np.bincount(shuffled[:ref_total], minlength=len(categories)).astype(float)
        right = np.bincount(shuffled[ref_total:], minlength=len(categories)).astype(float)
        null[index] = jensen_shannon_divergence(left, right)
    p_value = float((np.count_nonzero(null >= divergence) + 1) / (permutations + 1))
    significant = p_value <= alpha

    appeared = [c for c in categories if reference_counts.get(c, 0) == 0]
    vanished = [c for c in categories if current_counts.get(c, 0) == 0]

    return MetricResult(
        metric=metric,
        status=MetricStatus.ASSESSED,
        statistic=round(divergence, 6),
        p_value=round(p_value, 6),
        significant=bool(significant),
        interpretation=(
            f"The {label} distribution moved: Jensen-Shannon divergence "
            f"{divergence:.4f} bits over {len(categories)} categories "
            f"(permutation p = {p_value:.4g} <= alpha {alpha:g})"
            + (f"; new in the current population: {', '.join(appeared)}" if appeared else "")
            + (f"; absent from the current population: {', '.join(vanished)}" if vanished else "")
            + "."
            if significant
            else f"The {label} distribution is consistent with the reference: "
            f"Jensen-Shannon divergence {divergence:.4f} bits over "
            f"{len(categories)} categories (permutation p = {p_value:.4g}, not "
            f"resolved at alpha {alpha:g})."
        ),
        requirement=requirement,
        observation={
            "jensen_shannon_bits": round(divergence, 6),
            "p_value": round(p_value, 6),
            "null_median": round(float(np.median(null)), 6),
            "null_p95": round(float(np.quantile(null, 0.95)), 6),
            "p_value_resolution": round(1.0 / (permutations + 1), 8),
            "categories": categories,
            "reference_proportions": {
                c: round(float(reference_counts.get(c, 0) / max(ref_total, 1)), 6)
                for c in categories
            },
            "current_proportions": {
                c: round(float(current_counts.get(c, 0) / max(cur_total, 1)), 6)
                for c in categories
            },
            "reference_counts": {c: int(reference_counts.get(c, 0)) for c in categories},
            "current_counts": {c: int(current_counts.get(c, 0)) for c in categories},
            "appeared": appeared,
            "vanished": vanished,
        },
    )


__all__ = [
    "METRIC_VERSION", "MetricResult", "MetricStatus", "PSI_BANDS",
    "energy_distance_test", "mean_shift", "covariance_shift",
    "marginal_psi", "population_stability_index",
    "categorical_shift", "jensen_shannon_divergence",
]
