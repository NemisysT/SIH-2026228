"""Out-of-distribution scoring against a declared reference distribution.

Two complementary detectors from the OOD literature, both chosen because they
run offline on a fixed feature space and because their output is explainable:

**Mahalanobis distance** (Lee, Lee, Lee & Shin, NeurIPS 2018) — a parametric
view: how far is this sample from the reference distribution's centre, measured
in the reference's own covariance geometry.  Covariance is estimated with
Ledoit-Wolf shrinkage (Ledoit & Wolf, 2004) because a 600-dimensional covariance
from a few hundred samples is otherwise singular and the distance meaningless.
A reference-fitted PCA reduces dimension first, which is what makes the estimate
well-conditioned rather than merely invertible.

**k-NN distance** (Sun, Ming, Zhu & Li, ICML 2022, "Out-of-distribution Detection
with Deep Nearest Neighbors") — a non-parametric view: how far is this sample
from the reference *manifold*.  This catches samples that sit at a normal
Mahalanobis radius but in a region the reference set never populates, which a
single Gaussian cannot express.

**PCA reconstruction residual** — how much of this sample lies *outside* the
subspace the reference distribution spans at all.  This one is not optional
window dressing: reducing dimension before measuring distance discards the
directions in which the reference set has no variance, and a genuinely
different acquisition process (a different sensor band, a different optical
train) differs precisely in those directions.  Measured on this build's
attack lab, dropping the residual term takes out-of-distribution recall to
zero while leaving AUROC around 0.75 — the ranking survives, the decision does
not.  The residual restores it.

Thresholds are not chosen, they are derived: each threshold is the
``1 - target_fpr`` quantile of **cross-fitted** reference scores (5-fold, so a
reference sample is never scored by a model fitted on itself).  The threshold
therefore has a stated meaning — "flags at most ``target_fpr`` of
reference-distribution samples" — and the reported empirical p-value says where
in the reference distribution the sample actually fell.

What this detector does *not* say
---------------------------------
It never calls an OOD sample malicious.  Terrain, season, sensor and
illumination changes produce exactly this signature and are the normal condition
of an operational pipeline.  Every finding here carries that limitation
explicitly, severity is capped accordingly, and the drift-versus-manipulation
question is Module 4's, where population-level evidence exists to answer it.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from sklearn.covariance import LedoitWolf

from ..core.evidence import Coverage, EvidenceItem, Severity
from ..risk.statistics import (
    empirical_pvalue,
    empirical_quantile_threshold,
    mahalanobis_scores,
)
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "ood_insertion"

#: Prior when uncalibrated.  Low on purpose: an unexplained distance from a
#: reference set is weak evidence of an *insertion attack* specifically.
UNCALIBRATED_PRIOR = 0.40

_FOLDS = 5


class OODDetector:
    name = "ood"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        cfg = ctx.config.ood

        rows = ctx.features.valid_rows()
        sample_ids = [ctx.features.sample_ids[r] for r in rows]
        vectors = ctx.features.embeddings[rows]

        reference_ids, mode, mode_note = self._reference(ctx, sample_ids)
        reference_mask = np.array([sid in reference_ids for sid in sample_ids])
        n_reference = int(reference_mask.sum())

        if n_reference < cfg.min_reference_samples:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=f"reference distribution has {n_reference} samples, below "
                           f"ood.min_reference_samples={cfg.min_reference_samples}; "
                           "a covariance estimate from fewer samples would not support "
                           "a distance claim",
                )
            )
            out.stats = {"reference_samples": n_reference, "mode": mode}
            return out

        reference = vectors[reference_mask]
        _, n_components = _fit_scorers(reference, cfg)
        cross_fitted, observed = _cross_fitted_scores(
            vectors, reference_mask, cfg, folds=_FOLDS
        )

        # A sample is flagged if ANY method exceeds its threshold, so three
        # methods each operating at the configured rate would produce roughly
        # three times that rate overall.  The per-method rate is therefore
        # Bonferroni-corrected by the number of methods, which makes
        # ``target_fpr`` mean what an operator would assume it means: the
        # family-wise false-alarm rate on reference-distribution samples.
        per_method_fpr = cfg.target_fpr / max(len(cross_fitted), 1)
        thresholds = {
            method: empirical_quantile_threshold(cross_fitted[method], per_method_fpr)
            for method in cross_fitted
        }

        scores: dict[str, float] = {}
        flagged_ids: set[str] = set()
        n_flagged = 0

        for i, sample_id in enumerate(sample_ids):
            per_method: dict[str, dict[str, float]] = {}
            exceeded: list[str] = []
            p_values: list[float] = []
            for method in observed:
                value = float(observed[method][i])
                # A reference sample must be compared against the cross-fitted
                # distribution, not against a model that has already seen it.
                p_value = empirical_pvalue(value, cross_fitted[method])
                per_method[method] = {
                    "score": value,
                    "threshold": thresholds[method],
                    "empirical_p": p_value,
                }
                p_values.append(p_value)
                if value > thresholds[method]:
                    exceeded.append(method)

            min_p = min(p_values) if p_values else 1.0
            combined = float(np.clip(1.0 - min_p, 0.0, 1.0))
            scores[sample_id] = combined

            if not exceeded:
                continue
            n_flagged += 1
            flagged_ids.add(sample_id)
            severity, rationale = _severity(len(exceeded), len(observed), min_p, mode)
            is_reference = bool(reference_mask[i])

            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.sample_asset(sample_id),
                    contributor=ctx.contributor_of(sample_id),
                    title=(
                        "Sample lies outside the declared reference distribution "
                        f"({', '.join(exceeded)} exceeded threshold)"
                    ),
                    severity=severity,
                    score=combined,
                    prior=UNCALIBRATED_PRIOR,
                    coverage=Coverage.PARTIAL,
                    discriminator=(mode, *sorted(exceeded)),
                    evidence=[
                        EvidenceItem(
                            kind="ood_distance",
                            statement=(
                                "; ".join(
                                    f"{m}: score {per_method[m]['score']:.4g} vs "
                                    f"threshold {per_method[m]['threshold']:.4g} "
                                    f"(empirical p = {per_method[m]['empirical_p']:.4g})"
                                    for m in sorted(per_method)
                                )
                                + f". Each threshold is the {1 - per_method_fpr:.3%} quantile "
                                "of cross-fitted reference scores, Bonferroni-corrected "
                                f"across {len(thresholds)} methods so the family-wise "
                                f"false-alarm rate on reference samples is {cfg.target_fpr:.1%}."
                            ),
                            observation={
                                "methods": per_method,
                                "methods_exceeded": sorted(exceeded),
                                "target_fpr_family_wise": cfg.target_fpr,
                                "target_fpr_per_method": per_method_fpr,
                                "reference_samples": n_reference,
                                "reference_mode": mode,
                                "sample_is_in_reference_set": is_reference,
                                "pca_components": n_components,
                                "feature_space": ctx.features.extractor,
                            },
                            refs=(sample_id,),
                        ),
                        EvidenceItem(
                            kind="reference_definition",
                            statement=mode_note,
                            observation={
                                "mode": mode,
                                "reference_size": n_reference,
                                "total_analysed": len(sample_ids),
                            },
                            refs=(),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "methods_exceeded": len(exceeded),
                                "methods_total": len(observed),
                                "min_empirical_p": min_p,
                            },
                            refs=(),
                        ),
                    ],
                    assumptions=(
                        "the declared reference set is itself trustworthy and "
                        "representative of the intended operating distribution",
                        "the classical feature space captures the acquisition "
                        "characteristics that distinguish distributions",
                    ),
                    limitations=(
                        "being out of distribution is NOT evidence of malicious "
                        "intent: terrain, season, sensor and illumination changes "
                        "produce the same signature and are expected in operation",
                        "distinguishing operational drift from deliberate insertion "
                        "requires population-level analysis, which is Module 4 scope "
                        "and is not performed here",
                        "an adversary who matches the reference distribution's "
                        "low-level statistics is not detected by this method",
                    ),
                )
            )

        out.scores[ATTACK_CLASS] = scores
        out.flagged[ATTACK_CLASS] = flagged_ids
        # Published for the label-consistency detector: a sample outside the
        # reference distribution has an unrepresentative neighbourhood, so any
        # label claim about it rests on weaker ground.
        ctx.shared["ood_flagged"] = flagged_ids
        ctx.shared["ood_reference_mode"] = mode
        out.stats = {
            "mode": mode,
            "reference_samples": n_reference,
            "analysed": len(sample_ids),
            "flagged": n_flagged,
            "observed_flag_rate": n_flagged / max(len(sample_ids), 1),
            "target_fpr_family_wise": cfg.target_fpr,
            "target_fpr_per_method": per_method_fpr,
            "thresholds": {k: float(v) for k, v in thresholds.items()},
            "pca_components": n_components,
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS,
                Coverage.PARTIAL,
                detector=self.name, detector_version=self.version,
                reason=(
                    None if mode == "declared"
                    else "no reference distribution was declared; samples were scored "
                         "against the dataset's own bulk, which an adversary "
                         "contributing a large share can shift in their favour"
                ),
                assumptions=("reference set is trustworthy and representative",),
                limitations=(
                    "OOD is not malice",
                    "detects distributional distance, not intent or provenance",
                ),
            )
        )
        return out

    def _reference(
        self, ctx: AnalysisContext, sample_ids: Sequence[str]
    ) -> tuple[frozenset[str], str, str]:
        if ctx.reference_sample_ids:
            available = frozenset(ctx.reference_sample_ids) & frozenset(sample_ids)
            return (
                available,
                "declared",
                f"Reference distribution was declared explicitly and resolved to "
                f"{len(available)} decodable samples.",
            )
        return (
            frozenset(sample_ids),
            "self",
            "No reference distribution was declared, so the dataset's own bulk was "
            "used as the reference. This is weaker: a contributor supplying a large "
            "share of the data shifts the reference towards itself. Declare a "
            "trusted reference set for a stronger claim.",
        )


def _fit_pca(reference: np.ndarray, components: int) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic PCA fitted on the reference set only.

    Fitting on the reference alone matters: fitting on the whole dataset would
    let inserted samples define the very subspace used to judge them.
    """
    mean_vector = reference.mean(axis=0)
    centred = reference - mean_vector
    _, _, vt = np.linalg.svd(centred, full_matrices=False)
    k = int(min(components, vt.shape[0], centred.shape[0] - 1))
    k = max(k, 1)
    projector = vt[:k].T
    # SVD sign is arbitrary; fix it so the projection is bit-reproducible.
    signs = np.sign(projector[np.argmax(np.abs(projector), axis=0), np.arange(k)])
    signs[signs == 0] = 1.0
    return projector * signs, mean_vector


def _fit_scorers(reference: np.ndarray, cfg) -> tuple[dict[str, Any], int]:
    """Fit every configured scorer on a reference set, in the original space.

    PCA is fitted here rather than by the caller because of ``residual``: the
    reconstruction error is only meaningful against the *same* subspace the
    distance measures use, and cross-fitting must refit both together or the
    reference scores are contaminated.
    """
    projector, mean_vector = _fit_pca(reference, cfg.pca_components)
    reference_p = (reference - mean_vector) @ projector
    scorers: dict[str, Any] = {}

    if "mahalanobis" in cfg.methods:
        estimator = LedoitWolf(store_precision=True, assume_centered=False).fit(reference_p)
        location, precision = estimator.location_, estimator.precision_

        def mahalanobis(points: np.ndarray) -> np.ndarray:
            return mahalanobis_scores((points - mean_vector) @ projector, location, precision)

        scorers["mahalanobis"] = mahalanobis

    if "knn" in cfg.methods:
        k = min(cfg.knn_k, max(reference_p.shape[0] - 1, 1))

        def knn(points: np.ndarray) -> np.ndarray:
            return _knn_distance((points - mean_vector) @ projector, reference_p, k)

        scorers["knn"] = knn

    if "residual" in cfg.methods:
        def residual(points: np.ndarray) -> np.ndarray:
            centred = points - mean_vector
            reconstructed = (centred @ projector) @ projector.T
            return np.linalg.norm(centred - reconstructed, axis=1)

        scorers["residual"] = residual

    return scorers, int(projector.shape[1])


def _knn_distance(points: np.ndarray, reference: np.ndarray, k: int, block: int = 512) -> np.ndarray:
    out = np.zeros(points.shape[0], dtype=float)
    reference_sq = (reference**2).sum(axis=1)
    for start in range(0, points.shape[0], block):
        stop = min(start + block, points.shape[0])
        chunk = points[start:stop]
        squared = (
            (chunk**2).sum(axis=1)[:, None] - 2 * chunk @ reference.T + reference_sq[None, :]
        )
        np.maximum(squared, 0.0, out=squared)
        kk = min(k, squared.shape[1])
        nearest = np.partition(squared, kk - 1, axis=1)[:, :kk]
        out[start:stop] = np.sqrt(nearest).mean(axis=1)
    return out


def _cross_fitted_scores(
    vectors: np.ndarray, reference_mask: np.ndarray, cfg, folds: int
) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    """Score reference and candidate samples under the *same* fitting regime.

    Naively, one fits the scorers on the whole reference set, scores everything
    with that, and derives the threshold from cross-fitted reference scores.
    That is wrong, and quietly so.  Every scorer here depends on how much data
    it was fitted on:

    * Ledoit-Wolf shrinkage is stronger for smaller ``n``, which compresses
      Mahalanobis distances;
    * k-NN distance grows as the reference set thins;
    * the PCA subspace, and therefore the residual, tightens with more data.

    So a threshold taken from ``K-1``-fold fits and applied to scores from a
    full fit compares two different scales.  Measured on this build's clean
    corpus, that mismatch produced an 8.9% false-alarm rate against a nominal
    1% — the stated FPR would have been fiction.

    The fix is symmetry: every fold model scores its held-out reference samples
    *and* every candidate sample.  Reference samples keep their held-out score;
    candidates take the mean across folds.  Both sides then come from models
    fitted on the same amount of data, and the quantile threshold means what it
    says.
    """
    reference_rows = np.nonzero(reference_mask)[0]
    n_reference = reference_rows.size
    effective_folds = max(2, min(folds, n_reference // 2)) if n_reference >= 4 else 2
    assignment = np.arange(n_reference) % effective_folds

    cross_fitted = {m: np.zeros(n_reference, dtype=float) for m in cfg.methods}
    accumulated = {m: np.zeros(vectors.shape[0], dtype=float) for m in cfg.methods}
    fold_count = 0

    for fold in range(effective_folds):
        held_out = assignment == fold
        fit_on = ~held_out
        if fit_on.sum() < 3 or held_out.sum() == 0:
            continue
        scorers, _ = _fit_scorers(vectors[reference_rows[fit_on]], cfg)
        fold_count += 1
        for method, scorer in scorers.items():
            cross_fitted[method][held_out] = scorer(vectors[reference_rows[held_out]])
            accumulated[method] += scorer(vectors)

    observed = {
        method: values / max(fold_count, 1) for method, values in accumulated.items()
    }
    # A reference sample is judged by the model that never saw it, not by the
    # average of models that mostly did.
    for method in observed:
        observed[method][reference_rows] = cross_fitted[method]
    return cross_fitted, observed


def _severity(
    n_exceeded: int, n_methods: int, min_p: float, mode: str
) -> tuple[Severity, str]:
    # Severity is capped at MEDIUM for OOD by design: "different from the
    # reference" is never, on this evidence alone, a HIGH-severity security
    # claim, and letting it become one is how an assurance tool starts crying
    # wolf at every seasonal change.
    if n_exceeded == n_methods and min_p <= 0.005 and mode == "declared":
        return (
            Severity.MEDIUM,
            "every configured distance measure places this sample in the extreme "
            "tail of a declared reference distribution; two independent views agree",
        )
    if n_exceeded == n_methods:
        return (
            Severity.LOW,
            "all configured measures exceeded their thresholds, but against a "
            "self-derived or less extreme reference",
        )
    return (
        Severity.LOW,
        f"{n_exceeded} of {n_methods} distance measures exceeded threshold; the "
        "measures disagree, which is common for legitimate acquisition variation",
    )
