"""Label-consistency screening: model-free detection of suspicious labels.

Method and why this one
-----------------------
The established high-precision approach to label noise, Confident Learning
(Northcutt, Jiang & Chuang, JAIR 2021), needs a model's predicted probabilities.
Module 1 has no model — models are untrusted artifacts that Module 2 assesses —
so using one here would make dataset assurance depend on an unassured artifact.

Instead this detector uses the model-free branch of the same literature:
neighbourhood label agreement, in the Edited-Nearest-Neighbour tradition
(Wilson, 1972; surveyed in Frénay & Verleysen, 2014).  The claim is narrow and
checkable: *this sample sits inside a neighbourhood that consistently carries a
different label*.  Two independent quantities support it:

1. **Distance-weighted neighbourhood disagreement** over k nearest neighbours.
2. **Class-centroid margin** — whether the sample is closer to another class's
   centroid than to its own, which also yields the *suggested* alternative
   label an analyst can act on.

Adversarial hardening
---------------------
Near-duplicate members are removed from a query's neighbourhood by default.
Without this, an adversary flips a label and then floods the dataset with
near-copies carrying the same flipped label; the neighbourhood then agrees with
itself and the flip becomes invisible.  Excluding perceptual duplicates forces
agreement to come from genuinely distinct imagery.

For detection datasets the analysis runs on object crops rather than whole
images, because an image-level label in a detection set is a set union and
carries no single-class semantics.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

import numpy as np

from ..core.evidence import Coverage, EvidenceItem, Severity
from ..datasets.base import Task
from ..risk.statistics import distance_weighted_disagreement
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "label_flip"

#: Prior when uncalibrated.  Neighbourhood disagreement is a screening signal,
#: not a verdict: at class boundaries it fires on correctly labelled samples.
UNCALIBRATED_PRIOR = 0.45

_BLOCK = 512


class LabelConsistencyDetector:
    name = "label_consistency"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        cfg = ctx.config.label_consistency

        unit = self._collect(ctx)
        if unit is None:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason="no labelled, decodable units available for analysis",
                )
            )
            return out

        keys, labels, vectors, level = unit

        counts: dict[str, int] = defaultdict(int)
        for label in labels:
            counts[label] += 1
        eligible_classes = {c for c, n in counts.items() if n >= cfg.min_class_support}
        if len(eligible_classes) < 2:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=f"fewer than two classes have the required support of "
                           f"{cfg.min_class_support} samples; neighbourhood label "
                           "agreement is undefined",
                )
            )
            out.stats = {"class_counts": dict(sorted(counts.items()))}
            return out

        eligible = np.array([label in eligible_classes for label in labels])
        idx = np.nonzero(eligible)[0]
        vectors = vectors[idx]
        labels = [labels[i] for i in idx]
        keys = [keys[i] for i in idx]

        exclusion = self._exclusion_groups(ctx, keys) if cfg.exclude_near_duplicates else {}

        centroids, centroid_labels = _class_centroids(vectors, labels)
        k = min(cfg.k, len(labels) - 1)
        if k < 1:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason="not enough eligible samples to form a neighbourhood",
                )
            )
            return out

        suggestions: dict[str, tuple[str, str, float]] = {}
        scores: dict[str, float] = {}
        n_flagged = 0

        for start in range(0, len(labels), _BLOCK):
            stop = min(start + _BLOCK, len(labels))
            # Vectors are L2-normalised, so the dot product is cosine similarity.
            similarity = vectors[start:stop] @ vectors.T
            for local, global_i in enumerate(range(start, stop)):
                row = similarity[local].copy()
                row[global_i] = -np.inf
                for excluded in exclusion.get(keys[global_i], ()):  # near-duplicates
                    if excluded != global_i:
                        row[excluded] = -np.inf

                neighbours = np.argpartition(-row, min(k, row.size - 1))[:k]
                neighbours = neighbours[np.isfinite(row[neighbours])]
                if neighbours.size == 0:
                    continue
                neighbours = neighbours[np.argsort(-row[neighbours])]

                own_label = labels[global_i]
                neighbour_labels = [labels[j] for j in neighbours]
                distances = 1.0 - row[neighbours]
                disagreement = distance_weighted_disagreement(
                    distances, neighbour_labels, own_label
                )
                key_str = _key_str(keys[global_i])
                scores[key_str] = disagreement

                if disagreement < cfg.disagreement_min:
                    continue

                suggested, support = _weighted_majority(distances, neighbour_labels)
                own_similarity, suggested_similarity, margin = _centroid_margin(
                    vectors[global_i], centroids, centroid_labels, own_label, suggested
                )
                severity, rationale = _severity(disagreement, margin)
                sample_id, annotation_id = _split_key(keys[global_i])

                # Evidence qualification: if the OOD detector already placed
                # this sample outside the reference distribution, its
                # neighbourhood is drawn from imagery the sample does not
                # belong with, and label disagreement is the expected
                # consequence rather than evidence of a flip.  The finding is
                # kept -- suppressing it would hide a real observation -- but
                # its severity is capped and the reason is recorded, so an
                # analyst reads it alongside the OOD finding for the same asset.
                ood_flagged: set[str] = ctx.shared.get("ood_flagged", set())
                extra_evidence: list[EvidenceItem] = []
                extra_limitations: list[str] = []
                if sample_id in ood_flagged:
                    severity = Severity.LOW
                    rationale = (
                        "severity capped at LOW: this sample is also flagged as "
                        "out-of-distribution, so its neighbourhood is not "
                        "representative and label disagreement is expected "
                        "regardless of whether the label is correct"
                    )
                    extra_evidence.append(
                        EvidenceItem(
                            kind="evidence_qualification",
                            statement="This sample was independently flagged as "
                            "out-of-distribution. Neighbourhood label evidence is "
                            "weak for such samples; read this finding together with "
                            "the ood_insertion finding for the same asset.",
                            observation={
                                "qualified_by": "ood",
                                "reference_mode": ctx.shared.get(
                                    "ood_reference_mode", "unknown"
                                ),
                                "severity_capped_to": Severity.LOW.value,
                            },
                            refs=(sample_id,),
                        )
                    )
                    extra_limitations.append(
                        "sample is out-of-distribution; neighbourhood label "
                        "evidence is materially weaker for it"
                    )
                suggestions[key_str] = (own_label, suggested, disagreement)
                n_flagged += 1

                out.findings.append(
                    factory.emit(
                        attack_class=ATTACK_CLASS,
                        asset=ctx.sample_asset(sample_id),
                        contributor=ctx.contributor_of(sample_id),
                        title=(
                            f"Label '{own_label}' disagrees with its neighbourhood"
                            + (f" (object {annotation_id})" if annotation_id else "")
                            + f"; neighbours suggest '{suggested}'"
                        ),
                        severity=severity,
                        score=disagreement,
                        prior=UNCALIBRATED_PRIOR,
                        coverage=Coverage.PARTIAL,
                        discriminator=(level, annotation_id or "", own_label, suggested),
                        evidence=[
                            EvidenceItem(
                                kind="knn_label_disagreement",
                                statement=(
                                    f"{sum(1 for l in neighbour_labels if l != own_label)} "
                                    f"of the {len(neighbour_labels)} nearest neighbours carry a "
                                    f"different label; distance-weighted disagreement is "
                                    f"{disagreement:.3f} (threshold {cfg.disagreement_min})."
                                ),
                                observation={
                                    "k": int(len(neighbour_labels)),
                                    "own_label": own_label,
                                    "disagreement": float(disagreement),
                                    "threshold": cfg.disagreement_min,
                                    "neighbours": [
                                        {
                                            "key": _key_str(keys[j]),
                                            "label": labels[j],
                                            "cosine": float(row[j]),
                                        }
                                        for j in neighbours[:10]
                                    ],
                                },
                                refs=tuple(_split_key(keys[j])[0] for j in neighbours[:10]),
                            ),
                            EvidenceItem(
                                kind="class_centroid_margin",
                                statement=(
                                    f"The sample is {'closer' if margin > 0 else 'not closer'} "
                                    f"to the '{suggested}' centroid than to its own "
                                    f"'{own_label}' centroid (cosine {suggested_similarity:.4f} "
                                    f"vs {own_similarity:.4f}, margin {margin:+.4f})."
                                ),
                                observation={
                                    "own_label": own_label,
                                    "suggested_label": suggested,
                                    "cosine_to_own_centroid": own_similarity,
                                    "cosine_to_suggested_centroid": suggested_similarity,
                                    "margin": margin,
                                    "neighbour_support_for_suggestion": support,
                                },
                                refs=(),
                            ),
                            EvidenceItem(
                                kind="severity_rationale",
                                statement=rationale,
                                observation={
                                    "disagreement": float(disagreement),
                                    "centroid_margin": margin,
                                },
                                refs=(),
                            ),
                            *extra_evidence,
                        ],
                        assumptions=(
                            "samples of the same class are nearer each other than "
                            "samples of different classes in the configured feature space",
                            f"classes with at least {cfg.min_class_support} samples are "
                            "represented well enough for neighbourhood voting",
                        ),
                        limitations=(
                            *extra_limitations,
                            "this is a screening signal, not a verdict: genuinely "
                            "ambiguous or boundary samples produce the same evidence "
                            "as a flipped label",
                            "sensitive to the feature space; the default classical "
                            "descriptor is weaker than a task-trained embedding",
                            "a class that is mislabelled in its entirety looks "
                            "internally consistent and is not detectable this way",
                        ),
                    )
                )

        ctx.shared["label_suggestions"] = suggestions
        ctx.shared["label_analysis_level"] = level
        # Every analysed unit, with its contributor: the denominator the
        # systematic-mislabelling detector needs for a rate, and the reason it
        # can compute one without re-running the neighbourhood search.
        ctx.shared["label_units"] = [
            (_key_str(key), ctx.contributor_of(key[0]), label)
            for key, label in zip(keys, labels)
        ]
        out.scores[ATTACK_CLASS] = scores
        out.flagged[ATTACK_CLASS] = {key.split("#", 1)[0] for key in suggestions}
        out.stats = {
            "level": level,
            "units_analysed": len(labels),
            "classes_eligible": sorted(eligible_classes),
            "classes_excluded": sorted(set(counts) - eligible_classes),
            "flagged": n_flagged,
            "flag_rate": n_flagged / max(len(labels), 1),
            "near_duplicates_excluded_from_neighbourhoods": cfg.exclude_near_duplicates,
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.PARTIAL,
                detector=self.name, detector_version=self.version,
                reason="feature-space dependent; recall is measured on attack-lab "
                       "scenarios and reported, not assumed",
                assumptions=("class-conditional clustering in the feature space",),
                limitations=(
                    "cannot detect a uniformly mislabelled class",
                    "recall degrades as the flip rate rises, because flipped "
                    "samples begin to form their own consistent neighbourhood",
                ),
            )
        )
        return out

    # -- helpers --------------------------------------------------------

    def _collect(
        self, ctx: AnalysisContext
    ) -> tuple[list[tuple[str, str | None]], list[str], np.ndarray, str] | None:
        """Choose the analysis level: object crops for detection, images otherwise."""
        if ctx.dataset.task is Task.DETECTION and ctx.objects is not None and ctx.objects.n > 0:
            keys = [(sid, ann) for sid, ann in ctx.objects.keys]
            return keys, list(ctx.objects.labels), ctx.objects.embeddings, "object"

        keys_img: list[tuple[str, str | None]] = []
        labels: list[str] = []
        rows: list[int] = []
        for row in ctx.features.valid_rows():
            sample_id = ctx.features.sample_ids[row]
            record = ctx.manifest.sample(sample_id)
            if record is None or len(record.labels) != 1:
                continue
            keys_img.append((sample_id, None))
            labels.append(record.labels[0])
            rows.append(int(row))
        if not rows:
            return None
        return keys_img, labels, ctx.features.embeddings[np.array(rows)], "image"

    def _exclusion_groups(
        self, ctx: AnalysisContext, keys: Sequence[tuple[str, str | None]]
    ) -> dict[tuple[str, str | None], tuple[int, ...]]:
        """Row indices to remove from each query's neighbourhood.

        A sample's own perceptual near-duplicates are excluded so that a
        flooding attack cannot manufacture neighbourhood agreement for a
        flipped label.
        """
        clusters: list[list[str]] = ctx.shared.get("near_duplicate_clusters", [])
        exact = ctx.shared.get("exact_duplicate_groups", {})
        groups = [list(v) for v in exact.get("file", {}).values()]
        groups += [list(v) for v in exact.get("pixel", {}).values()]
        groups += clusters
        if not groups:
            return {}

        rows_by_sample: dict[str, list[int]] = defaultdict(list)
        for row, (sample_id, _) in enumerate(keys):
            rows_by_sample[sample_id].append(row)

        exclusion: dict[tuple[str, str | None], list[int]] = defaultdict(list)
        for group in groups:
            member_rows = [r for sid in group for r in rows_by_sample.get(sid, ())]
            for sid in group:
                for row in rows_by_sample.get(sid, ()):
                    exclusion[keys[row]].extend(member_rows)
        return {k: tuple(sorted(set(v))) for k, v in exclusion.items()}


def _class_centroids(
    vectors: np.ndarray, labels: Sequence[str]
) -> tuple[np.ndarray, list[str]]:
    unique = sorted(set(labels))
    centroids = np.zeros((len(unique), vectors.shape[1]), dtype=np.float32)
    for i, label in enumerate(unique):
        mask = np.array([l == label for l in labels])
        centroid = vectors[mask].mean(axis=0)
        norm = float(np.linalg.norm(centroid))
        centroids[i] = centroid / norm if norm > 1e-8 else centroid
    return centroids, unique


def _centroid_margin(
    vector: np.ndarray,
    centroids: np.ndarray,
    centroid_labels: list[str],
    own_label: str,
    suggested: str,
) -> tuple[float, float, float]:
    similarities = centroids @ vector
    own = float(similarities[centroid_labels.index(own_label)])
    other = (
        float(similarities[centroid_labels.index(suggested)])
        if suggested in centroid_labels
        else float("nan")
    )
    return own, other, other - own


def _weighted_majority(
    distances: np.ndarray, neighbour_labels: Sequence[str]
) -> tuple[str, float]:
    weights = 1.0 / (np.asarray(distances, dtype=float) + 1e-6)
    totals: dict[str, float] = defaultdict(float)
    for weight, label in zip(weights, neighbour_labels):
        totals[label] += float(weight)
    total = sum(totals.values()) or 1.0
    best = max(sorted(totals.items()), key=lambda kv: kv[1])
    return best[0], best[1] / total


def _severity(disagreement: float, margin: float) -> tuple[Severity, str]:
    if disagreement >= 0.9 and margin > 0:
        return (
            Severity.HIGH,
            "the neighbourhood is almost unanimous against the declared label and "
            "the sample is closer to the suggested class centroid; two independent "
            "signals agree",
        )
    if disagreement >= 0.8 or (disagreement >= 0.7 and margin > 0):
        return (
            Severity.MEDIUM,
            "strong neighbourhood disagreement, or moderate disagreement "
            "corroborated by the centroid margin",
        )
    return (
        Severity.LOW,
        "disagreement is above threshold but within the range seen at legitimate "
        "class boundaries",
    )


def _key_str(key: tuple[str, str | None]) -> str:
    return f"{key[0]}#{key[1]}" if key[1] else key[0]


def _split_key(key: tuple[str, str | None]) -> tuple[str, str | None]:
    return key
