"""Near-duplicate detection and near-duplicate flooding.

Two stages, for two different failure modes:

**Stage 1 — recall.**  pHash Hamming distance over all pairs.  Cheap, exact
(not approximate), and robust to the re-encode/exposure/mild-crop edits a
flooding adversary uses.  Its weakness is precision: low-detail images (sky,
sea, uniform terrain) have low-entropy hashes that collide.

**Stage 2 — precision.**  Every stage-1 candidate pair is confirmed by cosine
similarity in the classical feature space, which looks at colour, gradient and
acquisition statistics that pHash discards.  A pair that survives both is
supported by two independent views of the image.

Clusters are connected components over confirmed pairs (union-find).  Transitive
closure is the right structure here: an adversary who submits a chain of small
perturbations produces exactly that, and treating each pair independently would
under-report the size of the injected group.

Flooding is a *contributor-level* claim: it is not that a duplicate exists, but
that one source contributed an implausible share of a cluster.  That is emitted
separately, with the sample-level cluster findings as its evidence.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import numpy as np

from ..core.evidence import Coverage, EvidenceItem, Severity
from ..features.perceptual import hamming_pairs_within
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "near_duplicate_flood"

#: Prior used when no calibration table exists.  Deliberately modest: a
#: two-stage confirmed perceptual match is good evidence of similarity, but
#: "similar" is not "injected", and an uncalibrated detector should not imply
#: that it knows the difference.
UNCALIBRATED_PRIOR = 0.55


class _UnionFind:
    def __init__(self, n: int) -> None:
        self._parent = list(range(n))
        self._rank = [0] * n

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1

    def groups(self) -> dict[int, list[int]]:
        out: dict[int, list[int]] = defaultdict(list)
        for i in range(len(self._parent)):
            out[self.find(i)].append(i)
        return out


class NearDuplicateDetector:
    name = "near_duplicate"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        cfg = ctx.config.near_duplicate

        rows = ctx.features.valid_rows()
        n_valid = int(rows.size)

        if n_valid < 2:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=f"only {n_valid} decodable image(s); near-duplicate "
                           "analysis needs at least two",
                )
            )
            return out

        if n_valid > cfg.max_pairwise_samples:
            # Refuse rather than silently subsample: a partial scan reported as
            # a full one is the kind of quiet coverage gap this system exists
            # to prevent.
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=f"{n_valid} samples exceeds "
                           f"near_duplicate.max_pairwise_samples="
                           f"{cfg.max_pairwise_samples}; exact all-pairs comparison "
                           "was refused rather than approximated",
                )
            )
            out.stats = {"skipped_samples": n_valid}
            return out

        codes = ctx.features.phash[rows]
        embeddings = ctx.features.embeddings[rows]
        candidates = hamming_pairs_within(codes, cfg.phash_hamming_max)

        confirmed: list[tuple[int, int, int, float]] = []
        rejected = 0
        for i, j, distance in candidates:
            cosine = float(np.dot(embeddings[i], embeddings[j]))
            if cosine >= cfg.confirm_cosine_min:
                confirmed.append((i, j, distance, cosine))
            else:
                rejected += 1

        union = _UnionFind(n_valid)
        for i, j, _, _ in confirmed:
            union.union(i, j)

        pair_index: dict[tuple[int, int], tuple[int, float]] = {
            (i, j): (d, c) for i, j, d, c in confirmed
        }

        exact_groups = ctx.shared.get("exact_duplicate_groups", {})
        exact_file_members = {
            frozenset(members) for members in exact_groups.get("file", {}).values()
        }
        exact_pixel_members = {
            frozenset(members) for members in exact_groups.get("pixel", {}).values()
        }
        already_reported = exact_file_members | exact_pixel_members

        clusters: list[list[str]] = []
        cluster_scores: dict[str, float] = {}
        contributor_membership: dict[str, list[tuple[int, int]]] = defaultdict(list)

        for cluster_id, (_, member_rows) in enumerate(sorted(union.groups().items())):
            if len(member_rows) < 2:
                continue
            sample_ids = sorted(ctx.features.sample_ids[rows[r]] for r in member_rows)

            # Skip clusters that exact-duplicate detection already covered
            # completely; reporting the same group twice adds noise, not evidence.
            if frozenset(sample_ids) in already_reported:
                continue

            distances, cosines = _cluster_pair_stats(member_rows, pair_index)
            score = _cluster_score(distances, cosines, cfg.phash_hamming_max, cfg.confirm_cosine_min)
            severity, rationale = _severity(len(sample_ids), cfg.flood_cluster_size)

            contributors: dict[str, int] = defaultdict(int)
            for sid in sample_ids:
                contributors[ctx.contributor_of(sid)] += 1
            for name in contributors:
                contributor_membership[name].append((cluster_id, len(sample_ids)))

            clusters.append(sample_ids)
            for sid in sample_ids:
                cluster_scores[sid] = max(cluster_scores.get(sid, 0.0), score)

            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.sample_asset(sample_ids[0]),
                    contributor=(
                        next(iter(contributors)) if len(contributors) == 1 else None
                    ),
                    title=f"Near-duplicate cluster of {len(sample_ids)} images",
                    severity=severity,
                    score=score,
                    prior=UNCALIBRATED_PRIOR,
                    coverage=Coverage.SUPPORTED,
                    discriminator=("cluster", *sample_ids[:32]),
                    evidence=[
                        EvidenceItem(
                            kind="perceptual_hash_distance",
                            statement=f"{len(sample_ids)} images form a connected cluster "
                            f"under pHash Hamming distance <= {cfg.phash_hamming_max}/64 "
                            f"(observed mean {np.mean(distances):.2f}, max {max(distances)}).",
                            observation={
                                "cluster_size": len(sample_ids),
                                "hamming_threshold": cfg.phash_hamming_max,
                                "hamming_mean": float(np.mean(distances)),
                                "hamming_max": int(max(distances)),
                                "hamming_min": int(min(distances)),
                                "members": sample_ids[:50],
                            },
                            refs=tuple(sample_ids[:50]),
                        ),
                        EvidenceItem(
                            kind="embedding_confirmation",
                            statement="Every reported pair was independently confirmed in "
                            f"the classical feature space (cosine >= {cfg.confirm_cosine_min}; "
                            f"observed mean {np.mean(cosines):.4f}).",
                            observation={
                                "cosine_min_required": cfg.confirm_cosine_min,
                                "cosine_mean": float(np.mean(cosines)),
                                "cosine_min_observed": float(min(cosines)),
                                "feature_space": ctx.features.extractor,
                            },
                            refs=tuple(sample_ids[:50]),
                        ),
                        EvidenceItem(
                            kind="contributor_composition",
                            statement="Cluster membership by contributor: "
                            + ", ".join(f"{k}={v}" for k, v in sorted(contributors.items())),
                            observation={"by_contributor": dict(sorted(contributors.items()))},
                            refs=(),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "cluster_size": len(sample_ids),
                                "flood_cluster_size": cfg.flood_cluster_size,
                            },
                            refs=(),
                        ),
                    ],
                    assumptions=(
                        "perceptual similarity in pHash and in the classical feature "
                        "space jointly imply the images are near-identical in content",
                    ),
                    limitations=(
                        "pHash is not invariant to rotation, reflection, heavy crop or "
                        "geometric warping; such variants are not detected",
                        "near-duplication is not inherently malicious: burst capture, "
                        "video frames and tiled imagery produce it legitimately",
                    ),
                )
            )

        ctx.shared["near_duplicate_clusters"] = clusters
        ctx.shared["near_duplicate_members"] = {
            sid for cluster in clusters for sid in cluster
        }
        out.scores[ATTACK_CLASS] = cluster_scores
        out.flagged[ATTACK_CLASS] = set(cluster_scores)
        out.stats = {
            "candidate_pairs": len(candidates),
            "confirmed_pairs": len(confirmed),
            "rejected_by_embedding": rejected,
            "clusters": len(clusters),
            "samples_in_clusters": len(cluster_scores),
            "stage2_rejection_rate": (
                rejected / len(candidates) if candidates else 0.0
            ),
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=(
                    "images are comparable at the same orientation and framing",
                ),
                limitations=(
                    "no invariance to rotation, reflection or heavy crop",
                    "flooding is inferred from cluster size and contributor "
                    "concentration, both of which have legitimate causes",
                ),
            )
        )
        return out


def _cluster_pair_stats(
    member_rows: Iterable[int], pair_index: dict[tuple[int, int], tuple[int, float]]
) -> tuple[list[int], list[float]]:
    """Statistics over the confirmed edges *inside* one cluster."""
    members = sorted(member_rows)
    distances: list[int] = []
    cosines: list[float] = []
    for a_i, a in enumerate(members):
        for b in members[a_i + 1:]:
            hit = pair_index.get((a, b))
            if hit is not None:
                distances.append(hit[0])
                cosines.append(hit[1])
    if not distances:  # a cluster always has at least one confirmed edge
        distances, cosines = [0], [1.0]
    return distances, cosines


def _cluster_score(
    distances: list[int], cosines: list[float], hamming_max: int, cosine_min: float
) -> float:
    """Blend the two independent similarity views into one score in [0, 1].

    Both halves are monotone in "more similar", equally weighted because neither
    view is known to be more reliable than the other on unseen imagery.  The
    score feeds the calibration table; it is never reported as a confidence in
    its own right.
    """
    hamming_term = 1.0 - (float(np.mean(distances)) / max(hamming_max, 1))
    cosine_term = (float(np.mean(cosines)) - cosine_min) / max(1.0 - cosine_min, 1e-6)
    return float(np.clip(0.5 * hamming_term + 0.5 * cosine_term, 0.0, 1.0))


def _severity(cluster_size: int, flood_threshold: int) -> tuple[Severity, str]:
    if cluster_size >= flood_threshold * 4:
        return (
            Severity.HIGH,
            f"cluster is {cluster_size} images, more than four times the "
            f"flooding threshold of {flood_threshold}; a group this size "
            "materially shifts class balance",
        )
    if cluster_size >= flood_threshold:
        return (
            Severity.MEDIUM,
            f"cluster reaches the configured flooding threshold of {flood_threshold}",
        )
    return (
        Severity.LOW,
        "small cluster, consistent with ordinary redundancy in the source imagery",
    )
