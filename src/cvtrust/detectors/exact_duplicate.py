"""Exact duplicate detection.

Two digests, two different claims:

``file_sha256``
    Byte-identical files.  The submission literally repeated the same artifact.

``pixel_sha256``
    Identical decoded content in non-identical containers.  This is the
    interesting case: an adversary who knows that byte hashing is used will
    re-encode, strip EXIF or change the container, and the file digest then
    reports nothing while the training set is just as skewed.  Content digests
    close that gap deterministically, with no threshold to argue about.

Both are cryptographic equality, so confidence is 1.0.  Severity scales with the
size of the duplicate group, because two copies of an image is housekeeping and
forty copies is class-balance manipulation.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.evidence import ConfidenceBasis, Coverage, EvidenceItem, Severity
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "duplicate_flood"


def _severity(group_size: int, flood_threshold: int) -> tuple[Severity, str]:
    if group_size >= flood_threshold * 4:
        return Severity.HIGH, "group size is several times the flooding threshold"
    if group_size >= flood_threshold:
        return Severity.MEDIUM, "group size reaches the configured flooding threshold"
    return Severity.LOW, "small duplicate group; consistent with ordinary redundancy"


class ExactDuplicateDetector:
    name = "exact_duplicate"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        threshold = ctx.config.near_duplicate.flood_cluster_size

        by_file: dict[str, list[str]] = defaultdict(list)
        by_pixel: dict[str, list[str]] = defaultdict(list)
        for record in ctx.manifest.samples:
            if record.file_sha256:
                by_file[record.file_sha256].append(record.sample_id)
            if record.pixel_sha256:
                by_pixel[record.pixel_sha256].append(record.sample_id)

        file_groups = {d: sorted(ids) for d, ids in by_file.items() if len(ids) > 1}
        pixel_groups = {d: sorted(ids) for d, ids in by_pixel.items() if len(ids) > 1}

        flagged: set[str] = set()

        for digest, members in sorted(file_groups.items()):
            severity, rationale = _severity(len(members), threshold)
            contributors = sorted({ctx.contributor_of(m) for m in members})
            flagged.update(members)
            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.sample_asset(members[0]),
                    contributor=contributors[0] if len(contributors) == 1 else None,
                    title=f"{len(members)} byte-identical copies of this image in the dataset",
                    severity=severity,
                    confidence=1.0,
                    basis=ConfidenceBasis.DETERMINISTIC,
                    coverage=Coverage.SUPPORTED,
                    discriminator=("file_sha256", digest),
                    evidence=[
                        EvidenceItem(
                            kind="file_digest_collision",
                            statement=f"{len(members)} files share SHA-256 {digest[:16]}..., "
                            "so they are byte-for-byte the same artifact.",
                            observation={
                                "file_sha256": digest,
                                "group_size": len(members),
                                "members": members[:50],
                                "contributors": contributors,
                            },
                            refs=tuple(members[:50]),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "group_size": len(members),
                                "flood_cluster_size": threshold,
                            },
                            refs=(),
                        ),
                    ],
                    assumptions=("SHA-256 collision resistance",),
                    limitations=(
                        "duplication is not inherently malicious; identical frames "
                        "occur legitimately in video-derived and tiled imagery",
                    ),
                )
            )

        # Only report a content group when it is not already fully explained by
        # a byte-identical group: otherwise every exact duplicate is reported
        # twice and the analyst learns nothing from the second copy.
        for digest, members in sorted(pixel_groups.items()):
            file_digests = {
                ctx.manifest.sample(m).file_sha256 for m in members  # type: ignore[union-attr]
            }
            if len(file_digests) <= 1:
                continue
            severity, rationale = _severity(len(members), threshold)
            contributors = sorted({ctx.contributor_of(m) for m in members})
            flagged.update(members)
            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.sample_asset(members[0]),
                    contributor=contributors[0] if len(contributors) == 1 else None,
                    title=f"{len(members)} files with identical pixel content but "
                    f"{len(file_digests)} distinct file digests",
                    severity=severity,
                    confidence=1.0,
                    basis=ConfidenceBasis.DETERMINISTIC,
                    coverage=Coverage.SUPPORTED,
                    discriminator=("pixel_sha256", digest),
                    evidence=[
                        EvidenceItem(
                            kind="content_digest_collision",
                            statement=f"{len(members)} samples decode to identical pixels "
                            f"(content SHA-256 {digest[:16]}...) while differing as files. "
                            "Re-encoding or container edits hide this from byte hashing.",
                            observation={
                                "pixel_sha256": digest,
                                "group_size": len(members),
                                "distinct_file_digests": len(file_digests),
                                "members": members[:50],
                                "contributors": contributors,
                            },
                            refs=tuple(members[:50]),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "group_size": len(members),
                                "flood_cluster_size": threshold,
                            },
                            refs=(),
                        ),
                    ],
                    assumptions=(
                        "SHA-256 collision resistance",
                        "content identity is defined after conversion to 8-bit RGB, so "
                        "a greyscale image and its RGB expansion are the same content",
                    ),
                    limitations=(
                        "duplication is not inherently malicious",
                    ),
                )
            )

        ctx.shared["exact_duplicate_groups"] = {
            "file": file_groups,
            "pixel": pixel_groups,
        }
        ctx.shared["exact_duplicate_flagged"] = flagged
        out.scores[ATTACK_CLASS] = {sid: 1.0 for sid in sorted(flagged)}
        out.flagged[ATTACK_CLASS] = set(flagged)
        out.stats = {
            "file_duplicate_groups": len(file_groups),
            "content_duplicate_groups": len(pixel_groups),
            "samples_in_duplicate_groups": len(flagged),
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS,
                Coverage.SUPPORTED,
                detector=self.name,
                detector_version=self.version,
                assumptions=("SHA-256 collision resistance",),
                limitations=(
                    "exact-match only; any pixel change defeats it by design "
                    "(near-duplicate flooding is covered by the near_duplicate detector)",
                ),
            )
        )
        return out
