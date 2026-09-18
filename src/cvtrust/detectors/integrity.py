"""Structural integrity detector.

Turns the :class:`~cvtrust.datasets.base.IngestIssue` facts collected during
parsing and measurement into findings.  Everything here is *deterministic*: a
bounding box either extends past the image edge or it does not.  Confidence is
1.0 and means it, which is why these findings are the ones an analyst should
action first.

Severity is assigned per issue code from a table that is part of the report, so
the mapping is arguable rather than hidden.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.evidence import (
    AssetRef,
    AssetType,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Severity,
)
from ..datasets.base import IssueCode
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "metadata_inconsistency"

#: Issue code -> (severity, one-line analyst framing).
SEVERITY_TABLE: dict[IssueCode, tuple[Severity, str]] = {
    IssueCode.MISSING_IMAGE_FILE: (
        Severity.HIGH,
        "the dataset describes training data that is not present, so what was "
        "reviewed is not what would be trained on",
    ),
    IssueCode.UNREADABLE_IMAGE: (
        Severity.HIGH,
        "an undecodable file cannot be assessed by any downstream detector and "
        "will fail or silently skip during training",
    ),
    IssueCode.EMPTY_FILE: (Severity.HIGH, "zero-byte file where an image is declared"),
    IssueCode.DIMENSION_MISMATCH: (
        Severity.MEDIUM,
        "annotation geometry was authored against a different image than the one "
        "on disk; boxes will not land where the annotation claims",
    ),
    IssueCode.BBOX_OUT_OF_BOUNDS: (
        Severity.MEDIUM,
        "annotation geometry falls outside the image",
    ),
    IssueCode.INVALID_BBOX: (Severity.MEDIUM, "annotation geometry is not a valid box"),
    IssueCode.UNKNOWN_CATEGORY: (
        Severity.MEDIUM,
        "a label references a class the dataset does not declare",
    ),
    IssueCode.ORPHAN_ANNOTATION: (
        Severity.LOW,
        "annotation refers to an image that is not part of the dataset",
    ),
    IssueCode.DUPLICATE_ID: (
        Severity.MEDIUM,
        "duplicate identifiers make records ambiguous and can silently drop data",
    ),
    IssueCode.MALFORMED_RECORD: (Severity.LOW, "annotation record could not be parsed"),
    IssueCode.UNLABELLED_SAMPLE: (
        Severity.LOW,
        "sample carries no label; it contributes no supervision and may indicate "
        "an incomplete submission",
    ),
    IssueCode.UNSUPPORTED_EXTENSION: (
        Severity.INFO,
        "non-image file inside the dataset tree",
    ),
}


class IntegrityDetector:
    name = "integrity"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)

        issues = list(ctx.dataset.issues) + list(ctx.issues)
        grouped: dict[IssueCode, list] = defaultdict(list)
        for issue in issues:
            grouped[issue.code].append(issue)

        for code, members in sorted(grouped.items(), key=lambda kv: kv[0].value):
            severity, rationale = SEVERITY_TABLE.get(code, (Severity.LOW, ""))
            # Per-sample findings when the issue is attributable to a sample;
            # otherwise one dataset-level finding summarising the group.
            attributable = [i for i in members if i.sample_id]
            unattributable = [i for i in members if not i.sample_id]

            for issue in attributable:
                asset = ctx.sample_asset(issue.sample_id or issue.locator)
                out.findings.append(
                    factory.emit(
                        attack_class=ATTACK_CLASS,
                        asset=asset,
                        contributor=ctx.contributor_of(issue.sample_id or ""),
                        title=f"{code.value.replace('_', ' ')}: {issue.message}",
                        severity=severity,
                        confidence=1.0,
                        basis=ConfidenceBasis.DETERMINISTIC,
                        coverage=Coverage.SUPPORTED,
                        discriminator=(code.value, issue.locator, issue.message[:120]),
                        evidence=[
                            EvidenceItem(
                                kind=f"structural_{code.value}",
                                statement=issue.message,
                                observation=dict(issue.observation),
                                refs=(issue.locator,),
                            ),
                            EvidenceItem(
                                kind="severity_rationale",
                                statement=rationale or "structural defect in dataset metadata",
                                observation={"issue_code": code.value, "severity": severity.value},
                                refs=(),
                            ),
                        ],
                        assumptions=(
                            "the dataset's own annotation files are the authority on "
                            "what the dataset claims; the files on disk are the "
                            "authority on what it contains",
                        ),
                        limitations=(
                            "structural validity does not imply semantic correctness: "
                            "a well-formed annotation can still be wrong",
                        ),
                    )
                )

            if unattributable:
                out.findings.append(
                    factory.emit(
                        attack_class=ATTACK_CLASS,
                        asset=ctx.dataset_asset(),
                        title=f"{len(unattributable)} dataset-level "
                        f"{code.value.replace('_', ' ')} issue(s)",
                        severity=severity,
                        confidence=1.0,
                        basis=ConfidenceBasis.DETERMINISTIC,
                        coverage=Coverage.SUPPORTED,
                        discriminator=(code.value, "dataset-level"),
                        evidence=[
                            EvidenceItem(
                                kind=f"structural_{code.value}",
                                statement=f"{len(unattributable)} record(s) with "
                                f"'{code.value}' that cannot be attributed to a sample.",
                                observation={
                                    "count": len(unattributable),
                                    "examples": [
                                        {"locator": i.locator, "message": i.message,
                                         **dict(i.observation)}
                                        for i in unattributable[:10]
                                    ],
                                },
                                refs=tuple(i.locator for i in unattributable[:20]),
                            )
                        ],
                        assumptions=(),
                        limitations=(
                            "these records could not be attributed to a specific "
                            "sample, so they are not included in contributor rates",
                        ),
                    )
                )

        out.flagged[ATTACK_CLASS] = {
            i.sample_id for i in issues if i.sample_id
        }
        out.stats = {
            "issues_total": len(issues),
            "issues_by_code": {c.value: len(m) for c, m in sorted(grouped.items(), key=lambda kv: kv[0].value)},
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS,
                Coverage.SUPPORTED,
                detector=self.name,
                detector_version=self.version,
                assumptions=("annotation files and image files are both readable by the adapter",),
                limitations=(
                    "detects contradictions within the dataset, not semantic errors",
                    "cannot detect a consistent lie: an annotation set that is "
                    "internally coherent but describes the wrong reality is "
                    "structurally valid",
                ),
            )
        )
        return out
