"""The assurance report: the machine-readable record of an analysis.

One artifact, two consumers.  The JSON is what Module 5's UI, the evaluation
harness and any downstream automation read; the Markdown/console rendering in
:mod:`cvtrust.reporting.render` is generated *from this object*, never assembled
separately, so the human and machine views cannot drift apart.

The report deliberately carries more than findings: the configuration hash, the
feature space, the disposition rule table, the calibration status, the coverage
statement and the run context.  A finding is only interpretable alongside the
conditions that produced it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import digest_safe
from ..core.context import DIGEST_EXCLUDED_FIELDS, RunContext
from ..core.evidence import (
    SEVERITY_ORDER,
    SCHEMA_VERSION,
    Disposition,
    Finding,
    Severity,
    utc_now_iso,
)
from ..core.hashing import sha256_canonical, short
from ..risk.coverage import CoverageStatement

REPORT_SCHEMA_VERSION = "1.0"


class DetectorReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    findings: int
    stats: dict[str, Any] = Field(default_factory=dict)


class AssessmentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall: str
    rationale: str
    findings_total: int
    by_severity: dict[str, int]
    by_disposition: dict[str, int]
    by_attack_class: dict[str, int]
    assets_affected: int
    contributors_affected: int


class AssuranceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = REPORT_SCHEMA_VERSION
    evidence_schema_version: str = SCHEMA_VERSION
    report_id: str
    generated_at: str = Field(default_factory=utc_now_iso)
    module: str = "1: dataset forensics"

    run: RunContext
    dataset: dict[str, Any]
    configuration: dict[str, Any]
    feature_space: dict[str, Any]
    calibration: dict[str, Any]
    disposition_policy: dict[str, Any]

    summary: AssessmentSummary
    findings: list[Finding]
    contributor_risk: list[dict[str, Any]]
    detectors: list[DetectorReport]
    coverage: CoverageStatement
    limitations: list[str]

    def stable_digest(self) -> str:
        """Digest over everything except timings and the dataset's location.

        This is what the determinism test compares: two runs over identical
        inputs must produce the same value, and a regression that perturbs any
        score, threshold or ordering changes it.  See
        :data:`cvtrust.core.context.DIGEST_EXCLUDED_FIELDS` for what is left
        out, and why.
        """
        return sha256_canonical(digest_safe(_strip_volatile(self.model_dump(mode="json"))))


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v)
            for k, v in value.items()
            if k not in DIGEST_EXCLUDED_FIELDS
        }
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


#: Global limitations, printed on every report.  These are properties of the
#: approach, not of any particular dataset, and an analyst who reads only the
#: findings needs to see them.
GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "This build implements Module 1 (dataset forensics) only. Model integrity, "
    "inference provenance and distribution-shift analysis are declared "
    "NOT_ASSESSED in the coverage statement, not silently omitted.",
    "Detection coverage is limited to the attack classes listed as SUPPORTED or "
    "PARTIAL in the coverage statement. A clean report is a statement about "
    "those classes and nothing else.",
    "Statistical findings identify patterns inconsistent with a stated null "
    "model. They are not proof of intent: an unfamiliar annotation guideline, a "
    "sensor change or a different collection protocol can produce the same "
    "signature as a deliberate attack.",
    "Out-of-distribution is never treated as equivalent to malicious.",
    "Where confidence is CALIBRATED, the underlying precision was measured on "
    "synthetic attack-lab scenarios. That is a defensible lower bound on "
    "evidence quality, not an operational guarantee for unseen imagery; "
    "recalibration against representative data is a deployment step.",
    "The default feature space is a deterministic classical descriptor chosen "
    "for air-gapped operation. A task-trained embedding would improve "
    "label-consistency and OOD sensitivity; measured recall in this build "
    "reflects the classical space.",
)


def summarise(findings: list[Finding]) -> AssessmentSummary:
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_disposition: dict[str, int] = {d.value: 0 for d in Disposition}
    by_attack_class: dict[str, int] = {}
    assets: set[str] = set()
    contributors: set[str] = set()

    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_disposition[finding.disposition.value] += 1
        by_attack_class[finding.attack_class] = (
            by_attack_class.get(finding.attack_class, 0) + 1
        )
        assets.add(finding.asset.key())
        if finding.contributor:
            contributors.add(finding.contributor)

    overall, rationale = _overall(findings)
    return AssessmentSummary(
        overall=overall,
        rationale=rationale,
        findings_total=len(findings),
        by_severity=by_severity,
        by_disposition=by_disposition,
        by_attack_class=dict(sorted(by_attack_class.items())),
        assets_affected=len(assets),
        contributors_affected=len(contributors),
    )


def _overall(findings: list[Finding]) -> tuple[str, str]:
    """Overall assessment by explicit rule, not by averaging scores.

    Averaging is the wrong operation for security evidence: one confident
    HIGH-severity finding among a thousand clean samples is exactly the case
    that matters, and any mean would bury it.  The roll-up is therefore a
    worst-case rule, and it always names the coverage caveat.
    """
    caveat = " Assessment applies only to the attack classes declared SUPPORTED or PARTIAL."
    quarantine = [f for f in findings if f.disposition is Disposition.QUARANTINE]
    if quarantine:
        return (
            "QUARANTINE REQUIRED",
            f"{len(quarantine)} finding(s) meet the quarantine rule "
            f"(severity and calibrated confidence above policy thresholds)." + caveat,
        )
    high = [
        f for f in findings
        if f.disposition is Disposition.REVIEW
        and SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.HIGH]
    ]
    if high:
        return (
            "REVIEW REQUIRED",
            f"{len(high)} high-severity finding(s) require analyst review before "
            "this dataset is used." + caveat,
        )
    review = [f for f in findings if f.disposition is Disposition.REVIEW]
    if review:
        return (
            "REVIEW RECOMMENDED",
            f"{len(review)} finding(s) warrant review; none met the quarantine rule."
            + caveat,
        )
    return (
        "NO ACTIONABLE FINDINGS",
        "No finding reached the review threshold." + caveat,
    )


def build_report(
    *,
    run: RunContext,
    dataset: dict[str, Any],
    configuration: dict[str, Any],
    feature_space: dict[str, Any],
    calibration: dict[str, Any],
    disposition_policy: dict[str, Any],
    findings: list[Finding],
    contributor_risk: list[dict[str, Any]],
    detectors: list[DetectorReport],
    coverage: CoverageStatement,
    extra_limitations: list[str] | None = None,
) -> AssuranceReport:
    ordered = sorted(findings, key=lambda f: f.sort_key())
    summary = summarise(ordered)
    report = AssuranceReport(
        report_id="",
        run=run,
        dataset=dataset,
        configuration=configuration,
        feature_space=feature_space,
        calibration=calibration,
        disposition_policy=disposition_policy,
        summary=summary,
        findings=ordered,
        contributor_risk=contributor_risk,
        detectors=detectors,
        coverage=coverage,
        limitations=list(GLOBAL_LIMITATIONS) + list(extra_limitations or []),
    )
    object.__setattr__(report, "report_id", f"R-{short(report.stable_digest(), 16)}")
    return report
