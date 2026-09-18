"""The model assurance report.

Structurally parallel to :mod:`cvtrust.reporting.report` and sharing its
``RunContext``, ``Finding``, ``CoverageStatement`` and disposition machinery —
but with one section the dataset report does not have and needs:

The **assessment matrix**.

The brief's §18 argument is the reason.  A single "model trust = 72%" number is
strictly less informative than

::

    Identity:   MISMATCH
    Structure:  CONSISTENT
    Behaviour:  0.3% disagreement
    Parameter:  UNAVAILABLE
    Backdoor:   NOT_ASSESSED

because the second tells an analyst what to do next and the first does not.  So
the six assessment levels are carried as separate, separately-valued fields, and
nothing in this module ever combines them into one score.

The vocabulary is closed and excludes the word *safe*.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import digest_safe
from ..core.context import RunContext
from ..core.evidence import (
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    Disposition,
    Finding,
    Severity,
    utc_now_iso,
)
from ..core.hashing import sha256_canonical, short
from ..risk.coverage import CoverageStatement
from .report import DetectorReport, _strip_volatile

MODEL_REPORT_SCHEMA_VERSION = "1.0"


class AssessmentStatus(str, Enum):
    """The closed vocabulary for an assessment level.

    ``SAFE`` is deliberately absent and will never be added.  A model can only
    be assessed against the attacks and behaviours actually tested, so the
    strongest positive statement available is
    ``NO_ANOMALY_DETECTED`` — which is a statement about the tests, not about
    the model.
    """

    #: A cryptographic fact: digests match.
    VERIFIED = "VERIFIED"
    #: Tested, nothing found. Scoped to what was tested.
    NO_ANOMALY_DETECTED = "NO_ANOMALY_DETECTED"
    #: Structure or behaviour matches the reference.
    CONSISTENT = "CONSISTENT"
    #: A cryptographic fact: digests differ.
    MISMATCH = "MISMATCH"
    #: Measured deviation that warrants explanation.
    ANOMALOUS = "ANOMALOUS"
    #: Evidence that would be serious if it holds up.
    HIGH_RISK_INDICATOR = "HIGH_RISK_INDICATOR"
    #: The method needs white-box access the artifact does not give.
    REQUIRES_WHITE_BOX = "REQUIRES_WHITE_BOX"
    #: Not run, with a reason. Never to be read as "clean".
    NOT_ASSESSED = "NOT_ASSESSED"
    #: Run was attempted and could not complete.
    ASSESSMENT_UNAVAILABLE = "ASSESSMENT_UNAVAILABLE"


class AssessmentLevel(BaseModel):
    """One row of the assessment matrix."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: str
    status: AssessmentStatus
    detail: str
    reason: str | None = None
    detector: str | None = None
    evidence_keys: tuple[str, ...] = ()


class ModelAssessmentMatrix(BaseModel):
    """The six levels, kept separate on purpose.

    There is no ``overall_score`` field and there will not be one.  The roll-up
    below is a worst-case *label* with a named rationale, not an average: one
    confident HIGH-severity indicator among five clean levels is exactly the
    case that matters, and any mean would bury it.
    """

    model_config = ConfigDict(extra="forbid")

    identity: AssessmentLevel
    structure: AssessmentLevel
    parameters: AssessmentLevel
    behaviour: AssessmentLevel
    activation: AssessmentLevel
    trigger: AssessmentLevel

    def levels(self) -> list[AssessmentLevel]:
        return [
            self.identity, self.structure, self.parameters,
            self.behaviour, self.activation, self.trigger,
        ]


class ModelAssessmentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall: str
    rationale: str
    findings_total: int
    by_severity: dict[str, int]
    by_disposition: dict[str, int]
    by_attack_class: dict[str, int]
    assessed_levels: int
    unassessed_levels: int


class ModelAssuranceReport(BaseModel):
    """The machine-readable record of one model assessment."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = MODEL_REPORT_SCHEMA_VERSION
    evidence_schema_version: str = SCHEMA_VERSION
    report_id: str
    generated_at: str = Field(default_factory=utc_now_iso)
    module: str = "2: model forensics and backdoor assurance"

    run: RunContext
    model: dict[str, Any]
    reference: dict[str, Any] | None
    access: dict[str, Any]
    battery: dict[str, Any] | None
    configuration: dict[str, Any]
    calibration: dict[str, Any]
    disposition_policy: dict[str, Any]
    benchmark: dict[str, Any]

    assessment: ModelAssessmentMatrix
    summary: ModelAssessmentSummary
    findings: list[Finding]
    detectors: list[DetectorReport]
    coverage: CoverageStatement
    limitations: list[str]

    def stable_digest(self) -> str:
        """Digest over everything except timings and the artifact's location."""
        return sha256_canonical(
            digest_safe(_strip_volatile(self.model_dump(mode="json")))
        )


#: Global limitations printed on every model report.  Properties of the
#: approach, not of any particular model.
MODEL_GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "This report never states that a model is safe. A model is assessed only "
    "against the attacks and behaviours actually tested, under the access mode "
    "and battery recorded above. NO_ANOMALY_DETECTED is a statement about the "
    "tests that ran, not about the model.",
    "Backdoor coverage is limited to universal patch triggers in the declared "
    "family, plus — where gradients are available — triggers a Neural Cleanse "
    "optimisation can reconstruct within the recorded budget. Sample-specific "
    "and input-aware triggers, semantic backdoors, triggers that are large by "
    "design, and adaptive backdoors trained against these detectors are NOT "
    "assessed and are declared NOT_SUPPORTED in the coverage statement.",
    "Unusual weight statistics are reported as a parameter anomaly indicator and "
    "never as proof of a backdoor. No published result establishes that "
    "connection, and quantisation-aware training, unusual initialisation, weight "
    "decay and layer saturation all produce the same observation in clean models.",
    "Out-of-distribution behaviour is never treated as evidence of a backdoor. "
    "OOD probes are present in the battery to guard against exactly that error.",
    "Spectral signatures and activation clustering were published as "
    "training-set poisoning detectors and are applied here to the probe battery "
    "instead. They detect trigger-aligned separation in the model's "
    "representations; they do not detect that the supplier's training data was "
    "poisoned.",
    "Model metadata — declared architecture, producer, version strings — is "
    "supplied by the untrusted side and plays no part in any identity decision. "
    "Identity is SHA-256 over content, and nothing else.",
    "Where confidence is CALIBRATED, the underlying precision was measured on "
    "the synthetic model attack lab. That is a defensible lower bound on "
    "evidence quality for those scenarios, not an operational guarantee for "
    "models the system has never seen.",
    "Benchmark evaluation against NIST TrojAI or BackdoorBench is performed only "
    "if those artifacts have been vendored into a local directory. They are "
    "never downloaded, and their absence is reported as NOT_ASSESSED.",
)


def _overall(
    findings: list[Finding], matrix: ModelAssessmentMatrix
) -> tuple[str, str]:
    """Worst-case roll-up by explicit rule.

    Averaging is the wrong operation for security evidence, so this is a
    precedence chain over dispositions and severities, and it always names the
    coverage caveat.
    """
    caveat = (
        " This assessment covers only the levels marked assessed above and the "
        "attack classes declared SUPPORTED or PARTIAL in the coverage statement."
    )
    quarantine = [f for f in findings if f.disposition is Disposition.QUARANTINE]
    if quarantine:
        return (
            "QUARANTINE REQUIRED",
            f"{len(quarantine)} finding(s) meet the quarantine rule." + caveat,
        )

    high_risk = [
        level for level in matrix.levels()
        if level.status is AssessmentStatus.HIGH_RISK_INDICATOR
    ]
    if high_risk:
        return (
            "REVIEW REQUIRED — HIGH-RISK INDICATOR",
            f"{len(high_risk)} assessment level(s) report a high-risk indicator: "
            + ", ".join(level.level for level in high_risk) + "." + caveat,
        )

    severe = [
        f for f in findings
        if f.disposition is Disposition.REVIEW
        and SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.HIGH]
    ]
    if severe:
        return (
            "REVIEW REQUIRED",
            f"{len(severe)} high-severity finding(s) require analyst review before "
            "this model is relied on." + caveat,
        )

    review = [f for f in findings if f.disposition is Disposition.REVIEW]
    if review:
        return (
            "REVIEW RECOMMENDED",
            f"{len(review)} finding(s) warrant review; none met the quarantine rule."
            + caveat,
        )

    unassessed = [
        level for level in matrix.levels()
        if level.status in (
            AssessmentStatus.NOT_ASSESSED,
            AssessmentStatus.REQUIRES_WHITE_BOX,
            AssessmentStatus.ASSESSMENT_UNAVAILABLE,
        )
    ]
    if unassessed:
        return (
            "NO ANOMALY DETECTED — PARTIAL COVERAGE",
            f"No finding reached the review threshold, but {len(unassessed)} of 6 "
            "assessment level(s) could not be assessed: "
            + ", ".join(level.level for level in unassessed)
            + ". A level that was not assessed is an open question, not a clean "
            "result." + caveat,
        )

    return (
        "NO ANOMALY DETECTED",
        "Every assessment level ran and none produced an actionable finding."
        + caveat,
    )


def summarise_model(
    findings: list[Finding], matrix: ModelAssessmentMatrix
) -> ModelAssessmentSummary:
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_disposition: dict[str, int] = {d.value: 0 for d in Disposition}
    by_attack_class: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] += 1
        by_disposition[finding.disposition.value] += 1
        by_attack_class[finding.attack_class] = (
            by_attack_class.get(finding.attack_class, 0) + 1
        )

    unassessed = sum(
        1 for level in matrix.levels()
        if level.status in (
            AssessmentStatus.NOT_ASSESSED,
            AssessmentStatus.REQUIRES_WHITE_BOX,
            AssessmentStatus.ASSESSMENT_UNAVAILABLE,
        )
    )
    overall, rationale = _overall(findings, matrix)
    return ModelAssessmentSummary(
        overall=overall,
        rationale=rationale,
        findings_total=len(findings),
        by_severity=by_severity,
        by_disposition=by_disposition,
        by_attack_class=dict(sorted(by_attack_class.items())),
        assessed_levels=6 - unassessed,
        unassessed_levels=unassessed,
    )


def build_model_report(
    *,
    run: RunContext,
    model: dict[str, Any],
    reference: dict[str, Any] | None,
    access: dict[str, Any],
    battery: dict[str, Any] | None,
    configuration: dict[str, Any],
    calibration: dict[str, Any],
    disposition_policy: dict[str, Any],
    benchmark: dict[str, Any],
    assessment: ModelAssessmentMatrix,
    findings: list[Finding],
    detectors: list[DetectorReport],
    coverage: CoverageStatement,
    extra_limitations: list[str] | None = None,
) -> ModelAssuranceReport:
    ordered = sorted(findings, key=lambda f: f.sort_key())
    report = ModelAssuranceReport(
        report_id="",
        run=run,
        model=model,
        reference=reference,
        access=access,
        battery=battery,
        configuration=configuration,
        calibration=calibration,
        disposition_policy=disposition_policy,
        benchmark=benchmark,
        assessment=assessment,
        summary=summarise_model(ordered, assessment),
        findings=ordered,
        detectors=detectors,
        coverage=coverage,
        limitations=list(MODEL_GLOBAL_LIMITATIONS) + list(extra_limitations or []),
    )
    object.__setattr__(report, "report_id", f"MR-{short(report.stable_digest(), 16)}")
    return report
