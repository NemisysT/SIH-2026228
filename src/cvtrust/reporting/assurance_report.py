"""The pipeline assurance report — Module 4's machine-readable record.

Named ``PipelineAssuranceReport`` rather than ``AssuranceReport`` because
Module 1 already owns that name for a *dataset* report, and a pipeline
assessment is a different object: it has no dataset of its own, it has four
scopes, and it carries the findings of three other modules verbatim.

The schema follows one rule that is worth stating outright, because every
"unified risk dashboard" ever built has broken it:

    **The report preserves the underlying findings. It does not replace them
    with a summary.**

So ``source_findings`` carries every Module 1-4 finding exactly as its module
emitted it, ``evidence`` carries the normalised fusion view alongside, and
``decision`` carries the conclusion with lineage back to both.  An analyst who
distrusts the fusion can ignore it entirely and still have a complete record;
an analyst who trusts it can read the decision and follow one link per hop back
to an image.

There is no aggregate field of any kind, and there will not be one.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..assurance.decision import AssuranceDecision
from ..assurance.evidence import EvidenceGraph
from ..core.canonical import digest_safe
from ..core.context import RunContext
from ..core.evidence import SCHEMA_VERSION, Finding, utc_now_iso
from ..core.hashing import sha256_canonical, short
from ..risk.coverage import CapabilityStatement, CoverageStatement
from ..shift.characterize import ShiftAssessment
from .report import _strip_volatile

ASSURANCE_REPORT_SCHEMA_VERSION = "1.0"


class ScopeSummary(BaseModel):
    """One scope's headline, kept as its own row (brief §3).

    The four scopes are never merged into one status.  ``model suspicious +
    provenance valid`` and ``model clean + provenance invalid`` are both real
    and call for opposite actions, so they must be visibly different rows.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: str
    disposition: str
    governing_rule: str | None
    statement: str
    assessed: bool
    source_report_id: str | None = None
    findings: int = 0
    supporting_evidence: int = 0


class PipelineAssuranceReport(BaseModel):
    """The machine-readable record of one pipeline assurance run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = ASSURANCE_REPORT_SCHEMA_VERSION
    evidence_schema_version: str = SCHEMA_VERSION
    report_id: str
    generated_at: str = Field(default_factory=utc_now_iso)
    module: str = "4: distribution shift, evidence fusion and assurance"

    run: RunContext
    inputs: dict[str, Any] = Field(
        description="What was supplied, by digest, and what was not. The second "
        "half is load-bearing: a fusion over three inputs and a fusion over one "
        "must not look alike."
    )
    configuration: dict[str, Any]
    policy: dict[str, Any] = Field(
        description="The assurance rule table, verbatim. The rule an analyst "
        "reads here is the rule the code executed."
    )

    dataset_assurance: ScopeSummary | None = None
    model_assurance: ScopeSummary | None = None
    provenance_assurance: ScopeSummary | None = None
    distribution_assurance: ScopeSummary | None = None

    distribution_shift: ShiftAssessment | None = None

    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    evidence: EvidenceGraph
    #: Every upstream finding, verbatim and unmodified.
    source_findings: list[Finding] = Field(default_factory=list)

    decision: AssuranceDecision
    coverage: CoverageStatement
    capabilities: CapabilityStatement
    limitations: list[str] = Field(default_factory=list)

    def scopes(self) -> list[ScopeSummary]:
        return [
            s
            for s in (
                self.dataset_assurance,
                self.model_assurance,
                self.provenance_assurance,
                self.distribution_assurance,
            )
            if s is not None
        ]

    def stable_digest(self) -> str:
        """Digest over everything except timings and artifact locations.

        The same inputs, policy version, configuration, seed and software
        version must produce the same value on any machine. See
        :data:`cvtrust.core.context.DIGEST_EXCLUDED_FIELDS` for what is left out
        and why.
        """
        return sha256_canonical(
            digest_safe(_strip_volatile(self.model_dump(mode="json")))
        )


#: Global limitations printed on every pipeline assurance report.  Properties
#: of the approach, not of any particular pipeline.
ASSURANCE_GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "This report contains no trust score, no risk score and no aggregate number "
    "of any kind, and it will not acquire one. Dispositions follow from named "
    "rules over named evidence, and the rule table is printed above.",
    "The four assurance scopes are separate facts and are never combined into "
    "one. A cryptographically perfect provenance chain over a backdoored model "
    "is entirely possible, as is a forged record of a sound one, and this "
    "report keeps both possibilities visible (ADR-014).",
    "A distribution shift is not an attack. Terrain, season, sensor, "
    "illumination and collection-protocol changes produce the same signature "
    "and are the normal condition of an operational pipeline. No rule in this "
    "policy escalates on shift alone.",
    "Evidence independence is decided by a curated family table, printed in the "
    "evidence summary, not measured from data. Two detectors correlated in a "
    "way the table does not record would be counted as two phenomena.",
    "ACCEPT in any scope is a statement about the checks that ran in that "
    "scope, bounded by its own coverage statement. It is never a statement that "
    "an artifact is safe, authentic or uncompromised.",
    "A scope with no input is reported NOT_ASSESSED and listed in the "
    "decision's unassessed areas. A pipeline with major unassessed attack "
    "classes is not equivalent to a comprehensively assessed clean one and is "
    "not presented as equivalent here.",
    "The reference population used for distribution analysis is assumed "
    "representative and uncontaminated. Nothing in this system establishes "
    "either, and a contaminated reference makes a clean population look shifted "
    "and a shifted one look clean.",
)


def build_assurance_report(
    *,
    run: RunContext,
    inputs: dict[str, Any],
    configuration: dict[str, Any],
    policy: dict[str, Any],
    scope_summaries: dict[str, ScopeSummary | None],
    shift: ShiftAssessment | None,
    evidence: EvidenceGraph,
    evidence_summary: dict[str, Any],
    source_findings: list[Finding],
    decision: AssuranceDecision,
    coverage: CoverageStatement,
    capabilities: CapabilityStatement,
    extra_limitations: list[str] | None = None,
) -> PipelineAssuranceReport:
    report = PipelineAssuranceReport(
        report_id="",
        run=run,
        inputs=inputs,
        configuration=configuration,
        policy=policy,
        dataset_assurance=scope_summaries.get("dataset"),
        model_assurance=scope_summaries.get("model"),
        provenance_assurance=scope_summaries.get("provenance"),
        distribution_assurance=scope_summaries.get("distribution"),
        distribution_shift=shift,
        evidence_summary=evidence_summary,
        evidence=evidence,
        source_findings=sorted(source_findings, key=lambda f: f.sort_key()),
        decision=decision,
        coverage=coverage,
        capabilities=capabilities,
        limitations=list(ASSURANCE_GLOBAL_LIMITATIONS) + list(extra_limitations or []),
    )
    object.__setattr__(report, "report_id", f"AR-{short(report.stable_digest(), 16)}")
    return report


__all__ = [
    "ASSURANCE_REPORT_SCHEMA_VERSION", "ASSURANCE_GLOBAL_LIMITATIONS",
    "PipelineAssuranceReport", "ScopeSummary", "build_assurance_report",
]
