"""The assurance decision: what the system concluded, and why, and what it did not.

One object, and the governing principle of the whole module is legible in its
field list.  A decision here must be able to say:

    we observed X, because of evidence Y, with confidence basis Z;
    however, A and B were not assessed.

so it carries ``supporting_evidence``, ``contradicting_evidence`` and
``unassessed_areas`` as *peers*.  A schema in which the gaps are a footnote is a
schema that will produce confident-looking reports about pipelines nobody
examined.

There is no ``score`` field, no ``risk`` field and no ``trust`` field.  The
closest thing to a summary number in this object is
``independent_family_count``, which is a count of distinct phenomena with
supporting unconfounded evidence — and its own documentation says it is not a
score and is never combined with anything.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import ConfidenceBasis, Severity
from .evidence import EvidenceGraph, NormalizedEvidence
from .policy import AssuranceDisposition, RuleOutcome, Scope, ScopeDecision

DECISION_SCHEMA_VERSION = "1.0"


class EvidenceReference(BaseModel):
    """A pointer from the decision back to one piece of evidence.

    Deliberately not a copy of the evidence: the full normalised record and the
    original finding both live in the report, and duplicating them here would
    create two versions of the same fact that could drift.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    finding_id: str
    source_module: int
    source_detector: str
    attack_class: str
    evidence_class: str
    dependency_group: str
    severity: Severity
    confidence: float
    confidence_basis: ConfidenceBasis
    title: str
    asset: str
    contributor: str | None = None
    confounded_by: tuple[str, ...] = ()
    role: str = Field(
        description="Why this reference is attached: 'supporting' (a rule fired "
        "on it), 'context' (below the corroboration floor), or 'contradicting' "
        "(an assessed scope that produced no concern)."
    )

    @classmethod
    def of(cls, evidence: NormalizedEvidence, role: str) -> "EvidenceReference":
        return cls(
            evidence_id=evidence.evidence_id,
            finding_id=evidence.finding_id,
            source_module=evidence.source_module,
            source_detector=evidence.source_detector,
            attack_class=evidence.attack_class,
            evidence_class=evidence.evidence_class.value,
            dependency_group=evidence.dependency_group.value,
            severity=evidence.severity,
            confidence=evidence.confidence,
            confidence_basis=evidence.confidence_basis,
            title=evidence.title,
            asset=evidence.asset.key(),
            contributor=evidence.contributor,
            confounded_by=tuple(f.value for f in evidence.active_confounders),
            role=role,
        )


class UnassessedArea(BaseModel):
    """Something the run did not examine, and what it would take to examine it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    area: str
    kind: str = Field(description="'scope', 'attack_class' or 'capability'.")
    reason: str
    remedy: str | None = None


class LineageNode(BaseModel):
    """One step of the decision's explanation tree.

    The tree is flat on purpose: ``decision -> rule -> finding -> detector`` is
    three hops, and an analyst following it in a terminal or a table needs rows,
    not a nested document.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    rule_id: str
    scope: Scope
    disposition: AssuranceDisposition
    finding_id: str | None = None
    evidence_id: str | None = None
    source_module: int | None = None
    source_detector: str | None = None
    source_report_id: str | None = None
    detail: str


class AssuranceDecision(BaseModel):
    """The structured conclusion of one pipeline assurance run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = DECISION_SCHEMA_VERSION
    decision_id: str
    disposition: AssuranceDisposition
    policy_version: str
    summary: str
    rationale: str

    asset_scope: dict[str, Any] = Field(
        description="What this decision is about: which dataset, model, log and "
        "reference population, by digest."
    )
    scopes: list[ScopeDecision] = Field(default_factory=list)
    fired_rules: list[RuleOutcome] = Field(default_factory=list)

    supporting_evidence: list[EvidenceReference] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceReference] = Field(default_factory=list)
    context_evidence: list[EvidenceReference] = Field(default_factory=list)
    unassessed_areas: list[UnassessedArea] = Field(default_factory=list)

    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    confidence_summary: dict[str, Any] = Field(default_factory=dict)
    severity_summary: dict[str, Any] = Field(default_factory=dict)
    conflicts: list[str] = Field(default_factory=list)

    lineage: list[LineageNode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    run_context: dict[str, Any] = Field(default_factory=dict)

    def scope_decision(self, scope: Scope) -> ScopeDecision | None:
        for entry in self.scopes:
            if entry.scope is scope:
                return entry
        return None


def confidence_summary(graph: EvidenceGraph) -> dict[str, Any]:
    """Confidence reported per basis, never pooled into one number.

    Pooling is the specific failure ADR-006 and ADR-014 exist to prevent: a
    cryptographic fact at 1.0 and a calibrated detector at 0.72 are not two
    samples of the same quantity, and their mean is not a quantity at all.  So
    this reports the bases present, the strongest evidence within each, and
    says in the payload that it is not a combination.
    """
    per_basis: dict[str, Any] = {}
    for basis in ConfidenceBasis:
        members = [e for e in graph.evidence if e.confidence_basis is basis]
        if not members:
            continue
        supporting = [e for e in members if e.supports]
        per_basis[basis.value] = {
            "count": len(members),
            "supporting": len(supporting),
            "max_confidence": max(e.confidence for e in members),
            "min_confidence": min(e.confidence for e in members),
        }
    return {
        "by_basis": per_basis,
        "deterministic_present": ConfidenceBasis.DETERMINISTIC.value in per_basis,
        "uncalibrated_present": (
            ConfidenceBasis.HEURISTIC_UNCALIBRATED.value in per_basis
        ),
        "note": "confidences are reported per basis and are never pooled. A "
        "cryptographic fact and a calibrated detector score are different kinds "
        "of number; their mean is not a number about anything.",
    }


def severity_summary(graph: EvidenceGraph) -> dict[str, Any]:
    """Severity reported independently of confidence (brief §17)."""
    counts = {s.value: 0 for s in Severity}
    for item in graph.evidence:
        counts[item.severity.value] += 1
    highest = max(
        (e for e in graph.evidence), key=lambda e: e.severity_rank(), default=None
    )
    return {
        "by_severity": counts,
        "highest": highest.severity.value if highest else None,
        "highest_finding_id": highest.finding_id if highest else None,
        "note": "severity answers 'how consequential if true' and confidence "
        "answers 'how sure are we'. Neither is derived from the other: a "
        "deterministic digest mismatch can be LOW severity at confidence 1.0, "
        "and an uncalibrated backdoor indicator can be HIGH severity at 0.45.",
    }


__all__ = [
    "DECISION_SCHEMA_VERSION", "AssuranceDecision", "EvidenceReference",
    "UnassessedArea", "LineageNode", "confidence_summary", "severity_summary",
]
