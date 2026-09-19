"""Evidence normalisation and the evidence graph.

Normalisation here means *adding a view*, never rewriting the original.  Every
:class:`~cvtrust.core.evidence.Finding` that Modules 1-4 produced is carried
into the assurance report verbatim; what this module builds alongside is a
:class:`NormalizedEvidence` record per finding, which adds exactly the fields
fusion needs and which the finding schema does not carry:

* ``source_module`` / ``source_report_id`` — which assessment produced it;
* ``evidence_class`` — data / model / provenance / distribution / context, kept
  distinct because the brief forbids collapsing them (§3);
* ``dependency_group`` — the phenomenon family (:mod:`.families`);
* ``confounded_by`` — families whose presence would explain this evidence as a
  side effect;
* ``supports`` — whether this evidence clears the configured floors and may
  therefore drive a disposition, or is context only.

Nothing here recomputes a confidence, re-derives a severity or re-dispositions
a finding.  A Module 3 cryptographic failure arrives ``DETERMINISTIC`` at 1.0
and leaves ``DETERMINISTIC`` at 1.0; it is never turned into "0.94 confidence"
so that it can be averaged with a calibrated detector's output, because that
average would be a category error with a decimal point (ADR-014).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import (
    SEVERITY_ORDER,
    AssetRef,
    Category,
    ConfidenceBasis,
    Coverage,
    Disposition,
    Finding,
    Severity,
)
from ..core.hashing import sha256_canonical, short
from .families import EvidenceClass, EvidenceFamily, classify, confounders_of

EVIDENCE_SCHEMA_VERSION = "1.0"


class EvidenceLineage(BaseModel):
    """Where a piece of evidence came from, one hop at a time."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    source_module: int
    source_detector: str
    source_detector_version: str
    source_report_id: str | None = None
    source_run_id: str | None = None
    #: Sample ids, peer findings or record ids the underlying evidence pointed
    #: at.  This is what lets an analyst walk from "QUARANTINE" back to an image
    #: without reading any source code.
    refs: tuple[str, ...] = ()


class NormalizedEvidence(BaseModel):
    """One finding, in the shape the fusion engine consumes.

    Immutable, like the finding it describes.  The original is not modified and
    is carried separately in the report.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    evidence_id: str
    finding_id: str

    source_module: int
    source_detector: str
    source_detector_version: str

    asset: AssetRef
    contributor: str | None
    category: Category
    evidence_class: EvidenceClass
    attack_class: str
    title: str

    severity: Severity
    confidence: float
    confidence_basis: ConfidenceBasis
    coverage: Coverage
    source_disposition: Disposition
    source_disposition_rule: str

    #: The raw measured values behind the claim, lifted from the finding's
    #: evidence items.  Carried so that the assurance report is readable on its
    #: own: an analyst should not need to cross-reference four other JSON files
    #: to see why a rule fired.
    raw_observation: dict[str, Any] = Field(default_factory=dict)

    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    lineage: EvidenceLineage

    dependency_group: EvidenceFamily
    confounded_by: tuple[EvidenceFamily, ...] = ()
    #: Set during graph construction: confounders that are actually present in
    #: this run.  Non-empty means this evidence is kept and reported but does
    #: not count as independent corroboration.
    active_confounders: tuple[EvidenceFamily, ...] = ()

    #: Whether this evidence clears the configured severity/confidence floors.
    #: Context evidence stays in the report and in the lineage; it does not
    #: drive a disposition.
    supports: bool = True
    support_reason: str = ""

    def independent(self) -> bool:
        """Usable as independent corroboration for a policy rule."""
        return self.supports and not self.active_confounders

    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def sort_key(self) -> tuple[int, float, str]:
        return (-self.severity_rank(), -self.confidence, self.evidence_id)


class EvidenceGroup(BaseModel):
    """All evidence in one family: one phenomenon, however many findings.

    ``corroboration`` counts the *distinct detectors* inside the family, not
    the findings.  Two hundred near-duplicate findings from one detector are
    one detector's opinion repeated two hundred times; two detectors agreeing
    is a genuinely stronger observation about the same phenomenon.  Neither
    makes the family count as two concerns.
    """

    model_config = ConfigDict(extra="forbid")

    family: EvidenceFamily
    evidence_class: EvidenceClass
    evidence_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    detectors: tuple[str, ...]
    corroboration: int
    max_severity: Severity
    max_confidence: float
    bases: tuple[ConfidenceBasis, ...]
    supporting: int
    context_only: int
    confounded: bool
    active_confounders: tuple[EvidenceFamily, ...] = ()
    assets: tuple[str, ...] = ()
    contributors: tuple[str, ...] = ()

    def counts_as_independent_support(self) -> bool:
        return self.supporting > 0 and not self.confounded


class EvidenceGraph(BaseModel):
    """The normalised evidence, grouped by family, with the tables it used.

    Called a graph because that is what it is — evidence nodes, family edges,
    confounding edges and lineage edges back to the source findings — but it is
    stored as the three adjacency views an analyst and a policy engine actually
    query, rather than as a generic node/edge soup nobody can read in a report.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = EVIDENCE_SCHEMA_VERSION
    evidence: list[NormalizedEvidence] = Field(default_factory=list)
    groups: list[EvidenceGroup] = Field(default_factory=list)
    #: Families whose phenomenon is present in this run, used to mark
    #: confounded evidence.  Derived, and reported, so the marking is auditable.
    active_phenomena: list[EvidenceFamily] = Field(default_factory=list)
    floors: dict[str, Any] = Field(default_factory=dict)

    def group(self, family: EvidenceFamily) -> EvidenceGroup | None:
        for entry in self.groups:
            if entry.family is family:
                return entry
        return None

    def independent_families(self) -> list[EvidenceFamily]:
        """Families contributing one unit of independent support each."""
        return [g.family for g in self.groups if g.counts_as_independent_support()]

    def families_of_class(self, evidence_class: EvidenceClass) -> list[EvidenceFamily]:
        return [g.family for g in self.groups if g.evidence_class is evidence_class]

    def by_family(self, family: EvidenceFamily) -> list[NormalizedEvidence]:
        return [e for e in self.evidence if e.dependency_group is family]

    def by_class(self, evidence_class: EvidenceClass) -> list[NormalizedEvidence]:
        return [e for e in self.evidence if e.evidence_class is evidence_class]

    def supporting_of_class(
        self, evidence_class: EvidenceClass
    ) -> list[NormalizedEvidence]:
        return [e for e in self.by_class(evidence_class) if e.supports]


def _observation_of(finding: Finding) -> dict[str, Any]:
    """Lift the finding's measured values into one mapping, keyed by kind.

    Kinds repeat across a finding's evidence items only rarely; where they do,
    the later item is suffixed rather than overwriting, because an observation
    silently replaced by another is exactly the kind of lossy normalisation
    this module exists not to do.
    """
    out: dict[str, Any] = {}
    for item in finding.evidence:
        key = item.kind
        suffix = 2
        while key in out:
            key = f"{item.kind}#{suffix}"
            suffix += 1
        out[key] = {"statement": item.statement, **dict(item.observation)}
    return out


def normalise(
    finding: Finding,
    *,
    source_module: int,
    source_report_id: str | None = None,
    source_run_id: str | None = None,
) -> NormalizedEvidence:
    """Build the fusion view of one finding.  The finding is not touched."""
    family, evidence_class = classify(finding.attack_class)
    refs: list[str] = []
    for item in finding.evidence:
        for ref in item.refs:
            if ref not in refs:
                refs.append(ref)
    # Content-addressed, like a finding id (ADR-003): the same finding from the
    # same report always normalises to the same evidence id, so two fusion runs
    # over the same inputs are diffable.
    evidence_id = "E-" + short(
        sha256_canonical(
            {
                "finding_id": finding.finding_id,
                "source_module": source_module,
                "source_report_id": source_report_id,
            }
        ),
        12,
    )
    return NormalizedEvidence(
        evidence_id=evidence_id,
        finding_id=finding.finding_id,
        source_module=source_module,
        source_detector=finding.method,
        source_detector_version=finding.method_version,
        asset=finding.asset,
        contributor=finding.contributor,
        category=finding.category,
        evidence_class=evidence_class,
        attack_class=finding.attack_class,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        confidence_basis=finding.confidence_basis,
        coverage=finding.coverage,
        source_disposition=finding.disposition,
        source_disposition_rule=finding.disposition_rule,
        raw_observation=_observation_of(finding),
        assumptions=finding.assumptions,
        limitations=finding.limitations,
        lineage=EvidenceLineage(
            finding_id=finding.finding_id,
            source_module=source_module,
            source_detector=finding.method,
            source_detector_version=finding.method_version,
            source_report_id=source_report_id,
            source_run_id=source_run_id,
            refs=tuple(refs[:64]),
        ),
        dependency_group=family,
        confounded_by=confounders_of(family),
    )


def _support_decision(
    evidence: NormalizedEvidence,
    *,
    min_severity: Severity,
    min_confidence: float,
) -> tuple[bool, str]:
    """Does this evidence clear the floors to drive a disposition?

    Deterministic evidence is exempt from the confidence floor.  A SHA-256
    mismatch's "confidence 1.0" is not a measurement on the same scale as a
    calibrated detector's 0.72, and applying a confidence threshold to it would
    imply it is.
    """
    if evidence.coverage in (Coverage.NOT_ASSESSED, Coverage.NOT_SUPPORTED):
        return False, (
            "coverage is "
            f"{evidence.coverage.value}: the check did not run, so this is a "
            "visible gap rather than support for a conclusion"
        )
    if evidence.severity_rank() < SEVERITY_ORDER[min_severity]:
        return False, (
            f"severity {evidence.severity.value} is below the corroboration "
            f"floor {min_severity.value}; kept as context"
        )
    if (
        evidence.confidence_basis is not ConfidenceBasis.DETERMINISTIC
        and evidence.confidence < min_confidence
    ):
        return False, (
            f"confidence {evidence.confidence:.2f} is below the corroboration "
            f"floor {min_confidence:.2f}; kept as context"
        )
    return True, "clears the corroboration floors"


def build_graph(
    evidence: Iterable[NormalizedEvidence],
    *,
    min_severity: Severity = Severity.MEDIUM,
    min_confidence: float = 0.30,
    extra_active_phenomena: Sequence[EvidenceFamily] = (),
) -> EvidenceGraph:
    """Group evidence by family and mark what is confounded.

    ``extra_active_phenomena`` lets the caller declare a phenomenon that is
    present in the run without having produced a *supporting* finding — the
    case that matters is a population shift observed at INFO severity because
    the declared context explains it.  That shift is still real, still makes
    label neighbourhoods unrepresentative, and must still confound the label
    family, even though it raised no actionable finding of its own.
    """
    items = list(evidence)
    decided: list[NormalizedEvidence] = []
    for item in items:
        supports, reason = _support_decision(
            item, min_severity=min_severity, min_confidence=min_confidence
        )
        decided.append(item.model_copy(update={"supports": supports, "support_reason": reason}))

    present: set[EvidenceFamily] = set(extra_active_phenomena)
    for item in decided:
        if item.supports:
            present.add(item.dependency_group)

    marked: list[NormalizedEvidence] = []
    for item in decided:
        active = tuple(
            sorted(
                (f for f in item.confounded_by if f in present),
                key=lambda f: f.value,
            )
        )
        marked.append(item.model_copy(update={"active_confounders": active}))

    groups: dict[EvidenceFamily, list[NormalizedEvidence]] = {}
    for item in marked:
        groups.setdefault(item.dependency_group, []).append(item)

    built: list[EvidenceGroup] = []
    for family in sorted(groups, key=lambda f: f.value):
        members = sorted(groups[family], key=lambda e: e.sort_key())
        detectors = tuple(sorted({m.source_detector for m in members}))
        supporting = [m for m in members if m.supports]
        confounded = bool(supporting) and all(m.active_confounders for m in supporting)
        active = tuple(
            sorted({f for m in members for f in m.active_confounders}, key=lambda f: f.value)
        )
        built.append(
            EvidenceGroup(
                family=family,
                evidence_class=members[0].evidence_class,
                evidence_ids=tuple(m.evidence_id for m in members),
                finding_ids=tuple(m.finding_id for m in members),
                detectors=detectors,
                corroboration=len({m.source_detector for m in supporting}),
                max_severity=max(members, key=lambda m: m.severity_rank()).severity,
                max_confidence=max(m.confidence for m in members),
                bases=tuple(sorted({m.confidence_basis.value for m in members})),  # type: ignore[arg-type]
                supporting=len(supporting),
                context_only=len(members) - len(supporting),
                confounded=confounded,
                active_confounders=active,
                assets=tuple(sorted({m.asset.key() for m in members})[:32]),
                contributors=tuple(sorted({m.contributor for m in members if m.contributor})),
            )
        )

    return EvidenceGraph(
        evidence=sorted(marked, key=lambda e: e.sort_key()),
        groups=built,
        active_phenomena=sorted(present, key=lambda f: f.value),
        floors={
            "corroboration_min_severity": min_severity.value,
            "corroboration_min_confidence": min_confidence,
            "deterministic_exempt_from_confidence_floor": True,
            "note": "evidence below a floor stays in the report and in the "
            "lineage; it does not drive a disposition",
        },
    )


def normalise_all(
    findings: Iterable[Finding],
    *,
    source_module: int,
    source_report_id: str | None = None,
    source_run_id: str | None = None,
) -> list[NormalizedEvidence]:
    return [
        normalise(
            finding,
            source_module=source_module,
            source_report_id=source_report_id,
            source_run_id=source_run_id,
        )
        for finding in findings
    ]


def summarise_evidence(graph: EvidenceGraph) -> dict[str, Any]:
    """Counts an analyst reads first, none of which is a score."""
    by_class: dict[str, int] = {c.value: 0 for c in EvidenceClass}
    by_basis: dict[str, int] = {b.value: 0 for b in ConfidenceBasis}
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for item in graph.evidence:
        by_class[item.evidence_class.value] += 1
        by_basis[item.confidence_basis.value] += 1
        by_severity[item.severity.value] += 1
    return {
        "total": len(graph.evidence),
        "supporting": sum(1 for e in graph.evidence if e.supports),
        "context_only": sum(1 for e in graph.evidence if not e.supports),
        "confounded": sum(1 for e in graph.evidence if e.active_confounders),
        "by_evidence_class": by_class,
        "by_confidence_basis": by_basis,
        "by_severity": by_severity,
        "families_present": [g.family.value for g in graph.groups],
        "independent_families": [f.value for f in graph.independent_families()],
        "independent_family_count": len(graph.independent_families()),
        "note": "independent_family_count is a count of distinct phenomena with "
        "supporting, unconfounded evidence. It is not a score and is not "
        "combined with severity or confidence into one.",
    }


__all__ = [
    "EVIDENCE_SCHEMA_VERSION", "EvidenceLineage", "NormalizedEvidence",
    "EvidenceGroup", "EvidenceGraph", "normalise", "normalise_all",
    "build_graph", "summarise_evidence",
]
