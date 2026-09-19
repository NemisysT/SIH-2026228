"""Fusion: normalise, group, evaluate, explain.

The four steps are kept separate and in this order for a reason each:

1. **normalise** — add the fusion view of every finding without touching the
   finding.  Modules 1-4 emit the same schema, so this step is mechanical; what
   it adds is the source module, the evidence class and the phenomenon family.
2. **group** — collapse findings into phenomenon families and mark the ones
   whose confounding phenomenon is actually present.  This is the step that
   stops three detectors reacting to one domain shift from becoming three
   attacks.
3. **evaluate** — run the rule table over the grouped evidence.  The rules can
   only see what step 2 produced, so a rule cannot accidentally count two
   correlated findings as independent: the graph has already decided what is
   independent, and it did so from a published table rather than from a
   coefficient.
4. **explain** — build the lineage, the unassessed areas and the summaries, so
   the decision can be read without the source code.

``FusionInputs`` is deliberately all-optional.  Every real deployment is
missing something — a model the analyst never received, a log the operator did
not export, a reference population nobody defined — and the only honest response
to a missing input is ``NOT_ASSESSED`` in that scope.  Making the inputs
required would force a caller to fabricate one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..core.config import Config
from ..core.evidence import Coverage, Finding, Severity
from ..core.hashing import sha256_canonical, short
from ..risk.coverage import (
    ATTACK_CLASS_REGISTRY,
    CapabilityEntry,
    CapabilityStatement,
    CoverageEntry,
    CoverageStatement,
    capability_entry,
)
from ..shift.characterize import ShiftAssessment, ShiftVerdict
from .decision import (
    AssuranceDecision,
    EvidenceReference,
    LineageNode,
    UnassessedArea,
    confidence_summary,
    severity_summary,
)
from .evidence import (
    EvidenceGraph,
    NormalizedEvidence,
    build_graph,
    normalise_all,
    summarise_evidence,
)
from .families import EvidenceClass, EvidenceFamily, describe_families
from .policy import (
    AssuranceDisposition,
    AssurancePolicyEngine,
    PolicyState,
    Scope,
    ScopeDecision,
    overall,
)


@dataclass
class ModuleInput:
    """One upstream assessment, with enough identity to be cited."""

    module: int
    findings: list[Finding] = field(default_factory=list)
    report_id: str | None = None
    run_id: str | None = None
    coverage: CoverageStatement | None = None
    #: Free-form identity of what was assessed: dataset digest, model digests,
    #: log head digest.  Carried into the decision's ``asset_scope``.
    asset: dict[str, Any] = field(default_factory=dict)
    #: Whether this input was actually supplied.  Present as a separate flag
    #: because an assessment that ran and found nothing is not the same thing as
    #: an assessment that never ran, and both arrive here as an empty finding
    #: list.
    supplied: bool = True


@dataclass
class FusionInputs:
    """Everything the fusion engine may be given.  All of it optional."""

    dataset: ModuleInput | None = None
    model: ModuleInput | None = None
    provenance: ModuleInput | None = None
    shift: ShiftAssessment | None = None
    shift_findings: list[Finding] = field(default_factory=list)

    def modules(self) -> list[ModuleInput]:
        return [m for m in (self.dataset, self.model, self.provenance) if m is not None]

    def supplied_scopes(self) -> dict[Scope, bool]:
        return {
            Scope.DATASET: self.dataset is not None and self.dataset.supplied,
            Scope.MODEL: self.model is not None and self.model.supplied,
            Scope.PROVENANCE: self.provenance is not None and self.provenance.supplied,
            Scope.DISTRIBUTION: self.shift is not None,
        }


@dataclass
class FusionResult:
    graph: EvidenceGraph
    decision: AssuranceDecision
    coverage: CoverageStatement
    capabilities: CapabilityStatement
    source_findings: list[Finding]
    evidence_summary: dict[str, Any]


#: Scope -> the remedy an analyst would apply to close it.  Held here rather
#: than inside a rule because it is operational advice, not policy: it says what
#: to go and get, and it must not read as though the gap changed the outcome.
_REMEDY: dict[Scope, str] = {
    Scope.DATASET: "run `cvtrust dataset scan` over the training or operating "
    "corpus and supply its JSON report",
    Scope.MODEL: "run `cvtrust model assess` against a trusted reference model "
    "and supply its JSON report",
    Scope.PROVENANCE: "run `cvtrust provenance verify-log` with a trust store "
    "and supply its JSON report",
    Scope.DISTRIBUTION: "declare a reference population and run "
    "`cvtrust assurance shift`",
}


def fuse(
    inputs: FusionInputs,
    config: Config,
    *,
    policy: AssurancePolicyEngine | None = None,
    run_context: dict[str, Any] | None = None,
) -> FusionResult:
    """Normalise, group, evaluate and explain.  Deterministic throughout."""
    engine = policy or AssurancePolicyEngine()

    # -- 1. normalise ---------------------------------------------------
    normalized: list[NormalizedEvidence] = []
    source_findings: list[Finding] = []
    for module_input in inputs.modules():
        if not module_input.supplied:
            continue
        normalized.extend(
            normalise_all(
                module_input.findings,
                source_module=module_input.module,
                source_report_id=module_input.report_id,
                source_run_id=module_input.run_id,
            )
        )
        source_findings.extend(module_input.findings)
    if inputs.shift is not None:
        normalized.extend(
            normalise_all(
                inputs.shift_findings,
                source_module=4,
                source_report_id=inputs.shift.assessment_id,
                source_run_id=None,
            )
        )
        source_findings.extend(inputs.shift_findings)

    # -- 2. group -------------------------------------------------------
    #
    # A shift that the declared context explains raises only an INFO finding, so
    # it never clears the corroboration floor and would not mark the family as
    # present.  It is still a real phenomenon that makes label neighbourhoods
    # unrepresentative, so it is declared active here explicitly.  Getting this
    # wrong in the other direction — letting an explained shift corroborate a
    # manipulation rule — is precisely what the family table prevents; getting it
    # wrong this way would let an explained shift quietly stop confounding the
    # label family, which is the more dangerous mistake.
    extra_active: list[EvidenceFamily] = []
    if inputs.shift is not None and inputs.shift.shift_observed():
        extra_active.append(EvidenceFamily.DISTRIBUTION_SHIFT)

    graph = build_graph(
        normalized,
        min_severity=Severity(config.assurance.corroboration_min_severity),
        min_confidence=config.assurance.corroboration_min_confidence,
        extra_active_phenomena=extra_active,
    )

    # -- 3. evaluate ----------------------------------------------------
    coverage = _coverage(inputs)
    gaps = tuple(
        entry.attack_class
        for entry in coverage.entries
        if entry.coverage in (Coverage.NOT_ASSESSED, Coverage.NOT_SUPPORTED)
    )
    state = PolicyState(
        graph=graph,
        shift=inputs.shift,
        inputs=inputs.supplied_scopes(),
        coverage_gaps=gaps,
        accept_explained_shift=config.assurance.accept_explained_shift,
    )
    scopes = engine.evaluate(state)
    disposition, rationale = overall(scopes)

    # -- 4. explain -----------------------------------------------------
    fired = sorted(
        (outcome for scope in scopes for outcome in scope.fired_rules),
        key=lambda o: o.rule_id,
    )
    cited = {eid for outcome in fired for eid in outcome.evidence_ids}
    supporting = [
        EvidenceReference.of(e, "supporting")
        for e in graph.evidence
        if e.evidence_id in cited
    ]
    context = [
        EvidenceReference.of(e, "context")
        for e in graph.evidence
        if e.evidence_id not in cited
    ]
    contradicting = _contradicting(graph, state)

    decision_payload = {
        "policy_version": engine.version,
        "disposition": disposition.value,
        "scopes": [
            {"scope": s.scope.value, "disposition": s.disposition.value,
             "rule": s.governing_rule}
            for s in scopes
        ],
        "evidence": sorted(e.evidence_id for e in graph.evidence),
    }
    decision_id = "D-" + short(sha256_canonical(decision_payload), 12)

    decision = AssuranceDecision(
        decision_id=decision_id,
        disposition=disposition,
        policy_version=engine.version,
        summary=_summary(disposition, scopes, graph),
        rationale=rationale,
        asset_scope=_asset_scope(inputs),
        scopes=scopes,
        fired_rules=fired,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        context_evidence=context,
        unassessed_areas=_unassessed(inputs, scopes, coverage),
        coverage_summary=_coverage_summary(coverage, scopes),
        confidence_summary=confidence_summary(graph),
        severity_summary=severity_summary(graph),
        conflicts=[
            outcome.statement for outcome in fired if outcome.rule_id.startswith("RULE-CONFLICT")
        ],
        lineage=_lineage(decision_id, scopes, graph),
        limitations=list(ASSURANCE_LIMITATIONS),
        run_context=run_context or {},
    )

    return FusionResult(
        graph=graph,
        decision=decision,
        coverage=coverage,
        capabilities=_capabilities(inputs, graph),
        source_findings=source_findings,
        evidence_summary=summarise_evidence(graph) | {"families": describe_families()},
    )


# ---------------------------------------------------------------------------
# Explanation builders
# ---------------------------------------------------------------------------


def _summary(
    disposition: AssuranceDisposition,
    scopes: Sequence[ScopeDecision],
    graph: EvidenceGraph,
) -> str:
    """One sentence that never overclaims in either direction."""
    per_scope = ", ".join(
        f"{s.scope.value}={s.disposition.value}" for s in scopes if s.scope is not Scope.PIPELINE
    )
    families = len(graph.independent_families())
    if disposition is AssuranceDisposition.NOT_ASSESSED:
        return (
            "NOT ASSESSED — no assurance scope had the inputs it needed. "
            f"Scopes: {per_scope}."
        )
    if disposition is AssuranceDisposition.QUARANTINE:
        return (
            f"QUARANTINE — at least one scope reports evidence that meets the "
            f"quarantine standard. Scopes: {per_scope}. "
            f"{families} distinct phenomenon/phenomena carry supporting, "
            "unconfounded evidence."
        )
    if disposition is AssuranceDisposition.REVIEW:
        return (
            f"REVIEW — evidence exists that an analyst should examine, and none "
            f"of it meets the quarantine standard. Scopes: {per_scope}. "
            f"{families} distinct phenomenon/phenomena carry supporting, "
            "unconfounded evidence."
        )
    return (
        "NO ACTIONABLE FINDINGS — every assessed scope ran and none produced "
        f"evidence above the corroboration floor. Scopes: {per_scope}. This "
        "covers only the attack classes declared SUPPORTED or PARTIAL in the "
        "coverage statement and says nothing about the rest."
    )


def _contradicting(
    graph: EvidenceGraph, state: PolicyState
) -> list[EvidenceReference]:
    """Evidence that argues *against* a concern, kept as a first-class list.

    Two kinds qualify, and both matter to an analyst deciding what to do:

    * evidence marked confounded — it looked like support and, given a
      phenomenon present in this run, does not establish what it appears to;
    * an assessed scope that produced no supporting evidence at all, which is a
      positive fact about that scope even though it is an absence.

    The second is represented in the report's scope decisions rather than
    fabricated as a pseudo-finding here; this list carries the first, which is
    real evidence with a real finding id behind it.
    """
    return [
        EvidenceReference.of(e, "contradicting")
        for e in graph.evidence
        if e.active_confounders and e.supports
    ]


def _unassessed(
    inputs: FusionInputs,
    scopes: Sequence[ScopeDecision],
    coverage: CoverageStatement,
) -> list[UnassessedArea]:
    areas: list[UnassessedArea] = []
    supplied = inputs.supplied_scopes()
    for scope, present in sorted(supplied.items(), key=lambda kv: kv[0].value):
        if present:
            continue
        areas.append(
            UnassessedArea(
                area=scope.value,
                kind="scope",
                reason=f"no {scope.value} assessment was supplied to this fusion",
                remedy=_REMEDY.get(scope),
            )
        )
    for entry in coverage.entries:
        if entry.coverage not in (Coverage.NOT_ASSESSED, Coverage.NOT_SUPPORTED):
            continue
        areas.append(
            UnassessedArea(
                area=entry.attack_class,
                kind="attack_class",
                reason=entry.reason or "no detector in this run reported on this class",
                remedy=str(ATTACK_CLASS_REGISTRY.get(entry.attack_class, {}).get("assessed_by"))
                if ATTACK_CLASS_REGISTRY.get(entry.attack_class, {}).get("assessed_by")
                else None,
            )
        )
    return areas


def _coverage_summary(
    coverage: CoverageStatement, scopes: Sequence[ScopeDecision]
) -> dict[str, Any]:
    assessed = coverage.assessed
    unassessed = coverage.unassessed
    return {
        "attack_classes_total": len(coverage.entries),
        "attack_classes_assessed": len(assessed),
        "attack_classes_not_assessed": len(unassessed),
        "assessed": sorted(e.attack_class for e in assessed),
        "not_assessed": sorted(e.attack_class for e in unassessed),
        "scopes_assessed": sorted(
            s.scope.value for s in scopes if s.assessed and s.scope is not Scope.PIPELINE
        ),
        "scopes_not_assessed": sorted(
            s.scope.value for s in scopes if not s.assessed
        ),
        "note": "a pipeline with major unassessed attack classes is not "
        "equivalent to a comprehensively assessed clean one, and this report "
        "does not present them as equivalent.",
    }


def _lineage(
    decision_id: str, scopes: Sequence[ScopeDecision], graph: EvidenceGraph
) -> list[LineageNode]:
    """decision -> rule -> finding -> detector, as rows."""
    by_id = {e.evidence_id: e for e in graph.evidence}
    nodes: list[LineageNode] = []
    for scope in scopes:
        for outcome in scope.fired_rules:
            if not outcome.evidence_ids:
                nodes.append(
                    LineageNode(
                        decision_id=decision_id,
                        rule_id=outcome.rule_id,
                        scope=outcome.scope,
                        disposition=outcome.disposition,
                        detail=outcome.statement,
                    )
                )
                continue
            for evidence_id in outcome.evidence_ids:
                evidence = by_id.get(evidence_id)
                if evidence is None:  # pragma: no cover - ids come from the graph
                    continue
                nodes.append(
                    LineageNode(
                        decision_id=decision_id,
                        rule_id=outcome.rule_id,
                        scope=outcome.scope,
                        disposition=outcome.disposition,
                        finding_id=evidence.finding_id,
                        evidence_id=evidence.evidence_id,
                        source_module=evidence.source_module,
                        source_detector=(
                            f"{evidence.source_detector} "
                            f"v{evidence.source_detector_version}"
                        ),
                        source_report_id=evidence.lineage.source_report_id,
                        detail=f"{evidence.attack_class}: {evidence.title}",
                    )
                )
    return nodes


def _asset_scope(inputs: FusionInputs) -> dict[str, Any]:
    scope: dict[str, Any] = {}
    for name, module_input in (
        ("dataset", inputs.dataset),
        ("model", inputs.model),
        ("provenance", inputs.provenance),
    ):
        scope[name] = (
            {"supplied": False}
            if module_input is None or not module_input.supplied
            else {
                "supplied": True,
                "report_id": module_input.report_id,
                "run_id": module_input.run_id,
                **module_input.asset,
            }
        )
    scope["distribution"] = (
        {"supplied": False}
        if inputs.shift is None
        else {
            "supplied": True,
            "assessment_id": inputs.shift.assessment_id,
            "verdict": inputs.shift.verdict.value,
            "reference_id": inputs.shift.reference.get("reference_id"),
            "reference_digest": inputs.shift.reference.get("digest"),
            "reference_mode": inputs.shift.reference.get("mode"),
        }
    )
    return scope


def _coverage(inputs: FusionInputs) -> CoverageStatement:
    """Merge every upstream coverage statement, worst value winning.

    Worst-value merge rather than best: two assessments of the same class, one
    of which could not run, is a class that was assessed under one set of
    conditions and not another, and reporting it as SUPPORTED would hide the
    half that failed.
    """
    order = {
        Coverage.SUPPORTED: 0,
        Coverage.PARTIAL: 1,
        Coverage.REQUIRES_WHITE_BOX: 2,
        Coverage.NOT_SUPPORTED: 3,
        Coverage.NOT_ASSESSED: 4,
    }
    merged: dict[str, CoverageEntry] = {}
    statements: list[CoverageStatement] = [
        m.coverage for m in inputs.modules() if m.supplied and m.coverage is not None
    ]
    modules: set[int] = {m.module for m in inputs.modules() if m.supplied}
    if inputs.shift is not None:
        modules.add(4)

    for statement in statements:
        modules.update(statement.implemented_modules)
        for entry in statement.entries:
            existing = merged.get(entry.attack_class)
            if existing is None or order[entry.coverage] > order[existing.coverage]:
                merged[entry.attack_class] = entry

    if inputs.shift is not None:
        from ..shift.findings import shift_coverage

        for entry in shift_coverage(inputs.shift, reference_supplied=True):
            merged[entry.attack_class] = entry

    # Only classes an upstream module actually reported on are carried forward;
    # everything else is rebuilt as NOT_ASSESSED by CoverageStatement.build,
    # which is where the reason for the gap is generated.
    reported = [
        entry
        for entry in merged.values()
        if entry.coverage is not Coverage.NOT_ASSESSED or entry.detector is not None
    ]
    return CoverageStatement.build(reported, tuple(sorted(modules)) or (4,))


def _capabilities(inputs: FusionInputs, graph: EvidenceGraph) -> CapabilityStatement:
    entries: list[CapabilityEntry] = []

    shift = inputs.shift
    # The measurement and its interpretation are reported as two capabilities,
    # because they fail independently: the test can run cleanly over a
    # population whose declared context says nothing, and a rich declaration is
    # worthless if the sample floors were not met.
    if shift is None:
        entries.append(
            capability_entry(
                "distribution_shift",
                Coverage.NOT_ASSESSED,
                reason="no reference population was supplied; without one the "
                "outcome is NOT_ASSESSED, never a stable population",
            )
        )
    elif not shift.resolved():
        entries.append(
            capability_entry(
                "distribution_shift",
                Coverage.NOT_ASSESSED,
                reason=shift.statement,
                limitations=(
                    "a refusal to answer is not a negative answer: nothing here "
                    "establishes that the population did not move",
                ),
            )
        )
    else:
        entries.append(
            capability_entry(
                "distribution_shift",
                Coverage.PARTIAL,
                reason=f"the shift analysis resolved {shift.verdict.value} over "
                f"{len([m for m in shift.metrics if m.assessed()])} assessed "
                f"metric(s) of {len(shift.metrics)}",
                limitations=(
                    "bounded by the reference population's own integrity, which "
                    "this system does not establish",
                    "a distribution shift is never equated with an attack",
                ),
            )
        )

    if shift is None:
        entries.append(
            capability_entry(
                "operational_drift",
                Coverage.NOT_ASSESSED,
                reason="no reference population was supplied, so no shift was "
                "characterised and no operational explanation was adjudicated",
            )
        )
    elif not shift.resolved():
        entries.append(
            capability_entry(
                "operational_drift",
                Coverage.NOT_ASSESSED,
                reason=shift.statement,
            )
        )
    elif shift.verdict is ShiftVerdict.NO_SHIFT_DETECTED:
        entries.append(
            capability_entry(
                "operational_drift",
                Coverage.PARTIAL,
                reason="the shift analysis ran and resolved no shift, so there "
                "was nothing for the declared context to explain",
                limitations=("a negative result bounds what the test could see",),
            )
        )
    else:
        declared = bool(
            shift.context is not None and shift.context.delta.any_declared()
        )
        entries.append(
            capability_entry(
                "operational_drift",
                Coverage.PARTIAL,
                reason=(
                    "the observed movement was checked against the declared "
                    "operational context"
                    if declared
                    else "a shift was observed and no operational context was "
                    "declared, so it could be neither explained nor contradicted"
                ),
                limitations=(
                    "the declared-change-to-feature-view mapping is a documented, "
                    "uncalibrated heuristic over one feature space",
                    "a declaration is a claim by the supplying side and is never "
                    "verified",
                ),
            )
        )

    entries.append(
        capability_entry(
            "evidence_fusion",
            Coverage.SUPPORTED,
            reason=f"{len(graph.evidence)} finding(s) from "
            f"{len({e.source_module for e in graph.evidence})} module(s) were "
            "normalised and evaluated against the rule table",
        )
    )
    entries.append(
        capability_entry(
            "evidence_dependency",
            Coverage.SUPPORTED,
            reason=f"{len(graph.groups)} phenomenon family/families were formed; "
            f"{sum(1 for e in graph.evidence if e.active_confounders)} piece(s) of "
            "evidence are marked confounded and excluded from independent "
            "corroboration",
            limitations=(
                "the family and confounding tables are curated, not learned; an "
                "unlisted correlation between two detectors is not detected",
            ),
        )
    )
    entries.append(
        capability_entry(
            "cross_module_lineage",
            Coverage.SUPPORTED,
            reason="every fired rule names the evidence that made it fire, and "
            "every piece of evidence names its module, detector and version",
        )
    )
    entries.append(
        capability_entry(
            "coverage_aware_assurance",
            Coverage.SUPPORTED,
            reason="scopes with no input resolve to NOT_ASSESSED and are carried "
            "in the decision's unassessed_areas",
        )
    )
    entries.append(
        capability_entry(
            "policy_disposition",
            Coverage.SUPPORTED,
            reason="the rule table is emitted verbatim into this report and the "
            "decision is reproducible from its inputs",
        )
    )
    entries.append(
        capability_entry(
            "conflicting_evidence",
            Coverage.SUPPORTED,
            reason="disagreement between evidence classes is recorded by "
            "RULE-CONFLICT-001, which carries ACCEPT so it cannot change an "
            "outcome",
        )
    )
    return CapabilityStatement.build(entries)


#: Limitations of the fusion approach itself, printed on every decision.
ASSURANCE_LIMITATIONS: tuple[str, ...] = (
    "This decision is a function of the evidence supplied and the rule table "
    "printed alongside it. It is not a probability, not a risk score and not a "
    "prediction; there is no universal trust score in this system and there "
    "will not be one.",
    "Evidence from different modules is combined by explicit rules over named "
    "evidence, never by arithmetic. A cryptographic fact and a calibrated "
    "detector score are different kinds of statement and are never averaged "
    "(ADR-014).",
    "Independence is decided by a curated family table, not measured. Two "
    "detectors that are correlated in a way the table does not record would "
    "still be counted as two phenomena; the table is in the report so that "
    "assumption can be challenged.",
    "A scope reported ACCEPT is a statement about the checks that ran in that "
    "scope, bounded by its own coverage statement. It is never a statement that "
    "the artifact is safe, authentic or uncompromised.",
    "A distribution shift is never treated as evidence of manipulation. The "
    "strongest statement the distribution scope makes is REVIEW, and any "
    "quarantine in a run with a shift came from another scope's own evidence.",
    "Consistency between an observed shift and a declared operational change is "
    "not confirmation of that change. A manipulation engineered to move the "
    "same feature views would be reported the same way.",
    "The decision covers only the attack classes declared SUPPORTED or PARTIAL "
    "in the coverage statement. Unassessed classes are listed in "
    "unassessed_areas and are open questions, not clean results.",
)


__all__ = [
    "ModuleInput", "FusionInputs", "FusionResult", "fuse",
    "ASSURANCE_LIMITATIONS",
]
