"""The assurance policy engine: explicit rules, printed, versioned, testable.

This is the module the brief is really about.  Everything upstream produces
evidence; this decides what to do about it, and the one thing it must never be
is a function nobody can read.  So:

* every rule is a **data object** with an id, a machine-readable condition, the
  evidence it requires, its exclusions, its disposition and its rationale;
* the whole rule table is emitted into the report, so the rule an analyst reads
  is the rule the code executed;
* **all** applicable rules are evaluated and every fired rule is recorded.  The
  disposition is the strictest among them and names the rule that set it.

Why "strictest among all fired" rather than "first match wins"
--------------------------------------------------------------
Module 1's finding-level policy is a first-match chain, which is right there:
one finding has one severity and one confidence, and the chain reads top to
bottom.  A pipeline assessment is not like that.  It has four largely
independent scopes — dataset, model, provenance, distribution — and a rule
firing in one says nothing about the others.  A first-match chain across all of
them would report the first thing it noticed and discard the rest, which is
exactly the collapse into a single narrative the brief forbids (§24).  Recording
every fired rule keeps the disagreements visible; taking the strictest keeps the
outcome conservative; naming the governing rule keeps it explainable.

What is deliberately absent
---------------------------
No weights.  No score.  No arithmetic combining evidence from different scopes.
There is no ``0.4 * model + 0.3 * dataset`` anywhere in this file and there will
not be, for the reason ADR-014 gives: the two states *model suspicious with
valid provenance* and *model clean with invalid provenance* call for opposite
actions, and any function mapping both onto one number maps them onto the same
one.  The only counting that happens is over **distinct evidence families**
(:mod:`.families`), and a family contributes at most one, however many findings
it holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import SEVERITY_ORDER, ConfidenceBasis, Coverage, Severity
from ..shift.characterize import ShiftAssessment, ShiftVerdict
from .evidence import EvidenceGraph, NormalizedEvidence
from .families import EvidenceClass, EvidenceFamily

ASSURANCE_POLICY_VERSION = "1.0"


class AssuranceDisposition(str, Enum):
    """The closed disposition vocabulary for a pipeline assessment.

    A superset of the finding-level
    :class:`~cvtrust.core.evidence.Disposition` by exactly one value.  A
    *finding* cannot be ``NOT_ASSESSED`` — it exists, so something was assessed
    — but a *scope* very much can, and a system that reported an unexamined
    model scope as ``ACCEPT`` would be lying in the most consequential field it
    has.  The finding-level enum is left untouched rather than widened, so no
    Module 1-3 report changes shape.
    """

    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"
    NOT_ASSESSED = "NOT_ASSESSED"


#: Strictness order.  ``NOT_ASSESSED`` sits between ACCEPT and REVIEW: an
#: unexamined scope is worse than an examined clean one and is not, by itself,
#: grounds for the analyst work that REVIEW demands.  It is surfaced through
#: the coverage statement and the decision's ``unassessed_areas`` instead.
DISPOSITION_ORDER: dict[AssuranceDisposition, int] = {
    AssuranceDisposition.ACCEPT: 0,
    AssuranceDisposition.NOT_ASSESSED: 1,
    AssuranceDisposition.REVIEW: 2,
    AssuranceDisposition.QUARANTINE: 3,
}


class Scope(str, Enum):
    """The assurance scopes, kept separate on purpose (brief §3)."""

    DATASET = "dataset"
    MODEL = "model"
    PROVENANCE = "provenance"
    DISTRIBUTION = "distribution"
    PIPELINE = "pipeline"


@dataclass(frozen=True, slots=True)
class PolicyState:
    """Everything the rules are allowed to see.

    Note what is absent: ground truth, any scenario label, and any notion of
    which attack the lab was simulating.  The evaluation harness joins those
    afterwards, exactly as Modules 1-3 do, so a rule cannot accidentally read
    the answer.
    """

    graph: EvidenceGraph
    shift: ShiftAssessment | None
    #: Which scopes had inputs at all.  A scope with no input is NOT_ASSESSED;
    #: a scope with an input and no findings is a clean result *for what was
    #: checked*, and the two are never merged.
    inputs: dict[Scope, bool]
    coverage_gaps: tuple[str, ...]
    accept_explained_shift: bool

    def supporting(
        self,
        *,
        families: Sequence[EvidenceFamily] = (),
        classes: Sequence[EvidenceClass] = (),
        min_severity: Severity | None = None,
        basis: ConfidenceBasis | None = None,
        min_confidence: float | None = None,
        require_independent: bool = False,
    ) -> list[NormalizedEvidence]:
        """Evidence matching a rule's conditions, with the floors applied."""
        out: list[NormalizedEvidence] = []
        for item in self.graph.evidence:
            if not item.supports:
                continue
            if require_independent and item.active_confounders:
                continue
            if families and item.dependency_group not in families:
                continue
            if classes and item.evidence_class not in classes:
                continue
            if min_severity and item.severity_rank() < SEVERITY_ORDER[min_severity]:
                continue
            if basis and item.confidence_basis is not basis:
                continue
            if min_confidence is not None and item.confidence < min_confidence:
                continue
            out.append(item)
        return out

    def independent_families_excluding(
        self, excluded: Sequence[EvidenceFamily]
    ) -> list[EvidenceFamily]:
        """Distinct phenomena with supporting, unconfounded evidence.

        This is the *only* counting the policy engine does, and it counts
        phenomena rather than findings for the reason :mod:`.families`
        explains: three detectors reacting to one domain shift are one concern.
        """
        blocked = set(excluded)
        return [f for f in self.graph.independent_families() if f not in blocked]

    def shift_observed(self) -> bool:
        return self.shift is not None and self.shift.shift_observed()

    def shift_resolved(self) -> bool:
        return self.shift is not None and self.shift.resolved()


class RuleOutcome(BaseModel):
    """One rule that fired, and the evidence that made it fire."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    scope: Scope
    disposition: AssuranceDisposition
    statement: str
    rationale: str
    evidence_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    families: tuple[str, ...] = ()
    observation: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AssuranceRule:
    """A policy rule as data, plus the predicate that implements it.

    The predicate and the description are written side by side and a test
    asserts that every rule in the table has both, because a rule whose
    description has drifted from its predicate is worse than no description.
    """

    rule_id: str
    scope: Scope
    title: str
    condition: str
    requires: tuple[str, ...]
    exclusions: tuple[str, ...]
    disposition: AssuranceDisposition
    rationale: str
    evaluate: Callable[[PolicyState], RuleOutcome | None]

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "scope": self.scope.value,
            "title": self.title,
            "if": self.condition,
            "requires_evidence": list(self.requires),
            "exclusions": list(self.exclusions),
            "then": self.disposition.value,
            "rationale": self.rationale,
        }


def _outcome(
    *,
    rule_id: str,
    scope: Scope,
    disposition: AssuranceDisposition,
    statement: str,
    rationale: str,
    evidence: Sequence[NormalizedEvidence] = (),
    families: Sequence[EvidenceFamily] = (),
    observation: dict[str, Any] | None = None,
) -> RuleOutcome:
    return RuleOutcome(
        rule_id=rule_id,
        scope=scope,
        disposition=disposition,
        statement=statement,
        rationale=rationale,
        evidence_ids=tuple(e.evidence_id for e in evidence),
        finding_ids=tuple(e.finding_id for e in evidence),
        families=tuple(f.value for f in families),
        observation=observation or {},
    )


# ---------------------------------------------------------------------------
# Rule implementations
#
# Each is a small function so that it can be read, and tested, in isolation.
# ---------------------------------------------------------------------------


def _fmt(evidence: Sequence[NormalizedEvidence], limit: int = 3) -> str:
    shown = [f"{e.finding_id} ({e.attack_class}, {e.severity.value})" for e in evidence[:limit]]
    more = f" and {len(evidence) - limit} more" if len(evidence) > limit else ""
    return ", ".join(shown) + more


def _prov_000(state: PolicyState) -> RuleOutcome | None:
    if state.inputs.get(Scope.PROVENANCE):
        return None
    return _outcome(
        rule_id="RULE-PROV-000",
        scope=Scope.PROVENANCE,
        disposition=AssuranceDisposition.NOT_ASSESSED,
        statement="No inference provenance was supplied, so the integrity of the "
        "record of inference was not assessed.",
        rationale="A pipeline with no provenance evidence is not a pipeline with "
        "good provenance. The gap is reported rather than resolved in either "
        "direction.",
    )


def _prov_001(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[EvidenceFamily.PROVENANCE_INTEGRITY],
        basis=ConfidenceBasis.DETERMINISTIC,
        min_severity=Severity.HIGH,
    )
    if not hits:
        return None
    return _outcome(
        rule_id="RULE-PROV-001",
        scope=Scope.PROVENANCE,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"The cryptographic integrity of the inference record could not be "
            f"established: {_fmt(hits)}."
        ),
        rationale="A signature, chain or binding failure is a verified fact, not "
        "an inference. Nothing downstream of a record whose integrity is broken "
        "can be relied upon, including a clean model assessment of the model the "
        "record names.",
        evidence=hits,
        families=[EvidenceFamily.PROVENANCE_INTEGRITY],
    )


def _prov_002(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[EvidenceFamily.PROVENANCE_TRUST, EvidenceFamily.PROVENANCE_REPLAY],
        basis=ConfidenceBasis.DETERMINISTIC,
    )
    integrity = state.supporting(
        families=[EvidenceFamily.PROVENANCE_INTEGRITY],
        basis=ConfidenceBasis.DETERMINISTIC,
        min_severity=Severity.HIGH,
    )
    if not hits or integrity:
        return None
    return _outcome(
        rule_id="RULE-PROV-002",
        scope=Scope.PROVENANCE,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"The record is cryptographically well-formed but its authority or "
            f"uniqueness is not established: {_fmt(hits)}."
        ),
        rationale="Anyone can generate a keypair and sign a record that verifies. "
        "A signature from an unauthorised, revoked or out-of-window key, or a "
        "record already observed, establishes nothing about who produced the "
        "inference or whether it happened once.",
        evidence=hits,
        families=[EvidenceFamily.PROVENANCE_TRUST, EvidenceFamily.PROVENANCE_REPLAY],
    )


def _prov_010(state: PolicyState) -> RuleOutcome | None:
    if not state.inputs.get(Scope.PROVENANCE):
        return None
    hits = state.supporting(
        classes=[EvidenceClass.PROVENANCE_INTEGRITY],
        basis=ConfidenceBasis.DETERMINISTIC,
    )
    if hits:
        return None
    return _outcome(
        rule_id="RULE-PROV-010",
        scope=Scope.PROVENANCE,
        disposition=AssuranceDisposition.ACCEPT,
        statement="Provenance evidence was supplied and no integrity, trust or "
        "replay failure reached the corroboration floor.",
        rationale="This is a statement about the integrity of the RECORD of an "
        "inference and about the checks that actually ran. It says nothing about "
        "the quality of the inference, the model that produced it, or the data "
        "the model was trained on.",
    )


def _model_000(state: PolicyState) -> RuleOutcome | None:
    if state.inputs.get(Scope.MODEL):
        return None
    return _outcome(
        rule_id="RULE-MODEL-000",
        scope=Scope.MODEL,
        disposition=AssuranceDisposition.NOT_ASSESSED,
        statement="No model assessment was supplied, so model integrity and "
        "backdoor behaviour were not assessed.",
        rationale="A missing model assessment is an open question. It is never "
        "reported as a clean model.",
    )


def _model_001(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[EvidenceFamily.MODEL_IDENTITY, EvidenceFamily.MODEL_TAMPERING],
        basis=ConfidenceBasis.DETERMINISTIC,
        min_severity=Severity.HIGH,
    )
    if not hits:
        return None
    return _outcome(
        rule_id="RULE-MODEL-001",
        scope=Scope.MODEL,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"The model is not the assured artifact: {_fmt(hits)}."
        ),
        rationale="Content identity is a digest comparison, not an inference. A "
        "model whose graph or parameter digest differs from its trusted "
        "reference is a different model, whatever its metadata says.",
        evidence=hits,
        families=[EvidenceFamily.MODEL_IDENTITY, EvidenceFamily.MODEL_TAMPERING],
    )


def _model_002(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[EvidenceFamily.MODEL_BACKDOOR],
        basis=ConfidenceBasis.CALIBRATED,
        min_severity=Severity.HIGH,
        min_confidence=0.85,
    )
    if not hits:
        return None
    return _outcome(
        rule_id="RULE-MODEL-002",
        scope=Scope.MODEL,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"Backdoor evidence of measured quality reached the quarantine "
            f"threshold: {_fmt(hits)}."
        ),
        rationale="Quarantine on a statistical indicator requires MEASURED "
        "evidence quality, not a documented prior. The confidence here is the "
        "Wilson lower bound of a precision measured on the model attack lab, and "
        "the finding carries that provenance.",
        evidence=hits,
        families=[EvidenceFamily.MODEL_BACKDOOR],
    )


def _model_003(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[
            EvidenceFamily.MODEL_BACKDOOR,
            EvidenceFamily.MODEL_TAMPERING,
            EvidenceFamily.MODEL_IDENTITY,
        ]
    )
    quarantining = [
        e
        for e in hits
        if e.confidence_basis is ConfidenceBasis.DETERMINISTIC
        and e.severity_rank() >= SEVERITY_ORDER[Severity.HIGH]
    ] or [
        e
        for e in hits
        if e.confidence_basis is ConfidenceBasis.CALIBRATED
        and e.severity_rank() >= SEVERITY_ORDER[Severity.HIGH]
        and e.confidence >= 0.85
    ]
    if not hits or quarantining:
        return None
    return _outcome(
        rule_id="RULE-MODEL-003",
        scope=Scope.MODEL,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            f"Model anomaly evidence exists but does not meet the quarantine "
            f"standard: {_fmt(hits)}."
        ),
        rationale="An uncalibrated or moderate-severity model indicator is "
        "grounds for an analyst to look, not for an irreversible action. "
        "Quarantining a model on a documented prior costs credibility the first "
        "time it is wrong.",
        evidence=hits,
        families=[EvidenceFamily.MODEL_BACKDOOR, EvidenceFamily.MODEL_TAMPERING],
    )


def _model_010(state: PolicyState) -> RuleOutcome | None:
    if not state.inputs.get(Scope.MODEL):
        return None
    if state.supporting(classes=[EvidenceClass.MODEL_INTEGRITY]):
        return None
    return _outcome(
        rule_id="RULE-MODEL-010",
        scope=Scope.MODEL,
        disposition=AssuranceDisposition.ACCEPT,
        statement="A model assessment was supplied and no model-integrity "
        "evidence reached the corroboration floor.",
        rationale="NO ANOMALY DETECTED, scoped to the attack classes the model "
        "assessment declared SUPPORTED or PARTIAL and to the access mode it ran "
        "under. This is a statement about the tests, not about the model.",
    )


def _data_000(state: PolicyState) -> RuleOutcome | None:
    if state.inputs.get(Scope.DATASET):
        return None
    return _outcome(
        rule_id="RULE-DATA-000",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.NOT_ASSESSED,
        statement="No dataset assessment was supplied, so dataset forensics were "
        "not assessed.",
        rationale="An unassessed dataset is an open question, not a clean one.",
    )


def _data_001(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(
        families=[EvidenceFamily.DATASET_METADATA, EvidenceFamily.DATASET_DUPLICATION],
        basis=ConfidenceBasis.DETERMINISTIC,
        min_severity=Severity.HIGH,
    )
    if not hits:
        return None
    return _outcome(
        rule_id="RULE-DATA-001",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"Deterministic dataset-integrity evidence at high severity: "
            f"{_fmt(hits)}."
        ),
        rationale="Post-baseline modification and exact duplication are digest "
        "comparisons, not inferences. There is no statistical uncertainty to "
        "weigh against the observation.",
        evidence=hits,
        families=[EvidenceFamily.DATASET_METADATA, EvidenceFamily.DATASET_DUPLICATION],
    )


def _data_002(state: PolicyState) -> RuleOutcome | None:
    hits = state.supporting(classes=[EvidenceClass.DATA_INTEGRITY], require_independent=True)
    deterministic = [
        e
        for e in hits
        if e.confidence_basis is ConfidenceBasis.DETERMINISTIC
        and e.severity_rank() >= SEVERITY_ORDER[Severity.HIGH]
    ]
    if not hits or deterministic:
        return None
    return _outcome(
        rule_id="RULE-DATA-002",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            f"Statistical dataset evidence warrants analyst review: {_fmt(hits)}."
        ),
        rationale="A statistical dataset finding identifies a pattern "
        "inconsistent with a stated null model. An unfamiliar annotation "
        "guideline, a sensor change or a different collection protocol produce "
        "the same signature as a deliberate attack, so this is grounds to look "
        "rather than grounds to quarantine.",
        evidence=hits,
        families=sorted(
            {e.dependency_group for e in hits}, key=lambda f: f.value
        ),
    )


def _data_003(state: PolicyState) -> RuleOutcome | None:
    """Statistical dataset evidence corroborated by an independent phenomenon.

    This is the one rule in the table that escalates a statistical observation
    to QUARANTINE, and it needs the corroboration to come from a **different
    family whose phenomenon does not confound it** — which is the whole reason
    :mod:`.families` exists.  Three detectors reacting to one domain shift do
    not satisfy it; a label anomaly plus an independently broken model digest
    does.
    """
    hits = state.supporting(
        classes=[EvidenceClass.DATA_INTEGRITY],
        min_severity=Severity.HIGH,
        require_independent=True,
    )
    if not hits:
        return None
    data_families = {e.dependency_group for e in hits}
    corroborating = [
        f
        for f in state.independent_families_excluding(sorted(data_families, key=lambda x: x.value))
        if f
        in (
            EvidenceFamily.MODEL_IDENTITY,
            EvidenceFamily.MODEL_TAMPERING,
            EvidenceFamily.MODEL_BACKDOOR,
            EvidenceFamily.PROVENANCE_INTEGRITY,
            EvidenceFamily.PROVENANCE_TRUST,
            EvidenceFamily.PROVENANCE_REPLAY,
        )
    ]
    if not corroborating:
        return None
    return _outcome(
        rule_id="RULE-DATA-003",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.QUARANTINE,
        statement=(
            f"High-severity dataset evidence ({_fmt(hits, 2)}) is corroborated by "
            f"independent evidence in {', '.join(f.value for f in corroborating)}."
        ),
        rationale="Corroboration is counted over distinct phenomena, never over "
        "detectors: the corroborating evidence is in a family that does not "
        "confound the dataset evidence, so the two are genuinely separate "
        "observations rather than one phenomenon seen twice.",
        evidence=hits,
        families=[*sorted(data_families, key=lambda f: f.value), *corroborating],
        observation={
            "dataset_families": [f.value for f in sorted(data_families, key=lambda x: x.value)],
            "corroborating_families": [f.value for f in corroborating],
            "counting_unit": "distinct evidence family, not finding",
        },
    )


def _data_004(state: PolicyState) -> RuleOutcome | None:
    """Dataset evidence that a phenomenon present in this run explains.

    Added after the lab found a hole rather than designed in from the start.
    The ``ood_without_attack`` scenario — a legitimate new sensor domain
    arriving — produces high-severity label-consistency findings, *all* of them
    confounded by the population shift that also arrived.  RULE-DATA-002
    requires unconfounded evidence and so did not fire; RULE-DATA-010 requires
    *no* supporting evidence and so did not fire either; the dataset scope fell
    through both and vanished from the report entirely.

    A scope silently absent is the worst possible outcome for a system whose
    whole claim is that gaps are visible, so this rule catches the case
    explicitly.  It is REVIEW rather than ACCEPT because a confounded finding
    is not a refuted one: the shift *explains* the label disagreement, and an
    analyst still has to confirm that explanation rather than assume it.
    """
    supporting = state.supporting(classes=[EvidenceClass.DATA_INTEGRITY])
    unconfounded = state.supporting(
        classes=[EvidenceClass.DATA_INTEGRITY], require_independent=True
    )
    if not supporting or unconfounded:
        return None
    confounders = sorted(
        {f.value for e in supporting for f in e.active_confounders}
    )
    return _outcome(
        rule_id="RULE-DATA-004",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            f"Dataset evidence exists ({_fmt(supporting)}) and every piece of it "
            f"is explained by {', '.join(confounders)}, which is present in this "
            "run. It is preserved and reported, and it does not count as "
            "independent evidence of manipulation."
        ),
        rationale="A confounded finding is not a refuted one. A population that "
        "moved has unrepresentative neighbourhoods, so label disagreement is the "
        "expected consequence rather than evidence of a flip -- but the "
        "explanation is a hypothesis an analyst confirms, not one the system "
        "assumes.",
        evidence=supporting,
        families=sorted(
            {e.dependency_group for e in supporting}, key=lambda f: f.value
        ),
        observation={
            "active_confounders": confounders,
            "supporting_but_confounded": len(supporting),
            "unconfounded_supporting": 0,
        },
    )


def _data_010(state: PolicyState) -> RuleOutcome | None:
    if not state.inputs.get(Scope.DATASET):
        return None
    if state.supporting(classes=[EvidenceClass.DATA_INTEGRITY]):
        return None
    return _outcome(
        rule_id="RULE-DATA-010",
        scope=Scope.DATASET,
        disposition=AssuranceDisposition.ACCEPT,
        statement="A dataset assessment was supplied and no dataset-integrity "
        "evidence reached the corroboration floor.",
        rationale="Scoped to the attack classes that assessment declared "
        "SUPPORTED or PARTIAL. A clean result from a system that never tested "
        "for a class is not a clean result for that class.",
    )


def _shift_000(state: PolicyState) -> RuleOutcome | None:
    if state.shift is not None:
        return None
    return _outcome(
        rule_id="RULE-SHIFT-000",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.NOT_ASSESSED,
        statement="No reference population was supplied, so population-level "
        "distribution shift was not assessed.",
        rationale="A shift claim requires a baseline. Without one there is no "
        "shift assessment, and an absent assessment is not a stable population.",
    )


def _shift_001(state: PolicyState) -> RuleOutcome | None:
    if state.shift is None or state.shift.resolved():
        return None
    return _outcome(
        rule_id="RULE-SHIFT-001",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.NOT_ASSESSED,
        statement=state.shift.statement,
        rationale="Sample sufficiency is enforced before a verdict, not after. A "
        "permutation test on a handful of samples stays valid and loses all its "
        "power, so its silence would be reported as reassurance it has not "
        "earned.",
        observation={"verdict": state.shift.verdict.value},
    )


def _shift_010(state: PolicyState) -> RuleOutcome | None:
    if state.shift is None or state.shift.verdict is not ShiftVerdict.NO_SHIFT_DETECTED:
        return None
    return _outcome(
        rule_id="RULE-SHIFT-010",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.ACCEPT,
        statement=state.shift.statement,
        rationale="No population-level difference was resolved at the configured "
        "alpha. This bounds the shift the test could see at these sample sizes.",
        observation={"verdict": state.shift.verdict.value},
    )


def _independent_integrity(state: PolicyState) -> list[EvidenceFamily]:
    """Families that are integrity evidence and not part of the shift story."""
    return [
        f
        for f in state.independent_families_excluding([EvidenceFamily.DISTRIBUTION_SHIFT])
        if f
        in (
            EvidenceFamily.DATASET_DUPLICATION,
            EvidenceFamily.DATASET_METADATA,
            EvidenceFamily.MODEL_IDENTITY,
            EvidenceFamily.MODEL_TAMPERING,
            EvidenceFamily.MODEL_BACKDOOR,
            EvidenceFamily.PROVENANCE_INTEGRITY,
            EvidenceFamily.PROVENANCE_TRUST,
            EvidenceFamily.PROVENANCE_REPLAY,
        )
    ]


def _shift_020(state: PolicyState) -> RuleOutcome | None:
    if (
        state.shift is None
        or state.shift.verdict is not ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT
    ):
        return None
    if _independent_integrity(state):
        return None
    disposition = (
        AssuranceDisposition.ACCEPT
        if state.accept_explained_shift
        else AssuranceDisposition.REVIEW
    )
    return _outcome(
        rule_id="RULE-SHIFT-020",
        scope=Scope.DISTRIBUTION,
        disposition=disposition,
        statement=(
            "A population shift was observed and is confined to the feature views "
            "the declared operational change would move. No independent integrity "
            "evidence accompanies it. Recorded as operational drift."
        ),
        rationale="Terrain, season, sensor and illumination changes are the "
        "normal condition of an operational pipeline. Reporting every declared "
        "change as an open question trains an analyst to ignore the tool, which "
        "is the expensive failure mode. Consistency with the declaration is not "
        "confirmation of it, and the finding says so.",
        observation={
            "verdict": state.shift.verdict.value,
            "declared_changes": list(state.shift.context.delta.changed)
            if state.shift.context
            else [],
            "accept_explained_shift": state.accept_explained_shift,
            "independent_integrity_families": [],
        },
    )


def _shift_030(state: PolicyState) -> RuleOutcome | None:
    if state.shift is None:
        return None
    if state.shift.verdict not in (
        ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT,
        ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED,
        ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT,
    ):
        return None
    if _independent_integrity(state):
        return None
    return _outcome(
        rule_id="RULE-SHIFT-030",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            "A population shift was observed that the declared operational "
            "context does not account for, and no independent integrity evidence "
            "accompanies it."
        ),
        rationale="An unexplained population change is an open question for an "
        "analyst: a new collection platform, an undeclared protocol change and a "
        "deliberate insertion all produce it. This rule deliberately does NOT "
        "escalate, because nothing here distinguishes them.",
        observation={
            "verdict": state.shift.verdict.value,
            "unexplained_blocks": list(state.shift.context.unexplained_blocks)
            if state.shift.context
            else [],
            "independent_integrity_families": [],
        },
    )


def _shift_040(state: PolicyState) -> RuleOutcome | None:
    if state.shift is None or not state.shift.shift_observed():
        return None
    corroborating = _independent_integrity(state)
    if not corroborating:
        return None
    return _outcome(
        rule_id="RULE-SHIFT-040",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            "A population shift was observed alongside independent integrity "
            f"evidence in {', '.join(f.value for f in corroborating)}. The two "
            "are separate observations and are reported as such."
        ),
        rationale="This is the strongest statement the shift scope makes, and it "
        "is still REVIEW. The shift does not make the integrity evidence "
        "stronger and the integrity evidence does not make the shift malicious; "
        "what the conjunction changes is the analyst's ordering, not the "
        "classification. Any quarantine here comes from the integrity family's "
        "own rule, on its own evidence.",
        families=corroborating,
        observation={
            "verdict": state.shift.verdict.value,
            "independent_integrity_families": [f.value for f in corroborating],
            "counting_unit": "distinct evidence family, not finding",
            "note": "maliciousness is NOT inferred from shift, here or anywhere",
        },
    )


def _shift_050(state: PolicyState) -> RuleOutcome | None:
    """Per-sample OOD evidence with no population-level assessment to read it.

    The second hole the lab found. Module 1's ``ood`` detector emits evidence in
    the DISTRIBUTION_SHIFT family, and every distribution rule above keys off
    the *shift assessment*. With no reference population supplied, that evidence
    entered the graph and drove nothing: samples flagged as outside the declared
    reference, and no rule in the table had anything to say about them.

    When a shift assessment IS present this rule stays silent, and that silence
    is the dependency handling doing its job: the per-sample findings and the
    population verdict are the same family and the same phenomenon, so letting
    both fire would count one observation twice.
    """
    if state.shift is not None:
        return None
    hits = state.supporting(
        families=[EvidenceFamily.DISTRIBUTION_SHIFT],
        min_severity=Severity.MEDIUM,
    )
    if not hits:
        return None
    return _outcome(
        rule_id="RULE-SHIFT-050",
        scope=Scope.DISTRIBUTION,
        disposition=AssuranceDisposition.REVIEW,
        statement=(
            f"Samples were flagged as lying outside the declared reference "
            f"distribution ({_fmt(hits)}), and no reference *population* was "
            "supplied, so whether the operating distribution has actually moved "
            "was not assessed."
        ),
        rationale="Per-sample distance from a reference and a population-level "
        "shift are different questions. The first was answered and the second "
        "was not, so the observation stands as an open question rather than "
        "being resolved in either direction. Out-of-distribution is never "
        "treated as evidence of malice.",
        evidence=hits,
        families=[EvidenceFamily.DISTRIBUTION_SHIFT],
        observation={
            "population_assessment_supplied": False,
            "remedy": "declare a reference population and run "
            "`cvtrust assurance shift`",
        },
    )


def _pipeline_conflict(state: PolicyState) -> RuleOutcome | None:
    """Record disagreement between evidence classes.  Never changes an outcome.

    Its whole job is to stop the report from forcing four different kinds of
    observation into one narrative.  It carries ``ACCEPT`` so that it can never
    raise or lower the disposition — it is a *statement*, and the strictness
    roll-up ignores it.
    """
    concerned: dict[str, list[str]] = {}
    for item in state.graph.evidence:
        if item.supports:
            concerned.setdefault(item.evidence_class.value, []).append(item.finding_id)
    clean: list[str] = []
    for scope, evidence_class in (
        (Scope.DATASET, EvidenceClass.DATA_INTEGRITY),
        (Scope.MODEL, EvidenceClass.MODEL_INTEGRITY),
        (Scope.PROVENANCE, EvidenceClass.PROVENANCE_INTEGRITY),
    ):
        if state.inputs.get(scope) and evidence_class.value not in concerned:
            clean.append(evidence_class.value)
    if not concerned or not clean:
        return None
    return _outcome(
        rule_id="RULE-CONFLICT-001",
        scope=Scope.PIPELINE,
        disposition=AssuranceDisposition.ACCEPT,
        statement=(
            "Evidence streams address different properties and do not agree: "
            + "; ".join(
                f"{name} raised {len(ids)} supporting finding(s)"
                for name, ids in sorted(concerned.items())
            )
            + ", while "
            + ", ".join(sorted(clean))
            + " produced none. These are separate facts about separate "
            "properties and are not combined."
        ),
        rationale="A cryptographically perfect record of a backdoored model and "
        "a forged record of a sound one are both real states calling for "
        "opposite actions. Any function mapping them onto one scale maps them "
        "onto the same value (ADR-014), so this system does not have one.",
        observation={
            "classes_with_supporting_evidence": sorted(concerned),
            "classes_assessed_without_supporting_evidence": sorted(clean),
        },
    )


# ---------------------------------------------------------------------------
# The rule table
# ---------------------------------------------------------------------------

RULES: tuple[AssuranceRule, ...] = (
    AssuranceRule(
        rule_id="RULE-PROV-000",
        scope=Scope.PROVENANCE,
        title="No provenance evidence supplied",
        condition="no provenance assessment was supplied to this fusion",
        requires=(),
        exclusions=(),
        disposition=AssuranceDisposition.NOT_ASSESSED,
        rationale="an unexamined scope is never reported as a clean one",
        evaluate=_prov_000,
    ),
    AssuranceRule(
        rule_id="RULE-PROV-001",
        scope=Scope.PROVENANCE,
        title="Provenance integrity failure",
        condition="supporting DETERMINISTIC evidence in PROVENANCE_INTEGRITY at "
        "severity >= HIGH",
        requires=("a provenance verification report",),
        exclusions=(),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="the cryptographic integrity of the inference record cannot be "
        "established; a digest either matches or it does not",
        evaluate=_prov_001,
    ),
    AssuranceRule(
        rule_id="RULE-PROV-002",
        scope=Scope.PROVENANCE,
        title="Key authority or replay failure",
        condition="supporting DETERMINISTIC evidence in PROVENANCE_TRUST or "
        "PROVENANCE_REPLAY",
        requires=("a trust store and/or a replay database",),
        exclusions=("RULE-PROV-001 already fired on the same log",),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="a valid signature from an unauthorised key establishes "
        "nothing, and a re-presented record is not a second inference",
        evaluate=_prov_002,
    ),
    AssuranceRule(
        rule_id="RULE-PROV-010",
        scope=Scope.PROVENANCE,
        title="Provenance checks ran and passed",
        condition="provenance evidence supplied and no supporting DETERMINISTIC "
        "provenance failure",
        requires=("a provenance verification report",),
        exclusions=(),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="a statement about the integrity of the RECORD and about the "
        "checks that ran; never about the inference it describes",
        evaluate=_prov_010,
    ),
    AssuranceRule(
        rule_id="RULE-MODEL-000",
        scope=Scope.MODEL,
        title="No model evidence supplied",
        condition="no model assessment was supplied to this fusion",
        requires=(),
        exclusions=(),
        disposition=AssuranceDisposition.NOT_ASSESSED,
        rationale="an unexamined model is an open question",
        evaluate=_model_000,
    ),
    AssuranceRule(
        rule_id="RULE-MODEL-001",
        scope=Scope.MODEL,
        title="Model is not the assured artifact",
        condition="supporting DETERMINISTIC evidence in MODEL_IDENTITY or "
        "MODEL_TAMPERING at severity >= HIGH",
        requires=("a trusted reference model",),
        exclusions=(),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="content identity is a digest comparison, not an inference",
        evaluate=_model_001,
    ),
    AssuranceRule(
        rule_id="RULE-MODEL-002",
        scope=Scope.MODEL,
        title="Measured backdoor evidence",
        condition="supporting CALIBRATED evidence in MODEL_BACKDOOR at severity "
        ">= HIGH and confidence >= 0.85",
        requires=("a calibration table measured on the model attack lab",),
        exclusions=("HEURISTIC_UNCALIBRATED confidence never satisfies this rule",),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="quarantine on a statistical indicator requires measured "
        "evidence quality, not a documented prior",
        evaluate=_model_002,
    ),
    AssuranceRule(
        rule_id="RULE-MODEL-003",
        scope=Scope.MODEL,
        title="Model anomaly below the quarantine standard",
        condition="supporting model evidence exists and no model rule reached "
        "QUARANTINE",
        requires=("a model assessment",),
        exclusions=("RULE-MODEL-001 or RULE-MODEL-002 fired",),
        disposition=AssuranceDisposition.REVIEW,
        rationale="an uncalibrated or moderate indicator is grounds to look, not "
        "grounds for an irreversible action",
        evaluate=_model_003,
    ),
    AssuranceRule(
        rule_id="RULE-MODEL-010",
        scope=Scope.MODEL,
        title="Model checks ran and found no anomaly",
        condition="model evidence supplied and no supporting MODEL_INTEGRITY "
        "evidence",
        requires=("a model assessment",),
        exclusions=(),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="scoped to the attack classes and access mode that assessment "
        "declared; never a statement that a model is safe",
        evaluate=_model_010,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-000",
        scope=Scope.DATASET,
        title="No dataset evidence supplied",
        condition="no dataset assessment was supplied to this fusion",
        requires=(),
        exclusions=(),
        disposition=AssuranceDisposition.NOT_ASSESSED,
        rationale="an unexamined dataset is an open question",
        evaluate=_data_000,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-001",
        scope=Scope.DATASET,
        title="Deterministic dataset integrity failure",
        condition="supporting DETERMINISTIC evidence in DATASET_METADATA or "
        "DATASET_DUPLICATION at severity >= HIGH",
        requires=("a dataset assessment; for dataset_tamper, a prior manifest",),
        exclusions=(),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="post-baseline modification and exact duplication are digest "
        "comparisons with no statistical uncertainty to weigh",
        evaluate=_data_001,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-002",
        scope=Scope.DATASET,
        title="Statistical dataset evidence",
        condition="supporting, unconfounded DATA_INTEGRITY evidence exists and "
        "RULE-DATA-001 did not fire",
        requires=("a dataset assessment",),
        exclusions=(
            "evidence confounded by an active distribution shift does not satisfy "
            "this rule",
        ),
        disposition=AssuranceDisposition.REVIEW,
        rationale="a statistical pattern inconsistent with a null model is "
        "grounds to look; an annotation guideline or a sensor change produces the "
        "same signature as an attack",
        evaluate=_data_002,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-003",
        scope=Scope.DATASET,
        title="Dataset evidence corroborated by an independent phenomenon",
        condition="supporting, unconfounded DATA_INTEGRITY evidence at severity "
        ">= HIGH, AND at least one independent model or provenance family with "
        "supporting evidence",
        requires=(
            "a dataset assessment",
            "an independent model or provenance assessment",
        ),
        exclusions=(
            "corroboration from a family that confounds the dataset evidence does "
            "not count",
            "multiple detectors within one family count once",
        ),
        disposition=AssuranceDisposition.QUARANTINE,
        rationale="two genuinely separate phenomena agreeing is a different "
        "statement from one phenomenon observed by three detectors",
        evaluate=_data_003,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-004",
        scope=Scope.DATASET,
        title="Dataset evidence fully explained by another phenomenon",
        condition="supporting DATA_INTEGRITY evidence exists and ALL of it is "
        "confounded by a phenomenon present in this run",
        requires=("a dataset assessment", "an active confounding phenomenon"),
        exclusions=("any unconfounded supporting dataset evidence sends this to "
                    "RULE-DATA-002 or RULE-DATA-003 instead",),
        disposition=AssuranceDisposition.REVIEW,
        rationale="a confounded finding is preserved and reported, does not "
        "corroborate, and still warrants a look: the explanation is a "
        "hypothesis, not a refutation",
        evaluate=_data_004,
    ),
    AssuranceRule(
        rule_id="RULE-DATA-010",
        scope=Scope.DATASET,
        title="Dataset checks ran and found nothing actionable",
        condition="dataset evidence supplied and no supporting DATA_INTEGRITY "
        "evidence",
        requires=("a dataset assessment",),
        exclusions=(),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="scoped to the attack classes that assessment declared "
        "SUPPORTED or PARTIAL",
        evaluate=_data_010,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-000",
        scope=Scope.DISTRIBUTION,
        title="No reference population",
        condition="no shift assessment was supplied to this fusion",
        requires=(),
        exclusions=(),
        disposition=AssuranceDisposition.NOT_ASSESSED,
        rationale="a shift claim requires a baseline; without one there is no "
        "assessment, not a stable population",
        evaluate=_shift_000,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-001",
        scope=Scope.DISTRIBUTION,
        title="Shift assessment unresolved",
        condition="the shift assessment returned INSUFFICIENT_SAMPLE or "
        "NOT_ASSESSED",
        requires=("populations above the configured sample floors",),
        exclusions=(),
        disposition=AssuranceDisposition.NOT_ASSESSED,
        rationale="an underpowered test's silence is not evidence of stability",
        evaluate=_shift_001,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-010",
        scope=Scope.DISTRIBUTION,
        title="No shift resolved",
        condition="the omnibus permutation test resolved no difference at alpha",
        requires=("a reference population above the sample floors",),
        exclusions=(),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="bounds what the test could see at these sample sizes",
        evaluate=_shift_010,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-020",
        scope=Scope.DISTRIBUTION,
        title="Operational drift consistent with the declared context",
        condition="shift observed AND confined to the views the declared change "
        "would move AND no independent integrity evidence in any other family",
        requires=("an operational context declaration for both populations",),
        exclusions=(
            "any independent integrity family with supporting evidence sends this "
            "to RULE-SHIFT-040 instead",
        ),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="declared operational change is the normal condition of the "
        "deployment; configurable via assurance.accept_explained_shift",
        evaluate=_shift_020,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-030",
        scope=Scope.DISTRIBUTION,
        title="Unexplained population shift",
        condition="shift observed AND not accounted for by the declared context "
        "(or nothing declared) AND no independent integrity evidence",
        requires=("a reference population above the sample floors",),
        exclusions=(
            "any independent integrity family with supporting evidence sends this "
            "to RULE-SHIFT-040 instead",
        ),
        disposition=AssuranceDisposition.REVIEW,
        rationale="an unexplained population change is an open question; a new "
        "platform, an undeclared protocol change and a deliberate insertion all "
        "produce it and nothing here distinguishes them",
        evaluate=_shift_030,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-040",
        scope=Scope.DISTRIBUTION,
        title="Shift alongside independent integrity evidence",
        condition="shift observed AND at least one independent integrity family "
        "has supporting, unconfounded evidence",
        requires=("independent evidence from a family that does not confound the shift",),
        exclusions=("families confounded by the shift itself do not count",),
        disposition=AssuranceDisposition.REVIEW,
        rationale="the conjunction changes the analyst's ordering, not the "
        "classification; any quarantine comes from the integrity family's own "
        "rule on its own evidence",
        evaluate=_shift_040,
    ),
    AssuranceRule(
        rule_id="RULE-SHIFT-050",
        scope=Scope.DISTRIBUTION,
        title="Per-sample OOD evidence with no population assessment",
        condition="supporting DISTRIBUTION_SHIFT evidence at severity >= MEDIUM "
        "AND no shift assessment was supplied",
        requires=("a dataset assessment whose OOD detector ran",),
        exclusions=("a supplied shift assessment silences this rule: the "
                    "per-sample findings and the population verdict are one "
                    "phenomenon and must not both fire",),
        disposition=AssuranceDisposition.REVIEW,
        rationale="per-sample distance and population-level movement are "
        "different questions; the second was not asked",
        evaluate=_shift_050,
    ),
    AssuranceRule(
        rule_id="RULE-CONFLICT-001",
        scope=Scope.PIPELINE,
        title="Evidence streams disagree",
        condition="at least one evidence class has supporting evidence while "
        "another assessed class has none",
        requires=("at least two assessed scopes",),
        exclusions=(),
        disposition=AssuranceDisposition.ACCEPT,
        rationale="records the disagreement without resolving it; carries ACCEPT "
        "so it can never raise or lower an outcome",
        evaluate=_pipeline_conflict,
    ),
)


class ScopeDecision(BaseModel):
    """One scope's outcome, and every rule that fired within it."""

    model_config = ConfigDict(extra="forbid")

    scope: Scope
    disposition: AssuranceDisposition
    governing_rule: str | None
    statement: str
    fired_rules: list[RuleOutcome] = Field(default_factory=list)
    assessed: bool = True


class AssurancePolicyEngine:
    """Evaluates the rule table.  Deterministic, versioned, and printable."""

    version = ASSURANCE_POLICY_VERSION

    def __init__(self, rules: Sequence[AssuranceRule] = RULES) -> None:
        self.rules = tuple(rules)

    def evaluate(self, state: PolicyState) -> list[ScopeDecision]:
        fired: list[RuleOutcome] = []
        for rule in self.rules:
            outcome = rule.evaluate(state)
            if outcome is None:
                continue
            # The predicate builds the outcome; the table owns the identity, so
            # a rule cannot report a different id or disposition than the one it
            # is documented with.
            fired.append(
                outcome.model_copy(
                    update={
                        "rule_id": rule.rule_id,
                        "scope": rule.scope,
                        "disposition": outcome.disposition,
                    }
                )
            )

        decisions: list[ScopeDecision] = []
        for scope in Scope:
            in_scope = [o for o in fired if o.scope is scope]
            if not in_scope:
                continue
            governing = max(
                in_scope,
                key=lambda o: (DISPOSITION_ORDER[o.disposition], o.rule_id),
            )
            decisions.append(
                ScopeDecision(
                    scope=scope,
                    disposition=governing.disposition,
                    governing_rule=governing.rule_id,
                    statement=governing.statement,
                    fired_rules=sorted(in_scope, key=lambda o: o.rule_id),
                    assessed=governing.disposition is not AssuranceDisposition.NOT_ASSESSED,
                )
            )
        return decisions

    def describe(self) -> dict[str, Any]:
        """The rule table, verbatim, for inclusion in the report."""
        return {
            "policy_version": self.version,
            "combination": "all applicable rules are evaluated; every fired rule "
            "is recorded; a scope's disposition is the STRICTEST among its fired "
            "rules and names the rule that set it; the overall disposition is the "
            "strictest across scopes",
            "strictness_order": [
                d.value
                for d in sorted(AssuranceDisposition, key=lambda x: DISPOSITION_ORDER[x])
            ],
            "counting_unit": "distinct evidence family. Multiple findings, or "
            "multiple detectors, within one family are one phenomenon and "
            "contribute at most one unit of independent support.",
            "accept_requires_full_coverage": "an overall ACCEPT is reachable "
            "only when every scope was assessed. NOT_ASSESSED outranks ACCEPT in "
            "the strictness order, so a pipeline with an unexamined scope reports "
            "NOT_ASSESSED however clean the examined scopes were.",
            "no_scoring": "there is no trust score, no weighted combination and "
            "no arithmetic across evidence classes in this engine. Dispositions "
            "follow from named rules over named evidence.",
            "rules": [rule.describe() for rule in self.rules],
        }


def overall(decisions: Sequence[ScopeDecision]) -> tuple[AssuranceDisposition, str]:
    """Strictest scope disposition, with the scope named.

    Deliberately not an average, for the reason Modules 1-3 give for their own
    roll-ups: one confident QUARANTINE among four quiet scopes is exactly the
    case that matters, and any mean would bury it.
    """
    if not decisions:
        return (
            AssuranceDisposition.NOT_ASSESSED,
            "No assurance scope produced a decision: nothing was assessed.",
        )
    assessed = [d for d in decisions if d.disposition is not AssuranceDisposition.NOT_ASSESSED]
    if not assessed:
        return (
            AssuranceDisposition.NOT_ASSESSED,
            "Every assurance scope reported NOT_ASSESSED. No evidence was "
            "supplied for the dataset, the model, the inference provenance or a "
            "reference population, so this run establishes nothing.",
        )
    worst = max(
        decisions, key=lambda d: (DISPOSITION_ORDER[d.disposition], d.scope.value)
    )
    unassessed = [d.scope.value for d in decisions if not d.assessed]
    if unassessed and worst.disposition is AssuranceDisposition.NOT_ASSESSED:
        # The consequence of NOT_ASSESSED outranking ACCEPT in the strictness
        # order, stated rather than left to be inferred from a table: an
        # overall ACCEPT is reachable only when EVERY scope was assessed. A
        # pipeline whose model and provenance nobody looked at is not a clean
        # pipeline, however clean its dataset scan was, and the one field an
        # operator reads first must not say otherwise.
        return (
            AssuranceDisposition.NOT_ASSESSED,
            "Assessed scopes produced nothing actionable, but "
            f"{len(unassessed)} scope(s) were not assessed at all: "
            f"{', '.join(sorted(unassessed))}. The overall disposition is "
            "NOT_ASSESSED rather than ACCEPT, because an ACCEPT here would "
            "present partial coverage as a clean pipeline. Per-scope "
            "dispositions are unchanged and are listed above.",
        )
    caveat = (
        f" Not assessed in this run: {', '.join(sorted(unassessed))}."
        if unassessed
        else ""
    )
    return (
        worst.disposition,
        f"The strictest disposition across assurance scopes is "
        f"{worst.disposition.value}, set by the {worst.scope.value} scope under "
        f"rule {worst.governing_rule}.{caveat}",
    )


__all__ = [
    "ASSURANCE_POLICY_VERSION", "AssuranceDisposition", "DISPOSITION_ORDER",
    "Scope", "PolicyState", "RuleOutcome", "AssuranceRule", "RULES",
    "ScopeDecision", "AssurancePolicyEngine", "overall",
]
