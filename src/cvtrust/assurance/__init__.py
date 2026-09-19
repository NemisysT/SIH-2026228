"""Module 4 — cross-module evidence fusion and the assurance policy engine.

Four packages feed this one.  What it adds is not another detector: it is the
apparatus for saying what a *pipeline* can defensibly be concluded to be, given
evidence of four different kinds about four different artifacts, some of which
was never gathered.
"""

from .decision import (
    AssuranceDecision,
    EvidenceReference,
    LineageNode,
    UnassessedArea,
)
from .evidence import (
    EvidenceGraph,
    EvidenceGroup,
    EvidenceLineage,
    NormalizedEvidence,
    build_graph,
    normalise,
    normalise_all,
    summarise_evidence,
)
from .families import (
    CONFOUNDED_BY,
    FAMILY_OF,
    EvidenceClass,
    EvidenceFamily,
    classify,
    describe_families,
)
from .fuse import (
    ASSURANCE_LIMITATIONS,
    FusionInputs,
    FusionResult,
    ModuleInput,
    fuse,
)
from .policy import (
    ASSURANCE_POLICY_VERSION,
    RULES,
    AssuranceDisposition,
    AssurancePolicyEngine,
    AssuranceRule,
    PolicyState,
    RuleOutcome,
    Scope,
    ScopeDecision,
    overall,
)

__all__ = [
    "AssuranceDecision", "EvidenceReference", "LineageNode", "UnassessedArea",
    "EvidenceGraph", "EvidenceGroup", "EvidenceLineage", "NormalizedEvidence",
    "build_graph", "normalise", "normalise_all", "summarise_evidence",
    "EvidenceClass", "EvidenceFamily", "FAMILY_OF", "CONFOUNDED_BY",
    "classify", "describe_families",
    "FusionInputs", "FusionResult", "ModuleInput", "fuse",
    "ASSURANCE_LIMITATIONS",
    "ASSURANCE_POLICY_VERSION", "AssuranceDisposition", "AssurancePolicyEngine",
    "AssuranceRule", "PolicyState", "RuleOutcome", "RULES", "Scope",
    "ScopeDecision", "overall",
]
