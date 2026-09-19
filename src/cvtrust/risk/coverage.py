"""Coverage statement: what was tested, what was not, and what is not supported.

The problem statement requires the system to "explicitly declare coverage and
limitations".  This module makes that a structured artifact rather than a
paragraph in a README: the report carries one entry per attack class known to
the platform, including the ones no detector in this build can assess.

A clean report from a system that never tested for an attack class is not a
clean result, and this is the artifact that makes the difference visible.
"""

from __future__ import annotations

from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import Coverage

#: Every attack class the platform knows about, with the module that owns it.
#: Classes owned by a later module appear here from day one, declared
#: NOT_ASSESSED, so that no report can imply coverage the build does not have.
ATTACK_CLASS_REGISTRY: dict[str, dict[str, Any]] = {
    "duplicate_flood": {
        "title": "Exact duplicate flooding",
        "module": 1,
        "description": "Identical samples submitted repeatedly to skew class balance "
        "or amplify a subset of the distribution.",
    },
    "near_duplicate_flood": {
        "title": "Near-duplicate flooding",
        "module": 1,
        "description": "Perceptually near-identical variants (re-encode, crop, "
        "photometric edit) submitted in bulk.",
    },
    "label_flip": {
        "title": "Label flipping",
        "module": 1,
        "description": "Individual labels changed to an incorrect class.",
    },
    "systematic_mislabel": {
        "title": "Systematic mislabelling",
        "module": 1,
        "description": "A consistent, directional label mapping applied by a "
        "contributor or batch.",
    },
    "ood_insertion": {
        "title": "Out-of-distribution insertion",
        "module": 1,
        "description": "Samples drawn from a different distribution than the "
        "declared reference.",
    },
    "metadata_inconsistency": {
        "title": "Malformed or inconsistent dataset metadata",
        "module": 1,
        "description": "Annotations that contradict the files they describe: "
        "missing images, wrong dimensions, out-of-bounds or invalid boxes, "
        "undeclared categories, duplicate identifiers.",
    },
    "dataset_tamper": {
        "title": "Post-baseline dataset modification",
        "module": 1,
        "description": "Files added, removed or modified after an integrity "
        "baseline was established.",
        # Assessed by a distinct command, because it is the only class here that
        # needs a second observation in time: a scan of a dataset cannot tell
        # you it changed, only a comparison against an earlier manifest can.
        "assessed_by": "`cvtrust dataset verify <manifest> <root>`, which "
        "re-hashes the dataset against a previously established manifest",
    },
    "trigger_injection": {
        "title": "Backdoor trigger injection in training data",
        "module": 2,
        "description": "Localised trigger patterns embedded in training samples to "
        "install a backdoor.",
        # An open item, and named as one. ADR-008 deferred *data-side* trigger
        # detection to Module 2 because doing it without the model-side
        # counterpart would have been a partial capability presented as a
        # complete one. Module 2 delivered the model side in full and
        # deliberately did not add a dataset-image detector, which is dataset
        # forensics rather than model forensics. Saying "no detector reported on
        # this class" would be true but would hide the history, so the reason
        # says what actually happened (ADR-011).
        "assessed_by": "NOT IMPLEMENTED — this is the data-side counterpart to "
        "Module 2's model-side backdoor assessment. The model side "
        "(`model_backdoor`) is implemented; detecting trigger artifacts in "
        "training *images* remains an open item, deliberately out of scope for "
        "a model-forensics module. See ADR-011 and docs/model-security.md §10.",
    },
    "model_substitution": {
        "title": "Model substitution", "module": 2,
        "description": "A different model served in place of the assured one. "
        "Assessed by cryptographic content identity over three digests (file, "
        "graph, parameters), which separates a re-serialisation from a genuine "
        "substitution. Requires a trusted reference model.",
    },
    "model_tampering": {
        "title": "Model modification", "module": 2,
        "description": "Weights or graph altered after assurance. Assessed "
        "deterministically against a trusted reference and localised to named "
        "tensors; degrades to peer-group screening and metamorphic consistency "
        "when no reference is available.",
    },
    "model_backdoor": {
        "title": "Backdoored model behaviour", "module": 2,
        "description": "Model behaves anomalously on triggered inputs. Assessed "
        "by a gradient-free sweep of a declared patch-trigger family, and — "
        "where the artifact exposes input gradients — by Neural Cleanse trigger "
        "reconstruction. Coverage is bounded by the declared family; "
        "sample-specific, semantic and adaptive triggers are NOT assessed.",
    },
    "inference_tampering": {
        "title": "Inference record modification", "module": 3,
        "description": "Output, input, model reference or configuration altered "
        "after inference. Assessed deterministically: every bound field is "
        "covered by an Ed25519 signature over canonical bytes, and each binding "
        "is additionally checked against the artifact the analyst independently "
        "holds, so a forger who re-signs with their own key is still caught by "
        "the mismatch.",
    },
    "inference_replay": {
        "title": "Inference replay", "module": 3,
        "description": "A previously valid inference record re-submitted. "
        "Assessed against a local replay database: exact re-presentation, nonce "
        "reuse and sequence collision are detected. Bounded by the database's "
        "retention, and deliberately distinct from the same input legitimately "
        "processed twice, which is not replay.",
    },
    "record_reordering": {
        "title": "Audit record reordering", "module": 3,
        "description": "Records resequenced, inserted, deleted or duplicated "
        "within the audit trail. Assessed by hash-chain linkage over the signed "
        "entry digest plus contiguous sequence numbers.",
    },
    "provenance_key_trust": {
        "title": "Provenance signed by an unauthorised key", "module": 3,
        "description": "A record signed by a key the operator has not "
        "authorised, has revoked, or that was outside its validity window. "
        "Cryptographic validity and key authority are separate facts and are "
        "never collapsed: anyone can generate a keypair, so a valid signature "
        "from an unknown key establishes nothing.",
    },
    "chain_truncation": {
        "title": "Audit log truncation", "module": 3,
        "description": "Entries removed from the end of a provenance log. "
        "Front truncation is self-detectable from the genesis rule. Tail "
        "truncation is NOT self-detectable -- a truncated chain is internally "
        "perfect -- and is assessed only against an out-of-band log anchor.",
        "assessed_by": "`cvtrust provenance verify-log --anchor <anchor.json>`, "
        "which compares the log head against a digest recorded out of band. "
        "Without an anchor the outcome is NOT_DETECTABLE, never clean.",
    },
    "distribution_shift": {
        "title": "Distribution shift", "module": 4,
        "description": "Population-level deviation from a declared reference "
        "distribution (terrain, season, sensor, illumination). Assessed by a "
        "permutation energy test over the joint feature distribution, with the "
        "movement attributed to feature views and checked against the declared "
        "operational context. PARTIAL at best: the result is bounded by the "
        "reference population's own integrity, which this system does not "
        "establish, and a shift is never equated with an attack.",
        "assessed_by": "`cvtrust assurance shift <reference> <current>`, which "
        "needs a reference population. Without one the outcome is NOT_ASSESSED, "
        "never a stable population.",
    },
}

#: Module 4 capabilities that are **not attack classes**.
#:
#: Operational drift is not an attack and evidence fusion is not a thing an
#: adversary does, so putting either in ``ATTACK_CLASS_REGISTRY`` would make the
#: attack matrix mean two different things at once.  They still need a coverage
#: declaration — the brief requires one, and an analyst needs to know whether
#: the fusion engine actually ran — so they get their own registry with the same
#: :class:`Coverage` vocabulary and the same rule: a capability that did not run
#: says so.
ASSURANCE_CAPABILITY_REGISTRY: dict[str, dict[str, Any]] = {
    # Listed as a capability as well as an attack class (ATTACK_CLASS_REGISTRY)
    # because the two answer different questions: the attack class says what an
    # adversary might do, this says what the engine can measure about it. A
    # reader auditing the capability list should not have to know to look in a
    # second table to find out whether shift was assessed at all.
    "distribution_shift": {
        "title": "Population-level distribution shift",
        "module": 4,
        "description": "Whether the current population is drawn from the same "
        "distribution as a declared reference, decided by a permutation energy "
        "test over the joint feature space with four supporting metrics, "
        "explicit sample-sufficiency handling, and a reference identity bound "
        "to the feature space it was measured in. Bounded by the reference "
        "population's own integrity, which nothing here establishes.",
    },
    "operational_drift": {
        "title": "Operational drift, distinguished from manipulation",
        "module": 4,
        "description": "Whether an observed population shift is accounted for by "
        "a declared operational change (season, terrain, sensor, illumination, "
        "acquisition mode). PARTIAL and permanently so: the mapping from a "
        "declared change to the feature views it would move is a documented, "
        "uncalibrated heuristic over one feature space, and a declaration is a "
        "claim by the supplying side that nothing here can verify.",
    },
    "evidence_fusion": {
        "title": "Cross-module evidence fusion",
        "module": 4,
        "description": "Findings from Modules 1-4 normalised into one evidence "
        "model and combined by an explicit, versioned rule table. No score, no "
        "weights, no arithmetic across evidence classes.",
    },
    "evidence_dependency": {
        "title": "Dependency-aware aggregation (double-counting prevention)",
        "module": 4,
        "description": "Evidence is grouped into phenomenon families and a "
        "family contributes at most one unit of independent support, however "
        "many findings or detectors it contains. Evidence whose confounding "
        "phenomenon is present in the run is marked and stops counting as "
        "independent corroboration.",
    },
    "cross_module_lineage": {
        "title": "Decision lineage back to source findings",
        "module": 4,
        "description": "Every disposition names the rules that produced it and "
        "every rule names the findings that made it fire, back to the module, "
        "detector and version that emitted them.",
    },
    "coverage_aware_assurance": {
        "title": "Coverage-aware disposition",
        "module": 4,
        "description": "A scope with no input is NOT_ASSESSED, never ACCEPT, and "
        "the unassessed areas are carried in the decision rather than inferred "
        "from an absence.",
    },
    "policy_disposition": {
        "title": "Explicit, versioned assurance policy",
        "module": 4,
        "description": "The rule table is data, is emitted verbatim into every "
        "report, and is reproducible from (inputs, policy version, "
        "configuration, seed, software version).",
    },
    "conflicting_evidence": {
        "title": "Preservation of conflicting evidence",
        "module": 4,
        "description": "Disagreement between evidence classes is recorded as a "
        "statement and never resolved into one narrative. The rule that records "
        "it carries ACCEPT so it can neither raise nor lower an outcome.",
    },
}


class CoverageEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    attack_class: str
    title: str
    coverage: Coverage
    owning_module: int
    detector: str | None = None
    detector_version: str | None = None
    reason: str | None = Field(
        default=None,
        description="Why the class was not assessed, when it was not.",
    )
    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class CoverageStatement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    implemented_modules: tuple[int, ...]
    entries: tuple[CoverageEntry, ...]

    @property
    def assessed(self) -> list[CoverageEntry]:
        return [
            e for e in self.entries
            if e.coverage in (Coverage.SUPPORTED, Coverage.PARTIAL)
        ]

    @property
    def unassessed(self) -> list[CoverageEntry]:
        return [e for e in self.entries if e not in self.assessed]

    @classmethod
    def build(
        cls,
        reported: Iterable[CoverageEntry],
        implemented_modules: tuple[int, ...] = (1,),
    ) -> "CoverageStatement":
        """Merge detector-reported coverage with the full attack-class registry.

        Anything a detector did not report on is emitted as ``NOT_ASSESSED``
        with the owning module named, so the gap is explicit.
        """
        by_class = {entry.attack_class: entry for entry in reported}
        entries: list[CoverageEntry] = []
        for attack_class, meta in sorted(ATTACK_CLASS_REGISTRY.items()):
            if attack_class in by_class:
                entries.append(by_class[attack_class])
                continue
            module = int(meta["module"])
            entries.append(
                CoverageEntry(
                    attack_class=attack_class,
                    title=str(meta["title"]),
                    coverage=Coverage.NOT_ASSESSED,
                    owning_module=module,
                    reason=(
                        f"owned by Module {module}, which is not part of this build"
                        if module not in implemented_modules
                        else str(meta.get("assessed_by"))
                        if meta.get("assessed_by")
                        else "no detector in this run reported on this class"
                    ),
                )
            )
        return cls(implemented_modules=implemented_modules, entries=tuple(entries))


class CapabilityEntry(BaseModel):
    """Coverage for a Module 4 capability that is not an attack class."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: str
    title: str
    coverage: Coverage
    owning_module: int
    detail: str | None = None
    reason: str | None = None
    limitations: tuple[str, ...] = ()


class CapabilityStatement(BaseModel):
    """The Module 4 capability matrix, built the same way as the attack one."""

    model_config = ConfigDict(extra="forbid")

    entries: tuple[CapabilityEntry, ...]

    @classmethod
    def build(cls, reported: Iterable[CapabilityEntry]) -> "CapabilityStatement":
        by_name = {entry.capability: entry for entry in reported}
        entries: list[CapabilityEntry] = []
        for name, meta in sorted(ASSURANCE_CAPABILITY_REGISTRY.items()):
            if name in by_name:
                entries.append(by_name[name])
                continue
            entries.append(
                CapabilityEntry(
                    capability=name,
                    title=str(meta["title"]),
                    coverage=Coverage.NOT_ASSESSED,
                    owning_module=int(meta["module"]),
                    detail=str(meta["description"]),
                    reason="this run did not exercise the capability",
                )
            )
        return cls(entries=tuple(entries))


#: What this BUILD implements, independent of any particular run.
#:
#: ``CapabilityStatement.build([])`` answers a different question -- "what did
#: THIS run exercise" -- and correctly answers NOT_ASSESSED for everything when
#: nothing ran.  ``cvtrust info`` describes the build, and printing
#: NOT_ASSESSED there would tell an operator the software cannot do something it
#: can, which is the same class of dishonesty as the reverse.
BUILD_CAPABILITY_COVERAGE: dict[str, Coverage] = {
    "distribution_shift": Coverage.PARTIAL,
    "operational_drift": Coverage.PARTIAL,
    "evidence_fusion": Coverage.SUPPORTED,
    "evidence_dependency": Coverage.PARTIAL,
    "cross_module_lineage": Coverage.SUPPORTED,
    "coverage_aware_assurance": Coverage.SUPPORTED,
    "policy_disposition": Coverage.SUPPORTED,
    "conflicting_evidence": Coverage.SUPPORTED,
}

#: Why each of the PARTIAL entries above is not SUPPORTED, printed next to it.
BUILD_CAPABILITY_BOUND: dict[str, str] = {
    "distribution_shift": "bounded by the reference population's own integrity, "
    "which this system does not establish; a shift is never an attack",
    "operational_drift": "the declared-change-to-feature-view mapping is an "
    "uncalibrated heuristic, and a declaration is never verified",
    "evidence_dependency": "independence is decided by a curated table, not "
    "measured; an unlisted correlation is not detected",
}


def build_capability_statement() -> "CapabilityStatement":
    """The capability matrix for this BUILD, not for a run."""
    return CapabilityStatement(
        entries=tuple(
            capability_entry(
                name,
                BUILD_CAPABILITY_COVERAGE[name],
                reason=BUILD_CAPABILITY_BOUND.get(name),
            )
            for name in sorted(ASSURANCE_CAPABILITY_REGISTRY)
        )
    )


def capability_entry(
    capability: str,
    coverage: Coverage,
    *,
    reason: str | None = None,
    limitations: Iterable[str] = (),
) -> CapabilityEntry:
    meta = ASSURANCE_CAPABILITY_REGISTRY[capability]
    return CapabilityEntry(
        capability=capability,
        title=str(meta["title"]),
        coverage=coverage,
        owning_module=int(meta["module"]),
        detail=str(meta["description"]),
        reason=reason,
        limitations=tuple(limitations),
    )
