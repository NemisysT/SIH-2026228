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
    "distribution_shift": {"title": "Distribution shift", "module": 4,
                           "description": "Population-level deviation from a declared "
                           "reference distribution (terrain, season, sensor, illumination)."},
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
