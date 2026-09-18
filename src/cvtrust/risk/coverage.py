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
    },
    "model_substitution": {"title": "Model substitution", "module": 2,
                           "description": "A different model served in place of the assured one."},
    "model_tampering": {"title": "Model modification", "module": 2,
                        "description": "Weights or graph altered after assurance."},
    "model_backdoor": {"title": "Backdoored model behaviour", "module": 2,
                       "description": "Model behaves anomalously on triggered inputs."},
    "inference_tampering": {"title": "Inference record modification", "module": 3,
                            "description": "Output, input or configuration altered after inference."},
    "inference_replay": {"title": "Inference replay", "module": 3,
                         "description": "A previously valid inference record re-submitted."},
    "record_reordering": {"title": "Audit record reordering", "module": 3,
                          "description": "Records resequenced within the audit trail."},
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
