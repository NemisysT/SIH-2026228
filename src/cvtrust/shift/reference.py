"""The reference population: identity, provenance, and the refusal to assume.

The single most consequential assumption in any drift analysis is the one
nobody writes down: *that the reference is right*.  Every metric in
:mod:`cvtrust.shift.metrics` answers "did the current population move relative
to the reference", and none of them can tell a current population that drifted
from a reference population that was contaminated in the first place.  A
poisoned reference makes a clean current population look shifted, and a
reference drawn from the same compromised source as the current population
makes a genuine shift invisible.

So this module does three things and refuses to do a fourth:

* it gives a reference population a **content identity** (a digest over the
  member sample digests and the feature space that embedded them), so two runs
  can be shown to have used the same reference or shown not to have;
* it records **how the reference was obtained** — declared by the operator from
  a separate corpus, declared as a subset of the dataset under assessment, or
  simply the dataset's own bulk — because those are three different strengths
  of claim;
* it carries the operator's **provenance statement** verbatim, unvalidated and
  labelled as unvalidated.

What it refuses to do is treat any of that as establishing that the reference
is trustworthy.  ``trusted`` is a tri-state whose default is ``UNKNOWN``, and
nothing in this package ever sets it to ``TRUSTED`` on its own evidence.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..core.hashing import sha256_canonical, short
from ..features.store import FeatureSet

REFERENCE_SCHEMA_VERSION = "1.0"


class ReferenceMode(str, Enum):
    """How the reference population was obtained.  Three different strengths."""

    #: A separate corpus the operator declared as the reference: the strongest
    #: available form, because the population under assessment cannot influence
    #: the baseline it is measured against.
    DECLARED_CORPUS = "DECLARED_CORPUS"
    #: A named subset of the dataset under assessment. Weaker: whoever chose
    #: the subset chose the baseline, and an adversary who contributed to both
    #: halves is inside the reference.
    DECLARED_SUBSET = "DECLARED_SUBSET"
    #: No reference was declared and the dataset's own bulk was used. Weakest,
    #: and reported as such: a contributor supplying a large share of the data
    #: moves the reference towards themselves (the same failure ADR-007 guards
    #: against in contributor aggregation).
    SELF = "SELF"


class ReferenceTrust(str, Enum):
    """What is known about the reference's own integrity.

    Set by the operator, never inferred.  ``ASSESSED_CLEAN`` means a Module 1
    scan of the reference corpus produced no actionable findings and the
    operator chose to record that; it is still a statement about the attack
    classes that scan covered.
    """

    UNKNOWN = "UNKNOWN"
    ASSERTED_BY_OPERATOR = "ASSERTED_BY_OPERATOR"
    ASSESSED_CLEAN = "ASSESSED_CLEAN"


class ReferencePopulation(BaseModel):
    """A reference population and everything known about where it came from."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = REFERENCE_SCHEMA_VERSION
    reference_id: str
    mode: ReferenceMode
    trust: ReferenceTrust = ReferenceTrust.UNKNOWN
    #: Content digest over the member sample digests plus the feature space.
    #: Two reference populations with the same digest are the same population
    #: embedded the same way; a different digest means the comparison is not
    #: the comparison somebody else ran.
    digest: str
    sample_count: int
    #: Free-text operator statement: where the imagery came from, when, under
    #: what authority.  Recorded verbatim and **never validated** — it is a
    #: claim in the report, not a fact the system checked.
    provenance: str | None = None
    version: str | None = None
    manifest_id: str | None = None
    manifest_digest: str | None = None
    locator: str | None = None
    #: The dataset the current population came from, when the reference is a
    #: subset of it.  Present so the report can say the two are not independent.
    shared_dataset_digest: str | None = None
    feature_space: dict[str, Any] = Field(default_factory=dict)
    sample_ids: tuple[str, ...] = ()

    def caveat(self) -> str:
        """The one sentence an analyst must read before believing any metric."""
        base = {
            ReferenceMode.DECLARED_CORPUS: (
                "The reference is a separately declared corpus. Its own integrity "
                "was not established by this analysis"
            ),
            ReferenceMode.DECLARED_SUBSET: (
                "The reference is a declared subset of the same dataset under "
                "assessment, so the two populations are not independent and a "
                "contributor present in both is inside the baseline"
            ),
            ReferenceMode.SELF: (
                "No reference was declared, so the dataset's own bulk was used. A "
                "contributor supplying a large share of the data moves the "
                "reference towards themselves, which weakens every metric below"
            ),
        }[self.mode]
        trust = {
            ReferenceTrust.UNKNOWN: (
                "nothing is known about whether the reference is itself "
                "contaminated"
            ),
            ReferenceTrust.ASSERTED_BY_OPERATOR: (
                "the operator asserts the reference is clean; this analysis did "
                "not verify that assertion"
            ),
            ReferenceTrust.ASSESSED_CLEAN: (
                "a dataset assessment of the reference reported no actionable "
                "findings, which covers only the attack classes that assessment "
                "declared SUPPORTED or PARTIAL"
            ),
        }[self.trust]
        return f"{base}, and {trust}."

    def describe(self) -> dict[str, Any]:
        return {
            "reference_id": self.reference_id,
            "mode": self.mode.value,
            "trust": self.trust.value,
            "digest": self.digest,
            "sample_count": self.sample_count,
            "provenance": self.provenance,
            "provenance_validated": False,
            "version": self.version,
            "manifest_id": self.manifest_id,
            "manifest_digest": self.manifest_digest,
            "locator": self.locator,
            "shared_dataset_digest": self.shared_dataset_digest,
            "feature_space": self.feature_space,
            "caveat": self.caveat(),
        }


class PopulationView(BaseModel):
    """The materialised numbers for one population, ready for the metrics.

    Separated from :class:`ReferencePopulation` because the *current* population
    needs exactly the same materialisation and has none of the provenance
    apparatus: it is simply the thing being assessed.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    name: str
    sample_ids: tuple[str, ...]
    embeddings: Any
    acquisition: Any
    acquisition_names: tuple[str, ...]
    class_counts: dict[str, int] = Field(default_factory=dict)
    contributor_counts: dict[str, int] = Field(default_factory=dict)
    metadata_counts: dict[str, dict[str, int]] = Field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.sample_ids)


def population_digest(
    sample_digests: Sequence[str], feature_space: dict[str, Any]
) -> str:
    """Content identity of a population: which samples, embedded how.

    The feature space is inside the digest deliberately.  The same images
    embedded by a different extractor are a different reference for the purpose
    of a distance metric, and letting the two share an identity would let a
    reviewer compare two incomparable runs and conclude the drift had changed.
    """
    return sha256_canonical(
        {
            "samples": sorted(sample_digests),
            "feature_space": {
                "name": feature_space.get("name"),
                "version": feature_space.get("version"),
                "dim": feature_space.get("dim"),
            },
        }
    )


def build_population(
    name: str,
    *,
    features: FeatureSet,
    sample_ids: Iterable[str] | None = None,
    labels: dict[str, str] | None = None,
    contributors: dict[str, str] | None = None,
    metadata: dict[str, dict[str, str]] | None = None,
) -> PopulationView:
    """Materialise one population from a feature set.

    Only samples that actually decoded are included, and the caller is told how
    many were dropped: an unreadable file is a Module 1 finding, and silently
    shrinking a population here would make a corrupt-file attack look like a
    smaller sample rather than a data-integrity problem.
    """
    wanted = None if sample_ids is None else set(sample_ids)
    rows: list[int] = []
    ids: list[str] = []
    for row in features.valid_rows():
        sample_id = features.sample_ids[int(row)]
        if wanted is not None and sample_id not in wanted:
            continue
        rows.append(int(row))
        ids.append(sample_id)

    index = np.array(rows, dtype=int)
    embeddings = (
        features.embeddings[index]
        if index.size
        else np.zeros((0, features.embeddings.shape[1]), dtype=np.float32)
    )
    acquisition = (
        features.acquisition[index]
        if index.size and features.acquisition.size
        else np.zeros((0, len(features.acquisition_names)), dtype=np.float64)
    )

    class_counts: dict[str, int] = {}
    contributor_counts: dict[str, int] = {}
    metadata_counts: dict[str, dict[str, int]] = {}
    for sample_id in ids:
        if labels and sample_id in labels:
            label = labels[sample_id]
            class_counts[label] = class_counts.get(label, 0) + 1
        if contributors and sample_id in contributors:
            who = contributors[sample_id]
            contributor_counts[who] = contributor_counts.get(who, 0) + 1
        for key, mapping in (metadata or {}).items():
            value = mapping.get(sample_id)
            if value is None:
                continue
            bucket = metadata_counts.setdefault(key, {})
            bucket[value] = bucket.get(value, 0) + 1

    return PopulationView(
        name=name,
        sample_ids=tuple(ids),
        embeddings=embeddings,
        acquisition=acquisition,
        acquisition_names=features.acquisition_names,
        class_counts=class_counts,
        contributor_counts=contributor_counts,
        metadata_counts=metadata_counts,
    )


def describe_reference(
    view: PopulationView,
    *,
    mode: ReferenceMode,
    feature_space: dict[str, Any],
    sample_digests: Sequence[str],
    trust: ReferenceTrust = ReferenceTrust.UNKNOWN,
    provenance: str | None = None,
    version: str | None = None,
    manifest_id: str | None = None,
    manifest_digest: str | None = None,
    locator: str | None = None,
    shared_dataset_digest: str | None = None,
) -> ReferencePopulation:
    digest = population_digest(sample_digests, feature_space)
    return ReferencePopulation(
        reference_id=f"REF-{short(digest, 12)}",
        mode=mode,
        trust=trust,
        digest=digest,
        sample_count=view.size,
        provenance=provenance,
        version=version,
        manifest_id=manifest_id,
        manifest_digest=manifest_digest,
        locator=str(locator) if locator else None,
        shared_dataset_digest=shared_dataset_digest,
        feature_space=feature_space,
        sample_ids=view.sample_ids,
    )


def load_reference_ids(path: Path | str) -> list[str]:
    """Read a declared reference sample-id list, in either accepted shape."""
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [str(item) for item in payload]
    return [str(item) for item in payload.get("samples", [])]


__all__ = [
    "REFERENCE_SCHEMA_VERSION", "ReferenceMode", "ReferenceTrust",
    "ReferencePopulation", "PopulationView", "build_population",
    "describe_reference", "population_digest", "load_reference_ids",
]
