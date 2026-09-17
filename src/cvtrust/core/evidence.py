"""The common evidence schema.

This module is deliberately the most conservative in the codebase.  Every module
of the platform — dataset forensics (M1), model forensics (M2), inference
provenance (M3), distribution analysis (M4) and the analyst UI (M5) — emits
:class:`Finding` objects in *this* shape.  Changing it is a breaking change and
requires bumping ``SCHEMA_VERSION``.

The central rule this schema enforces structurally, not by convention:

    A finding may not assert anything it cannot show the analyst.

Concretely, :class:`Finding` requires at least one :class:`EvidenceItem`, and
every ``EvidenceItem`` carries an ``observation`` mapping holding the raw
measured values behind the claim (hamming distances, neighbour ids, p-values,
counts).  An analyst — or a hostile reviewer — can recompute the claim from the
observation.  A score with no reproducible observation cannot be represented.
"""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Any, Final, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .hashing import sha256_canonical, short

SCHEMA_VERSION: Final[str] = "1.0"


class Severity(str, Enum):
    """How consequential the finding would be *if true*.

    Severity is deliberately independent of :class:`ConfidenceBasis` and of the
    confidence value.  Conflating "how sure are we" with "how bad is it" is the
    single most common way risk dashboards become meaningless.
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(str, Enum):
    """Which assurance domain produced the finding."""

    DATA = "DATA"
    MODEL = "MODEL"
    INFERENCE = "INFERENCE"
    DISTRIBUTION = "DISTRIBUTION"
    PIPELINE = "PIPELINE"


class Coverage(str, Enum):
    """Whether this attack class was actually tested, and how well.

    ``NOT_ASSESSED`` is a first-class, *visible* outcome.  A detector that could
    not run must say so here rather than returning zero findings, which an
    analyst would otherwise read as "clean".
    """

    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_ASSESSED = "NOT_ASSESSED"
    REQUIRES_WHITE_BOX = "REQUIRES_WHITE_BOX"


class Disposition(str, Enum):
    """Recommended analyst action."""

    ACCEPT = "ACCEPT"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"


class ConfidenceBasis(str, Enum):
    """Where a confidence number came from.  There are only four legal answers.

    ``DETERMINISTIC``
        The claim is a verified fact, not an inference: SHA-256 equality, a
        bounding box outside the image, JSON that does not parse.  Confidence
        is 1.0 and means it.

    ``STATISTICAL``
        The claim rests on a hypothesis test.  Confidence is ``1 - q`` where
        ``q`` is the multiple-testing-adjusted p-value.

    ``CALIBRATED``
        The claim rests on a threshold whose empirical precision was *measured*
        on attack-lab scenarios.  Confidence is the Wilson lower bound of that
        measured precision, and the finding carries the calibration provenance.

    ``HEURISTIC_UNCALIBRATED``
        No calibration table exists for this detector version.  Confidence is a
        documented prior, capped at :data:`UNCALIBRATED_CONFIDENCE_CAP`, and the
        finding is required to carry the ``uncalibrated`` limitation.
    """

    DETERMINISTIC = "DETERMINISTIC"
    STATISTICAL = "STATISTICAL"
    CALIBRATED = "CALIBRATED"
    HEURISTIC_UNCALIBRATED = "HEURISTIC_UNCALIBRATED"


#: Ceiling applied to any confidence that has no measured calibration behind it.
UNCALIBRATED_CONFIDENCE_CAP: Final[float] = 0.60

#: Ceiling applied to statistical confidence.  A p-value of 1e-40 does not mean
#: certainty; it means the null model is wrong, which is not the same claim.
STATISTICAL_CONFIDENCE_CAP: Final[float] = 0.99

#: Marker limitation string required on every uncalibrated finding.
UNCALIBRATED_LIMITATION: Final[str] = (
    "uncalibrated: no measured precision exists for this detector version; "
    "confidence is a documented prior, not an empirical rate"
)


class AssetType(str, Enum):
    DATASET = "dataset"
    SAMPLE = "sample"
    ANNOTATION = "annotation"
    CONTRIBUTOR = "contributor"
    BATCH = "batch"
    SOURCE = "source"
    MODEL = "model"
    INFERENCE = "inference"
    PIPELINE = "pipeline"


class AssetRef(BaseModel):
    """A stable pointer to the thing a finding is about."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: AssetType
    id: str = Field(min_length=1, description="Stable identifier within its type.")
    locator: str | None = Field(
        default=None, description="Where to find it: dataset-relative path, URI."
    )
    digest: str | None = Field(
        default=None, description="SHA-256 of the asset, when the asset is bytes."
    )

    def key(self) -> str:
        return f"{self.type.value}:{self.id}"


class EvidenceItem(BaseModel):
    """One observation supporting a finding.

    ``statement`` is for the analyst; ``observation`` is for the reviewer who
    does not believe the statement.  Both are mandatory.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Field(
        min_length=1,
        description="Stable machine id for the observation type, e.g. "
        "'perceptual_hash_distance', 'binomial_test'.",
    )
    statement: str = Field(
        min_length=1, description="Human-readable reason, one sentence."
    )
    observation: Mapping[str, Any] = Field(
        description="Raw measured values behind the statement. Must be enough "
        "to recompute or spot-check the claim. Required: an evidence item with "
        "no measured values is not evidence.",
    )
    refs: tuple[str, ...] = Field(
        default=(),
        description="Sample ids, file paths or other finding ids this "
        "observation points at, for lineage.",
    )

    @field_validator("observation")
    @classmethod
    def _non_empty_observation(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        if not value:
            raise ValueError(
                "evidence must carry a non-empty observation; a statement "
                "without measured values is not evidence"
            )
        return value


class Finding(BaseModel):
    """A single assurance finding.  The unit of currency across all modules."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(pattern=r"^F-[0-9a-f]{12}$")
    schema_version: str = SCHEMA_VERSION
    observed_at: str = Field(description="UTC ISO-8601. Excluded from finding_id.")

    asset: AssetRef
    contributor: str | None = None
    category: Category
    attack_class: str = Field(min_length=1)
    title: str = Field(min_length=1)

    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_basis: ConfidenceBasis

    evidence: tuple[EvidenceItem, ...] = Field(min_length=1)

    method: str = Field(min_length=1)
    method_version: str = Field(min_length=1)

    assumptions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    coverage: Coverage

    disposition: Disposition
    disposition_rule: str = Field(
        min_length=1, description="Id of the policy rule that chose the disposition."
    )

    @field_validator("limitations")
    @classmethod
    def _dedupe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        seen: list[str] = []
        for item in value:
            if item not in seen:
                seen.append(item)
        return tuple(seen)

    def model_post_init(self, _context: Any) -> None:
        # Enforce the confidence contract structurally rather than by review.
        if self.confidence_basis is ConfidenceBasis.DETERMINISTIC:
            if self.confidence != 1.0:
                raise ValueError(
                    "DETERMINISTIC confidence must be exactly 1.0; if the claim "
                    "is an inference, use another basis"
                )
        if self.confidence_basis is ConfidenceBasis.HEURISTIC_UNCALIBRATED:
            if self.confidence > UNCALIBRATED_CONFIDENCE_CAP:
                raise ValueError(
                    f"uncalibrated confidence {self.confidence} exceeds the cap "
                    f"{UNCALIBRATED_CONFIDENCE_CAP}"
                )
            if UNCALIBRATED_LIMITATION not in self.limitations:
                raise ValueError(
                    "an uncalibrated finding must declare the 'uncalibrated' limitation"
                )
        if self.confidence_basis is ConfidenceBasis.STATISTICAL:
            if self.confidence > STATISTICAL_CONFIDENCE_CAP:
                raise ValueError(
                    f"statistical confidence {self.confidence} exceeds the cap "
                    f"{STATISTICAL_CONFIDENCE_CAP}"
                )

    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def sort_key(self) -> tuple[int, float, str]:
        """Deterministic ordering: severity desc, confidence desc, id asc."""
        return (-self.severity_rank(), -self.confidence, self.finding_id)


def make_finding_id(
    *,
    method: str,
    method_version: str,
    attack_class: str,
    asset: AssetRef,
    discriminator: Sequence[str] = (),
) -> str:
    """Derive a deterministic, content-addressed finding id (ADR-003).

    A positional counter (``F-001``, ``F-002``) shifts whenever an unrelated
    finding appears or disappears, which breaks cross-run diffing, breaks
    references held by an analyst, and makes regression tests brittle.  Instead
    the id is a truncated SHA-256 over the finding's *identity*: which detector,
    looking at which asset, for which attack class, distinguished by a
    detector-supplied discriminator (e.g. the peer sample in a duplicate pair).

    Deliberately excluded from the id: timestamps, scores, severity and
    confidence.  Re-running a detector after recalibration must produce the
    *same* id for the same underlying observation, so the analyst sees an
    updated finding rather than a new one.
    """
    payload = {
        "method": method,
        "method_version": method_version,
        "attack_class": attack_class,
        "asset_type": asset.type.value,
        "asset_id": asset.id,
        "discriminator": list(discriminator),
    }
    return f"F-{short(sha256_canonical(payload), 12)}"


def utc_now_iso() -> str:
    """Current UTC time, ISO-8601, second precision, explicit ``Z``."""
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
