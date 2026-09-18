"""Detector framework.

Two contracts are enforced here rather than left to each detector's discipline:

1. **A detector that cannot run says so.**  Returning zero findings because a
   prerequisite was missing is indistinguishable, in a report, from returning
   zero findings because the dataset is clean.  Detectors therefore declare
   coverage per attack class, and an unmet requirement becomes
   ``NOT_ASSESSED`` with a machine-readable reason.

2. **Confidence goes through one door.**  :meth:`FindingFactory.emit` is the
   only way to construct a :class:`~cvtrust.core.evidence.Finding` in this
   codebase; it resolves confidence through the calibration set, applies the
   disposition policy, and attaches the calibration provenance as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, Sequence, runtime_checkable

from ..core.config import Config
from ..core.context import RunContext
from ..core.evidence import (
    UNCALIBRATED_LIMITATION,
    AssetRef,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Finding,
    Severity,
    make_finding_id,
    utc_now_iso,
)
from ..core.registry import Registry
from ..datasets.base import IngestIssue, RawDataset
from ..datasets.contributors import Attribution
from ..datasets.manifest import DatasetManifest
from ..features.store import FeatureSet, ObjectFeatureSet
from ..risk.calibration import CalibrationSet
from ..risk.coverage import ATTACK_CLASS_REGISTRY, CoverageEntry
from ..risk.disposition import DispositionPolicy


@dataclass
class AnalysisContext:
    """Everything a detector is allowed to see.

    Note what is *not* here: attack ground truth.  The attack lab writes ground
    truth outside the dataset root and the evaluation harness joins it to
    findings afterwards, so a detector can never accidentally read the answer.
    """

    dataset: RawDataset
    manifest: DatasetManifest
    features: FeatureSet
    objects: ObjectFeatureSet | None
    attributions: dict[str, Attribution]
    issues: list[IngestIssue]
    config: Config
    run: RunContext
    calibration: CalibrationSet
    policy: DispositionPolicy
    reference_sample_ids: frozenset[str] | None = None
    #: Cross-detector artifacts, e.g. near-duplicate groups that the label
    #: detector must exclude from neighbourhoods.  Detectors run in a fixed
    #: order (see ``pipeline.py``) so this is a dependency, not a race.
    shared: dict[str, Any] = field(default_factory=dict)

    def contributor_of(self, sample_id: str) -> str:
        attribution = self.attributions.get(sample_id)
        return attribution.contributor if attribution else self.config.contributor.unknown_label

    def sample_asset(self, sample_id: str) -> AssetRef:
        record = self.manifest.sample(sample_id)
        return AssetRef(
            type=AssetType.SAMPLE,
            id=sample_id,
            locator=record.relpath if record else sample_id,
            digest=record.file_sha256 if record else None,
        )

    def dataset_asset(self) -> AssetRef:
        return AssetRef(
            type=AssetType.DATASET,
            id=self.manifest.dataset.get("name", "dataset"),
            locator=str(self.dataset.root),
            digest=self.manifest.digest,
        )

    def contributor_asset(self, contributor: str) -> AssetRef:
        return AssetRef(type=AssetType.CONTRIBUTOR, id=contributor)


@dataclass
class DetectorOutput:
    detector: str
    version: str
    findings: list[Finding] = field(default_factory=list)
    coverage: list[CoverageEntry] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    #: Raw per-sample scores, keyed by attack class, kept for the evaluation
    #: harness to build calibration tables from.  Not part of the report.
    scores: dict[str, dict[str, float]] = field(default_factory=dict)
    #: Sample ids the detector actually flagged, keyed by attack class.  The
    #: evaluation harness scores against this rather than inferring positives
    #: from evidence refs -- a near-duplicate finding refs its whole cluster
    #: (all positives) while a label finding refs its neighbours (mostly
    #: negatives), so inference would silently corrupt the metrics.
    flagged: dict[str, set[str]] = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    name: str
    version: str
    attack_classes: tuple[str, ...]

    def run(self, ctx: AnalysisContext) -> DetectorOutput: ...


DETECTORS: Registry[Detector] = Registry("detector")


@runtime_checkable
class FactoryContext(Protocol):
    """The only two things :class:`FindingFactory` has ever needed.

    Widened from :class:`AnalysisContext` in Module 2 so that the model-side
    context (:class:`~cvtrust.detectors.model_base.ModelAnalysisContext`) can
    use the *same* construction path.  There is deliberately no second factory:
    "confidence goes through one door" is a property of the whole system, not
    of the dataset half of it, and a Module 2 finding must be built under the
    same calibration and disposition rules as a Module 1 one.

    This is a type-level widening only — the factory's behaviour is unchanged.
    """

    calibration: CalibrationSet
    policy: DispositionPolicy


class FindingFactory:
    """The single construction path for findings."""

    def __init__(self, ctx: FactoryContext, detector: str, version: str) -> None:
        self._ctx = ctx
        self._detector = detector
        self._version = version

    def emit(
        self,
        *,
        attack_class: str,
        asset: AssetRef,
        title: str,
        severity: Severity,
        evidence: Sequence[EvidenceItem],
        coverage: Coverage,
        category: Category = Category.DATA,
        contributor: str | None = None,
        discriminator: Sequence[str] = (),
        score: float | None = None,
        prior: float | None = None,
        confidence: float | None = None,
        basis: ConfidenceBasis | None = None,
        assumptions: Sequence[str] = (),
        limitations: Sequence[str] = (),
    ) -> Finding:
        """Build a finding, resolving confidence and disposition by policy.

        Either supply ``confidence`` + ``basis`` directly (for deterministic
        facts and hypothesis tests, where the number is derived in the detector)
        or supply ``score`` + ``prior`` and let the calibration set decide.
        """
        evidence_items = list(evidence)
        limitation_list = list(limitations)

        if confidence is None:
            if score is None or prior is None:
                raise ValueError(
                    "emit() requires either an explicit confidence/basis or a "
                    "score/prior pair to resolve against the calibration set"
                )
            confidence, basis, provenance = self._ctx.calibration.resolve(
                detector=self._detector,
                detector_version=self._version,
                attack_class=attack_class,
                score=score,
                prior=prior,
            )
            evidence_items.append(
                EvidenceItem(
                    kind="confidence_calibration",
                    statement=(
                        "Confidence is the measured lower-bound precision of this "
                        "detector in this score range."
                        if basis is ConfidenceBasis.CALIBRATED
                        else "No measured calibration exists for this detector "
                        "version; confidence is a capped prior."
                    ),
                    observation=provenance,
                    refs=(),
                )
            )
        if basis is None:
            raise ValueError("confidence basis must be supplied with an explicit confidence")

        if basis is ConfidenceBasis.HEURISTIC_UNCALIBRATED:
            limitation_list.append(UNCALIBRATED_LIMITATION)

        decision = self._ctx.policy.decide(
            severity=severity, confidence=confidence, coverage=coverage, basis=basis
        )

        return Finding(
            finding_id=make_finding_id(
                method=self._detector,
                method_version=self._version,
                attack_class=attack_class,
                asset=asset,
                discriminator=discriminator,
            ),
            observed_at=utc_now_iso(),
            asset=asset,
            contributor=contributor,
            category=category,
            attack_class=attack_class,
            title=title,
            severity=severity,
            confidence=round(float(confidence), 4),
            confidence_basis=basis,
            evidence=tuple(evidence_items),
            method=self._detector,
            method_version=self._version,
            assumptions=tuple(assumptions),
            limitations=tuple(limitation_list),
            coverage=coverage,
            disposition=decision.disposition,
            disposition_rule=decision.rule_id,
        )


def coverage_entry(
    attack_class: str,
    coverage: Coverage,
    *,
    detector: str,
    detector_version: str,
    reason: str | None = None,
    assumptions: Iterable[str] = (),
    limitations: Iterable[str] = (),
) -> CoverageEntry:
    meta = ATTACK_CLASS_REGISTRY.get(attack_class, {})
    return CoverageEntry(
        attack_class=attack_class,
        title=str(meta.get("title", attack_class)),
        coverage=coverage,
        owning_module=int(meta.get("module", 1)),
        detector=detector,
        detector_version=detector_version,
        reason=reason,
        assumptions=tuple(assumptions),
        limitations=tuple(limitations),
    )
