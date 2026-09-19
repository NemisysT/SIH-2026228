"""Shift observations expressed in the platform's one evidence schema.

Module 4 emits the same :class:`~cvtrust.core.evidence.Finding` objects that
Modules 1, 2 and 3 emit, through the same :class:`FindingFactory`, under the
same disposition policy.  There is no second finding type and no second
confidence system, for the reason ADR-002 gives: a schema that forks once forks
again, and the fusion engine downstream would then have to reconcile four
dialects of "confidence".

Two rules are enforced here rather than left to discipline.

**A shift finding is never CRITICAL and never claims intent.**  The highest
severity this module emits is ``MEDIUM``, and it is reserved for a shift the
declared context does not account for.  A population that moved is an operating
condition; it becomes a security concern only in combination with independent
integrity evidence, and that combination is the policy engine's decision to
make, not this module's.

**A shift finding is HEURISTIC_UNCALIBRATED unless the omnibus test produced
the claim.**  The energy test has a permutation null, so its confidence is
``1 - p`` on a ``STATISTICAL`` basis, capped like every other statistical
confidence.  The context-explanation reading has no null and no measured
precision, so anything resting on it is uncalibrated, capped at 0.60, and
carries the mandatory limitation.
"""

from __future__ import annotations

from typing import Any, Sequence

from ..core.evidence import (
    STATISTICAL_CONFIDENCE_CAP,
    AssetRef,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Finding,
    Severity,
)
from ..detectors.base import FindingFactory, coverage_entry
from ..risk.calibration import CalibrationSet
from ..risk.coverage import CoverageEntry
from ..risk.disposition import DispositionPolicy
from .characterize import ShiftAssessment, ShiftVerdict

SHIFT_METHOD = "distribution_shift"
SHIFT_METHOD_VERSION = "1.0"
ATTACK_CLASS = "distribution_shift"

#: Prior used when the claim rests on the context-explanation reading rather
#: than on the permutation test.  Low on purpose and capped lower still by the
#: uncalibrated ceiling: an unexplained movement in a heuristic feature
#: attribution is weak evidence of anything in particular.
UNCALIBRATED_PRIOR = 0.45


class _FactoryContext:
    """Minimal context for :class:`FindingFactory`.

    The factory needs exactly two things (see its ``FactoryContext`` protocol),
    and Module 4 has no dataset, model or log to carry — it has two populations.
    Constructing the pair explicitly is clearer than inventing a fourth analysis
    context object that would exist only to satisfy a type.
    """

    def __init__(self, calibration: CalibrationSet, policy: DispositionPolicy) -> None:
        self.calibration = calibration
        self.policy = policy


def _asset(assessment: ShiftAssessment, locator: str | None) -> AssetRef:
    return AssetRef(
        type=AssetType.DATASET,
        id=str(assessment.current.get("name") or assessment.current.get("id") or "current-population"),
        locator=locator,
        digest=assessment.current.get("digest"),
    )


def findings_for_shift(
    assessment: ShiftAssessment,
    *,
    calibration: CalibrationSet,
    policy: DispositionPolicy,
    locator: str | None = None,
    contributor: str | None = None,
) -> list[Finding]:
    """Zero or one finding per assessment.

    Zero when no shift was resolved: a metric that found nothing does not emit
    a finding saying so — the coverage entry and the report's shift section
    carry that, and manufacturing a "no shift" finding would put an ACCEPT row
    in the findings table that an analyst would have to read past every time.

    The unresolved cases *do* emit a finding, because ``INSUFFICIENT_SAMPLE``
    and ``NOT_ASSESSED`` are results an analyst must see, and the coverage
    statement alone is too easy to skim past.
    """
    factory = FindingFactory(
        _FactoryContext(calibration, policy), SHIFT_METHOD, SHIFT_METHOD_VERSION
    )
    asset = _asset(assessment, locator)
    energy = assessment.metric("energy_distance")

    if assessment.verdict is ShiftVerdict.NO_SHIFT_DETECTED:
        return []

    if not assessment.resolved():
        reason = (
            energy.reason
            if energy is not None and energy.reason
            else "no shift metric could be applied"
        )
        return [
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=asset,
                contributor=contributor,
                title="Population-level distribution shift was not assessed",
                severity=Severity.INFO,
                category=Category.DISTRIBUTION,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                coverage=(
                    Coverage.NOT_ASSESSED
                    if assessment.verdict is ShiftVerdict.NOT_ASSESSED
                    else Coverage.PARTIAL
                ),
                discriminator=(assessment.verdict.value,),
                evidence=[
                    EvidenceItem(
                        kind="shift_not_assessed",
                        statement=assessment.statement,
                        observation={
                            "verdict": assessment.verdict.value,
                            "reason": reason,
                            "reference_samples": assessment.reference.get("sample_count"),
                            "current_samples": assessment.current.get("sample_count"),
                            "metrics": [
                                {
                                    "metric": m.metric,
                                    "status": m.status.value,
                                    "reason": m.reason,
                                }
                                for m in assessment.metrics
                            ],
                        },
                    ),
                    _reference_evidence(assessment),
                ],
                assumptions=tuple(assessment.assumptions),
                limitations=(
                    "an unassessed attack class is an open question, not a clean "
                    "result: no statement about population-level shift is made here",
                    *assessment.limitations,
                ),
            )
        ]

    severity, confidence, basis, score = _grade(assessment, energy)
    evidence = [
        EvidenceItem(
            kind="population_shift",
            statement=assessment.statement,
            observation={
                "verdict": assessment.verdict.value,
                "reference_samples": assessment.reference.get("sample_count"),
                "current_samples": assessment.current.get("sample_count"),
            },
        )
    ]
    for result in assessment.metrics:
        evidence.append(
            EvidenceItem(
                kind=f"shift_metric.{result.metric}",
                statement=f"[{result.status.value}] {result.interpretation}",
                observation={
                    "metric": result.metric,
                    "version": result.version,
                    "status": result.status.value,
                    "statistic": result.statistic,
                    "p_value": result.p_value,
                    "significant": result.significant,
                    "requirement": result.requirement,
                    **(
                        {"reason": result.reason}
                        if result.reason
                        else {"detail": result.observation}
                    ),
                },
            )
        )
    if assessment.context is not None:
        evidence.append(
            EvidenceItem(
                kind="declared_context_check",
                statement=assessment.context.statement,
                observation={
                    "explanation": assessment.context.explanation.value,
                    "declared_reference": assessment.context.delta.reference,
                    "declared_current": assessment.context.delta.current,
                    "declared_changes": list(assessment.context.delta.changed),
                    "blocks_that_moved": list(assessment.context.moved_blocks),
                    "blocks_predicted": list(assessment.context.explained_blocks),
                    "blocks_unexplained": list(assessment.context.unexplained_blocks),
                    **assessment.context.observation,
                },
            )
        )
    evidence.append(_reference_evidence(assessment))

    kwargs: dict[str, Any] = (
        {"confidence": confidence, "basis": basis}
        if basis is not None
        else {"score": score, "prior": UNCALIBRATED_PRIOR}
    )
    return [
        factory.emit(
            attack_class=ATTACK_CLASS,
            asset=asset,
            contributor=contributor,
            title=_title(assessment.verdict),
            severity=severity,
            category=Category.DISTRIBUTION,
            coverage=Coverage.PARTIAL,
            discriminator=(assessment.verdict.value, assessment.reference["digest"][:16]),
            evidence=evidence,
            assumptions=tuple(assessment.assumptions),
            limitations=tuple(assessment.limitations),
            **kwargs,
        )
    ]


def _reference_evidence(assessment: ShiftAssessment) -> EvidenceItem:
    return EvidenceItem(
        kind="reference_population",
        statement=str(assessment.reference.get("caveat", "reference population")),
        observation={
            k: v for k, v in assessment.reference.items() if k != "caveat"
        },
    )


def _title(verdict: ShiftVerdict) -> str:
    return {
        ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT: (
            "Population shift observed, consistent with the declared operational change"
        ),
        ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED: (
            "Population shift observed; the declared operational change accounts "
            "for part of it"
        ),
        ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT: (
            "Population shift observed that the declared operational context does "
            "not account for"
        ),
        ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT: (
            "Population shift observed; no operational context was declared"
        ),
        ShiftVerdict.NO_SHIFT_DETECTED: "No population shift resolved",
        ShiftVerdict.INSUFFICIENT_SAMPLE: (
            "Population-level distribution shift was not assessed: insufficient sample"
        ),
        ShiftVerdict.NOT_ASSESSED: (
            "Population-level distribution shift was not assessed"
        ),
    }[verdict]


def _grade(
    assessment: ShiftAssessment, energy: Any
) -> tuple[Severity, float | None, ConfidenceBasis | None, float | None]:
    """Severity and confidence, kept independent of each other (brief §17).

    Severity answers "how consequential if true" and is driven by whether the
    declared context accounts for the movement.  Confidence answers "how sure
    are we that a movement occurred" and is driven by the permutation test.
    They are deliberately computed from different inputs: a shift can be
    certain and unimportant (a declared sensor swap, p = 0.001) or uncertain and
    important (an unexplained residual at p = 0.009), and a system that derived
    one from the other could not express either.
    """
    severity = {
        ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT: Severity.INFO,
        ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED: Severity.LOW,
        ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT: Severity.LOW,
        ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT: Severity.MEDIUM,
    }[assessment.verdict]

    if energy is not None and energy.assessed() and energy.p_value is not None:
        confidence = min(1.0 - float(energy.p_value), STATISTICAL_CONFIDENCE_CAP)
        return severity, confidence, ConfidenceBasis.STATISTICAL, None

    # Unreachable while the omnibus test gates every shift verdict, but kept as
    # the explicit fallback rather than an assertion: if a future verdict is
    # ever resolved without the test, it must degrade to uncalibrated rather
    # than inherit a statistical basis it has not earned.
    return severity, None, None, UNCALIBRATED_PRIOR  # pragma: no cover


def shift_coverage(
    assessment: ShiftAssessment | None,
    *,
    reference_supplied: bool,
) -> list[CoverageEntry]:
    """The coverage entry for ``distribution_shift``, conditional on inputs."""
    if not reference_supplied:
        return [
            coverage_entry(
                ATTACK_CLASS,
                Coverage.NOT_ASSESSED,
                detector=SHIFT_METHOD,
                detector_version=SHIFT_METHOD_VERSION,
                reason="no reference population was supplied; a population-level "
                "shift claim requires a baseline to compare against, and the "
                "dataset's own bulk is not one when the dataset is what is under "
                "assessment",
            )
        ]
    if assessment is None or assessment.verdict is ShiftVerdict.NOT_ASSESSED:
        return [
            coverage_entry(
                ATTACK_CLASS,
                Coverage.NOT_ASSESSED,
                detector=SHIFT_METHOD,
                detector_version=SHIFT_METHOD_VERSION,
                reason=(
                    assessment.statement
                    if assessment is not None
                    else "the shift analysis did not run"
                ),
            )
        ]
    if assessment.verdict is ShiftVerdict.INSUFFICIENT_SAMPLE:
        return [
            coverage_entry(
                ATTACK_CLASS,
                Coverage.NOT_ASSESSED,
                detector=SHIFT_METHOD,
                detector_version=SHIFT_METHOD_VERSION,
                reason=assessment.statement,
                limitations=(
                    "sample sufficiency is enforced before a verdict, never after",
                ),
            )
        ]
    return [
        coverage_entry(
            ATTACK_CLASS,
            Coverage.PARTIAL,
            detector=SHIFT_METHOD,
            detector_version=SHIFT_METHOD_VERSION,
            reason="PARTIAL because the result is bounded by the reference "
            "population's own integrity, which this analysis does not establish, "
            "and by the feature space's sensitivity"
            + (
                ""
                if assessment.reference.get("mode") == "DECLARED_CORPUS"
                else "; the reference is not an independent corpus"
            ),
            assumptions=tuple(assessment.assumptions),
            limitations=tuple(assessment.limitations),
        )
    ]


__all__ = [
    "SHIFT_METHOD", "SHIFT_METHOD_VERSION", "ATTACK_CLASS",
    "findings_for_shift", "shift_coverage",
]
