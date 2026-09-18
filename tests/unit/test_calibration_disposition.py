"""Calibration resolution and the disposition rule table."""

from __future__ import annotations

from cvtrust.core.config import DispositionConfig
from cvtrust.core.evidence import (
    UNCALIBRATED_CONFIDENCE_CAP,
    ConfidenceBasis,
    Coverage,
    Disposition,
    Severity,
)
from cvtrust.risk.calibration import CalibrationSet, build_table
from cvtrust.risk.disposition import DispositionPolicy


def _table(detector="near_duplicate", version="1.0", attack_class="near_duplicate_flood"):
    # 20 flagged observations: all correct at high scores, all wrong at low ones.
    scores = [0.05] * 10 + [0.97] * 10
    labels = [False] * 10 + [True] * 10
    return build_table(
        detector=detector, detector_version=version, attack_class=attack_class,
        scores=scores, is_true_positive=labels, provenance={"source": "test"},
    )


def test_measured_precision_drives_confidence():
    calibration = CalibrationSet(tables=(_table(),))
    high, basis, provenance = calibration.resolve(
        detector="near_duplicate", detector_version="1.0",
        attack_class="near_duplicate_flood", score=0.97, prior=0.5,
    )
    low, _, _ = calibration.resolve(
        detector="near_duplicate", detector_version="1.0",
        attack_class="near_duplicate_flood", score=0.05, prior=0.5,
    )
    assert basis is ConfidenceBasis.CALIBRATED
    assert high > low
    assert low == 0.0
    assert provenance["calibration"]["measured_precision"] == 1.0


def test_confidence_is_the_lower_bound_not_the_point_estimate():
    calibration = CalibrationSet(tables=(_table(),))
    confidence, _, provenance = calibration.resolve(
        detector="near_duplicate", detector_version="1.0",
        attack_class="near_duplicate_flood", score=0.97, prior=0.5,
    )
    assert confidence < provenance["calibration"]["measured_precision"]


def test_a_stale_detector_version_does_not_silently_reuse_calibration():
    calibration = CalibrationSet(tables=(_table(version="1.0"),))
    confidence, basis, _ = calibration.resolve(
        detector="near_duplicate", detector_version="2.0",
        attack_class="near_duplicate_flood", score=0.97, prior=0.55,
    )
    assert basis is ConfidenceBasis.HEURISTIC_UNCALIBRATED
    assert confidence <= UNCALIBRATED_CONFIDENCE_CAP


def test_missing_calibration_falls_back_to_a_capped_prior():
    confidence, basis, provenance = CalibrationSet.empty().resolve(
        detector="x", detector_version="1.0", attack_class="y", score=0.99, prior=0.95,
    )
    assert basis is ConfidenceBasis.HEURISTIC_UNCALIBRATED
    assert confidence == UNCALIBRATED_CONFIDENCE_CAP
    assert provenance["calibration"]["available"] is False


def _policy() -> DispositionPolicy:
    return DispositionPolicy(DispositionConfig())


def test_severe_and_calibrated_evidence_quarantines():
    decision = _policy().decide(
        severity=Severity.HIGH, confidence=0.95,
        coverage=Coverage.SUPPORTED, basis=ConfidenceBasis.CALIBRATED,
    )
    assert decision.disposition is Disposition.QUARANTINE
    assert decision.rule_id == "D-100-severe-and-confident"


def test_uncalibrated_evidence_cannot_quarantine_however_severe():
    decision = _policy().decide(
        severity=Severity.CRITICAL, confidence=0.99,
        coverage=Coverage.SUPPORTED, basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
    )
    assert decision.disposition is Disposition.REVIEW
    assert decision.rule_id == "D-110-severe-but-uncalibrated"


def test_an_unassessed_class_never_drives_an_irreversible_action():
    decision = _policy().decide(
        severity=Severity.CRITICAL, confidence=1.0,
        coverage=Coverage.NOT_ASSESSED, basis=ConfidenceBasis.DETERMINISTIC,
    )
    assert decision.disposition is Disposition.REVIEW
    assert decision.rule_id == "D-000-not-assessed"


def test_weak_evidence_is_accepted_rather_than_escalated():
    decision = _policy().decide(
        severity=Severity.LOW, confidence=0.1,
        coverage=Coverage.SUPPORTED, basis=ConfidenceBasis.CALIBRATED,
    )
    assert decision.disposition is Disposition.ACCEPT


def test_the_policy_publishes_the_rules_it_executes():
    described = _policy().describe()
    rule_ids = {rule["id"] for rule in described["rules"]}
    assert {"D-000-not-assessed", "D-100-severe-and-confident",
            "D-110-severe-but-uncalibrated", "D-200-actionable",
            "D-900-below-thresholds"} == rule_ids
