"""The evidence schema enforces its own rules; those rules are the test."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cvtrust.core.evidence import (
    STATISTICAL_CONFIDENCE_CAP,
    UNCALIBRATED_CONFIDENCE_CAP,
    UNCALIBRATED_LIMITATION,
    AssetRef,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    Disposition,
    EvidenceItem,
    Finding,
    Severity,
    make_finding_id,
)

ASSET = AssetRef(type=AssetType.SAMPLE, id="a/b.jpg")
EVIDENCE = (
    EvidenceItem(kind="k", statement="s", observation={"measured": 1}),
)


def _finding(**overrides) -> Finding:
    payload = dict(
        finding_id="F-000000000000",
        observed_at="2026-09-17T00:00:00Z",
        asset=ASSET,
        category=Category.DATA,
        attack_class="label_flip",
        title="t",
        severity=Severity.LOW,
        confidence=0.5,
        confidence_basis=ConfidenceBasis.CALIBRATED,
        evidence=EVIDENCE,
        method="m",
        method_version="1.0",
        coverage=Coverage.SUPPORTED,
        disposition=Disposition.REVIEW,
        disposition_rule="D-200",
    )
    payload.update(overrides)
    return Finding(**payload)


def test_evidence_requires_a_measured_observation():
    with pytest.raises(ValidationError):
        EvidenceItem(kind="k", statement="s", observation={})


def test_a_finding_cannot_exist_without_evidence():
    with pytest.raises(ValidationError):
        _finding(evidence=())


def test_deterministic_confidence_must_be_exactly_one():
    with pytest.raises(ValidationError, match="DETERMINISTIC"):
        _finding(confidence_basis=ConfidenceBasis.DETERMINISTIC, confidence=0.99)
    assert _finding(
        confidence_basis=ConfidenceBasis.DETERMINISTIC, confidence=1.0
    ).confidence == 1.0


def test_uncalibrated_confidence_is_capped():
    with pytest.raises(ValidationError, match="exceeds the cap"):
        _finding(
            confidence_basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
            confidence=UNCALIBRATED_CONFIDENCE_CAP + 0.01,
            limitations=(UNCALIBRATED_LIMITATION,),
        )


def test_uncalibrated_findings_must_declare_the_limitation():
    with pytest.raises(ValidationError, match="uncalibrated"):
        _finding(
            confidence_basis=ConfidenceBasis.HEURISTIC_UNCALIBRATED,
            confidence=0.5,
            limitations=(),
        )


def test_statistical_confidence_is_capped_below_certainty():
    with pytest.raises(ValidationError, match="statistical confidence"):
        _finding(
            confidence_basis=ConfidenceBasis.STATISTICAL,
            confidence=STATISTICAL_CONFIDENCE_CAP + 0.005,
        )


def test_confidence_is_bounded_to_the_unit_interval():
    with pytest.raises(ValidationError):
        _finding(confidence=1.5)


def test_findings_are_immutable():
    finding = _finding()
    with pytest.raises(ValidationError):
        finding.severity = Severity.HIGH  # type: ignore[misc]


def test_finding_ids_are_content_addressed_and_stable():
    kwargs = dict(
        method="near_duplicate", method_version="1.0",
        attack_class="near_duplicate_flood", asset=ASSET, discriminator=["x", "y"],
    )
    assert make_finding_id(**kwargs) == make_finding_id(**kwargs)


def test_finding_ids_distinguish_assets_and_discriminators():
    base = dict(method="m", method_version="1", attack_class="c", asset=ASSET)
    other_asset = AssetRef(type=AssetType.SAMPLE, id="a/c.jpg")
    assert make_finding_id(**base) != make_finding_id(**{**base, "asset": other_asset})
    assert make_finding_id(**base) != make_finding_id(**base, discriminator=["z"])


def test_finding_id_does_not_depend_on_score_or_severity():
    """Recalibration must update a finding, not create a new one."""
    low = _finding(severity=Severity.LOW, confidence=0.2)
    high = _finding(severity=Severity.CRITICAL, confidence=0.99)
    assert low.finding_id == high.finding_id


def test_sort_order_is_severity_then_confidence_then_id():
    findings = [
        _finding(finding_id="F-000000000002", severity=Severity.LOW, confidence=0.9),
        _finding(finding_id="F-000000000001", severity=Severity.HIGH, confidence=0.4),
        _finding(finding_id="F-000000000003", severity=Severity.HIGH, confidence=0.8),
    ]
    ordered = [f.finding_id for f in sorted(findings, key=lambda f: f.sort_key())]
    assert ordered == ["F-000000000003", "F-000000000001", "F-000000000002"]
