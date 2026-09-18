"""Calibration tables: where ``CALIBRATED`` confidence comes from.

A detector produces a raw score.  Turning that score into "confidence 0.91"
requires knowing how often a score in that range actually corresponded to a real
attack.  That is a measurement, not a choice, so it is measured:
``cvtrust evaluate`` runs the detectors over attack-lab scenarios where ground
truth is known, bins the scores, and records the observed precision per bin.

Confidence reported at scan time is the **Wilson lower bound** of that measured
precision, so a bin supported by 4 observations yields a visibly weaker
confidence than one supported by 400.

Stated limitation, printed in every report that uses a calibration table:
precision measured on synthetic attack-lab data is a statement about the
detector's behaviour on those scenarios.  It is a defensible lower bound on
evidence quality, not an operational guarantee for imagery the system has never
seen.  Recalibration against representative data is a deployment step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..core.errors import ConfigError
from ..core.evidence import (
    UNCALIBRATED_CONFIDENCE_CAP,
    ConfidenceBasis,
)
from ..core.logging import get_logger

log = get_logger("risk.calibration")

CALIBRATION_SCHEMA_VERSION = "1.0"


class CalibrationBin(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    lower: float
    upper: float
    flagged: int = Field(ge=0, description="Findings whose score fell in this bin.")
    true_positives: int = Field(ge=0)
    precision: float = Field(ge=0.0, le=1.0)
    precision_lower_95: float = Field(ge=0.0, le=1.0)

    def contains(self, score: float) -> bool:
        return self.lower <= score < self.upper or (
            score >= self.upper and self.upper >= 1.0
        )


class DetectorCalibration(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    detector: str
    detector_version: str
    attack_class: str
    bins: tuple[CalibrationBin, ...]
    support: int
    provenance: dict[str, Any] = Field(
        description="Scenario ids, seeds, sample counts and date behind this table."
    )

    def confidence_for(self, score: float) -> tuple[float, CalibrationBin] | None:
        for bin_ in self.bins:
            if bin_.contains(score):
                return bin_.precision_lower_95, bin_
        return None


class CalibrationSet(BaseModel):
    """All calibration tables available to a run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = CALIBRATION_SCHEMA_VERSION
    created_at: str | None = None
    tables: tuple[DetectorCalibration, ...] = ()

    @classmethod
    def empty(cls) -> "CalibrationSet":
        return cls()

    @classmethod
    def load(cls, path: str | Path | None) -> "CalibrationSet":
        if path is None:
            return cls.empty()
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"calibration table not found: {p}")
        try:
            return cls.model_validate(json.loads(p.read_text(encoding="utf-8")))
        except Exception as exc:
            raise ConfigError(f"invalid calibration table {p}: {exc}") from exc

    def lookup(
        self, detector: str, detector_version: str, attack_class: str
    ) -> DetectorCalibration | None:
        for table in self.tables:
            if (
                table.detector == detector
                and table.attack_class == attack_class
                and table.detector_version == detector_version
            ):
                return table
        return None

    def resolve(
        self,
        *,
        detector: str,
        detector_version: str,
        attack_class: str,
        score: float,
        prior: float,
    ) -> tuple[float, ConfidenceBasis, dict[str, Any]]:
        """Map a raw detector score to a confidence and its basis.

        Falls back to ``HEURISTIC_UNCALIBRATED`` — capped, and flagged in the
        finding's limitations — whenever no measured table covers this detector
        version and attack class.  The fallback is deliberately visible: an
        analyst should be able to tell at a glance which findings rest on
        measurement and which rest on a documented prior.
        """
        table = self.lookup(detector, detector_version, attack_class)
        if table is not None:
            hit = table.confidence_for(score)
            if hit is not None:
                confidence, bin_ = hit
                return (
                    confidence,
                    ConfidenceBasis.CALIBRATED,
                    {
                        "calibration": {
                            "score": score,
                            "bin": [bin_.lower, bin_.upper],
                            "measured_precision": bin_.precision,
                            "precision_lower_95": bin_.precision_lower_95,
                            "bin_support": bin_.flagged,
                            "table_support": table.support,
                            "provenance": table.provenance,
                        }
                    },
                )
        return (
            min(prior, UNCALIBRATED_CONFIDENCE_CAP),
            ConfidenceBasis.HEURISTIC_UNCALIBRATED,
            {"calibration": {"score": score, "available": False, "prior": prior}},
        )


def build_table(
    *,
    detector: str,
    detector_version: str,
    attack_class: str,
    scores: Sequence[float],
    is_true_positive: Sequence[bool],
    provenance: dict[str, Any],
    edges: Sequence[float] = (0.0, 0.25, 0.5, 0.7, 0.85, 0.95, 1.0),
) -> DetectorCalibration:
    """Measure precision per score bin from a labelled evaluation run."""
    from .statistics import wilson_lower_bound

    bins: list[CalibrationBin] = []
    for lower, upper in zip(edges[:-1], edges[1:]):
        members = [
            tp
            for score, tp in zip(scores, is_true_positive)
            if lower <= score < upper or (upper >= 1.0 and score >= upper)
        ]
        flagged = len(members)
        true_positives = sum(1 for tp in members if tp)
        precision = (true_positives / flagged) if flagged else 0.0
        bins.append(
            CalibrationBin(
                lower=float(lower),
                upper=float(upper),
                flagged=flagged,
                true_positives=true_positives,
                precision=precision,
                precision_lower_95=wilson_lower_bound(true_positives, flagged),
            )
        )
    return DetectorCalibration(
        detector=detector,
        detector_version=detector_version,
        attack_class=attack_class,
        bins=tuple(bins),
        support=len(scores),
        provenance=provenance,
    )
