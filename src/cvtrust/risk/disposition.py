"""Recommended disposition: an explicit rule table, not a judgement call.

The analyst sees which rule fired (``disposition_rule`` on every finding), and
the rules themselves are printed in the report.  This is the difference between
a tool that recommends QUARANTINE and a tool that can be argued with.

Order matters: the first matching rule wins, and rules are evaluated from
strictest to weakest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.config import DispositionConfig
from ..core.evidence import (
    SEVERITY_ORDER,
    ConfidenceBasis,
    Coverage,
    Disposition,
    Severity,
)


@dataclass(frozen=True, slots=True)
class DispositionDecision:
    disposition: Disposition
    rule_id: str


class DispositionPolicy:
    version = "1.0"

    def __init__(self, cfg: DispositionConfig) -> None:
        self.cfg = cfg
        self._quarantine_severity = SEVERITY_ORDER[Severity(cfg.quarantine_min_severity)]
        self._review_severity = SEVERITY_ORDER[Severity(cfg.review_min_severity)]

    def decide(
        self,
        *,
        severity: Severity,
        confidence: float,
        coverage: Coverage,
        basis: ConfidenceBasis,
    ) -> DispositionDecision:
        rank = SEVERITY_ORDER[severity]

        # A finding the system could not actually assess must never drive an
        # irreversible action, however severe the hypothetical would be.
        if coverage in (Coverage.NOT_ASSESSED, Coverage.NOT_SUPPORTED):
            return DispositionDecision(Disposition.REVIEW, "D-000-not-assessed")

        # Uncalibrated evidence can raise an analyst's attention but is not
        # allowed, on its own, to quarantine an asset.  Quarantine is expensive
        # and reversing it costs credibility.
        if (
            rank >= self._quarantine_severity
            and confidence >= self.cfg.quarantine_min_confidence
            and basis is not ConfidenceBasis.HEURISTIC_UNCALIBRATED
        ):
            return DispositionDecision(Disposition.QUARANTINE, "D-100-severe-and-confident")

        if (
            rank >= self._quarantine_severity
            and confidence >= self.cfg.quarantine_min_confidence
        ):
            return DispositionDecision(Disposition.REVIEW, "D-110-severe-but-uncalibrated")

        if rank >= self._review_severity and confidence >= self.cfg.review_min_confidence:
            return DispositionDecision(Disposition.REVIEW, "D-200-actionable")

        return DispositionDecision(Disposition.ACCEPT, "D-900-below-thresholds")

    def describe(self) -> dict[str, Any]:
        """The rule table, verbatim, for inclusion in the report."""
        return {
            "policy_version": self.version,
            "thresholds": self.cfg.model_dump(mode="json"),
            "rules": [
                {
                    "id": "D-000-not-assessed",
                    "when": "coverage is NOT_ASSESSED or NOT_SUPPORTED",
                    "then": "REVIEW",
                    "rationale": "an unassessed attack class is an open question, "
                    "not a clean result, and not grounds for quarantine either",
                },
                {
                    "id": "D-100-severe-and-confident",
                    "when": f"severity >= {self.cfg.quarantine_min_severity} and "
                    f"confidence >= {self.cfg.quarantine_min_confidence} and "
                    "confidence is not uncalibrated",
                    "then": "QUARANTINE",
                },
                {
                    "id": "D-110-severe-but-uncalibrated",
                    "when": "severe and confident, but confidence has no measured "
                    "calibration behind it",
                    "then": "REVIEW",
                    "rationale": "quarantine requires measured evidence quality",
                },
                {
                    "id": "D-200-actionable",
                    "when": f"severity >= {self.cfg.review_min_severity} and "
                    f"confidence >= {self.cfg.review_min_confidence}",
                    "then": "REVIEW",
                },
                {
                    "id": "D-900-below-thresholds",
                    "when": "otherwise",
                    "then": "ACCEPT",
                },
            ],
        }
