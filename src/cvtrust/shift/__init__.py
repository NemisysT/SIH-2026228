"""Module 4 — population-level distribution-shift characterisation.

Deliberately *not* a second out-of-distribution detector.  Module 1's ``ood``
detector answers a per-sample question ("is this image unusual relative to a
reference?").  This package answers a population question ("has the
distribution of the current operating population moved relative to an
appropriate reference population?"), which is a different question with a
different failure mode: a population can shift without any single sample being
individually remarkable, and a handful of individually remarkable samples do
not make a population shift.
"""

from .context import (
    CONTEXT_DIMENSIONS,
    ContextExplanation,
    OperationalContext,
    explain_shift,
)
from .characterize import ShiftAssessment, ShiftCharacterizer, ShiftVerdict
from .findings import SHIFT_METHOD, SHIFT_METHOD_VERSION, findings_for_shift, shift_coverage
from .metrics import MetricResult, MetricStatus
from .reference import ReferencePopulation, ReferenceMode, build_population

__all__ = [
    "CONTEXT_DIMENSIONS", "ContextExplanation", "OperationalContext", "explain_shift",
    "ShiftAssessment", "ShiftCharacterizer", "ShiftVerdict",
    "MetricResult", "MetricStatus",
    "ReferencePopulation", "ReferenceMode", "build_population",
    "SHIFT_METHOD", "SHIFT_METHOD_VERSION", "findings_for_shift", "shift_coverage",
]
