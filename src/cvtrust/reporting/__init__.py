"""Assurance reporting: the machine-readable record and its human renderings."""

from .model_render import (
    render_model_evaluation,
    render_model_markdown,
    render_model_report,
)
from .model_report import (
    MODEL_GLOBAL_LIMITATIONS,
    AssessmentLevel,
    AssessmentStatus,
    ModelAssessmentMatrix,
    ModelAssessmentSummary,
    ModelAssuranceReport,
    build_model_report,
    summarise_model,
)
from .provenance_render import (
    render_provenance_evaluation,
    render_provenance_markdown,
    render_provenance_report,
)
from .provenance_report import (
    PROVENANCE_GLOBAL_LIMITATIONS,
    CryptographicSummary,
    ProvenanceAssessmentSummary,
    ProvenanceReport,
    RecordSummary,
    VerificationMatrix,
    build_provenance_report,
)
from .render import render_coverage, render_evaluation, render_markdown, render_report
from .report import (
    GLOBAL_LIMITATIONS,
    AssessmentSummary,
    AssuranceReport,
    DetectorReport,
    build_report,
    summarise,
)

__all__ = [
    "AssuranceReport", "AssessmentSummary", "DetectorReport", "build_report",
    "summarise", "GLOBAL_LIMITATIONS", "render_report", "render_coverage",
    "render_evaluation", "render_markdown",
    # Module 2
    "ModelAssuranceReport", "ModelAssessmentMatrix", "ModelAssessmentSummary",
    "AssessmentLevel", "AssessmentStatus", "build_model_report", "summarise_model",
    "MODEL_GLOBAL_LIMITATIONS", "render_model_report", "render_model_markdown",
    "render_model_evaluation",
    # Module 3
    "ProvenanceReport", "ProvenanceAssessmentSummary", "CryptographicSummary",
    "VerificationMatrix", "RecordSummary", "build_provenance_report",
    "PROVENANCE_GLOBAL_LIMITATIONS", "render_provenance_report",
    "render_provenance_markdown", "render_provenance_evaluation",
]
