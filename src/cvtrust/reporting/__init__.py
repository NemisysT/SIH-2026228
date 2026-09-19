"""Assurance reporting: the machine-readable record and its human renderings."""

from .assurance_render import render_assurance_markdown, render_assurance_report
from .assurance_report import (
    ASSURANCE_GLOBAL_LIMITATIONS,
    PipelineAssuranceReport,
    ScopeSummary,
    build_assurance_report,
)
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
    # Module 4
    "PipelineAssuranceReport", "ScopeSummary", "build_assurance_report",
    "ASSURANCE_GLOBAL_LIMITATIONS", "render_assurance_report",
    "render_assurance_markdown",
]
