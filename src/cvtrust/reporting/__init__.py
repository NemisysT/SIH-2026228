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
]
