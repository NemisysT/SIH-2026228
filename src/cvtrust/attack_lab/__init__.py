"""The synthetic attack laboratory.

Ground truth is generated, never annotated, and is written outside the dataset
root so that no detector can read it.
"""

from .attacks import (
    ATTACK_LAB_VERSION,
    SCENARIOS,
    AttackResult,
    combined,
    duplicate_flood,
    label_flip,
    near_duplicate_flood,
    ood_insertion,
    systematic_mislabel,
)
from .evaluate import (
    ClassMetrics,
    EvaluationReport,
    ScenarioResult,
    evaluate_all,
    evaluate_scenario,
)
from .synth import CLASSES, DEFAULT_CONTRIBUTORS, generate_clean_dataset, render_ood_sample

__all__ = [
    "ATTACK_LAB_VERSION", "SCENARIOS", "AttackResult", "combined", "duplicate_flood",
    "label_flip", "near_duplicate_flood", "ood_insertion", "systematic_mislabel",
    "ClassMetrics", "EvaluationReport", "ScenarioResult", "evaluate_all",
    "evaluate_scenario", "CLASSES", "DEFAULT_CONTRIBUTORS", "generate_clean_dataset",
    "render_ood_sample",
]
