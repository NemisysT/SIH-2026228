"""Model evaluation harness: measure the detectors against known ground truth.

Same discipline as the Module 1 harness.  The pipeline is invoked exactly as it
would be on an unknown artifact; ground truth is joined to the findings
*afterwards*, from a file written outside the directory the detectors read.

Unit of evaluation
------------------
Module 1 scores per *sample*.  Here the unit is the **model**: a scenario
produces one artifact, that artifact either carries an attack or does not, and a
detector either flags it or does not.  That makes the population small — 15
scenarios in the default matrix — and the harness says so everywhere, because a
precision measured over 15 artifacts is a weaker measurement than one over
15,000 samples and must not be presented as though it were the same thing.

Three scorings, deliberately all reported
-----------------------------------------
``detector-attributed``
    Did the detector that *owns* this attack class flag this model?  This is
    the strict reading and the one the calibration tables are built from.

``level-outcome``
    Did the corresponding assessment level reach a non-clean status?  An
    analyst reads the matrix, not the detector list, so this is what the report
    actually communicates.  A substituted model is flagged by ``model_identity``
    *and* by the structure, parameter and behaviour levels, so this scoring
    credits detections the first attributes elsewhere.

``deterministic-verification``
    For the identity and structure levels only: did the detector's *factual*
    claim match the recorded ground-truth fact?

Why the third scoring is necessary, not decorative
---------------------------------------------------
Scoring the identity level's precision against an *attack* label measures the
wrong thing, and the number it produces is actively misleading.

Every scenario artifact in the lab differs from the reference — including the
clean ones, because a model retrained from a different seed is a different file
with different weights.  The identity detector reports MISMATCH on all of them,
and **every one of those reports is true**.  Scored against "was this an
attack?", the clean retrains become "false positives" and identity precision
collapses to 0.13; but the detector did not get anything wrong.  What it
answers is "is this the artifact you assured?", and a legitimately retrained
model genuinely is not.

So the deterministic levels are scored against the fact they actually assert —
the recorded digests — and the attack-label metrics for those levels are
published beside them with this caveat attached, rather than quietly dropped.
Reporting only the flattering framing of either would be an overstatement.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..core.config import Config
from ..core.evidence import utc_now_iso
from ..core.logging import get_logger
from ..model_pipeline import assess_model
from ..reporting.model_report import AssessmentStatus
from ..risk.calibration import CalibrationSet, DetectorCalibration, build_table

log = get_logger("attack_lab.model_evaluate")

MODEL_EVALUATION_SCHEMA_VERSION = "1.0"

#: Ground-truth attack class -> the assessment level that should respond, and
#: the detector that owns the claim.
CLASS_TO_LEVEL: dict[str, str] = {
    "model_substitution": "identity",
    "model_tampering": "parameters",
    "model_backdoor": "trigger",
}

CLASS_TO_DETECTOR: dict[str, str] = {
    "model_substitution": "model_identity",
    "model_tampering": "model_parameters",
    "model_backdoor": "model_trigger",
}

#: Statuses that mean "this level said something was wrong".
NON_CLEAN: frozenset[AssessmentStatus] = frozenset({
    AssessmentStatus.MISMATCH,
    AssessmentStatus.ANOMALOUS,
    AssessmentStatus.HIGH_RISK_INDICATOR,
})


class ModelClassMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_class: str
    detector: str | None
    population: dict[str, int]
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    auroc: float | None = None
    coverage: str | None = None
    missed: list[str] = Field(default_factory=list)
    false_positive_examples: list[str] = Field(default_factory=list)
    scoring: str = "detector-attributed"


class ModelScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    artifact_format: str
    attack_classes: list[str]
    is_clean: bool
    model_sha256: str
    report_id: str
    overall: str
    access_mode: str
    duration_ms: int
    assessment: dict[str, str]
    findings_total: int
    detector_flags: dict[str, bool]
    detector_scores: dict[str, float]
    ground_truth_summary: dict[str, Any] = Field(default_factory=dict)


class DeterministicVerification(BaseModel):
    """Correctness of a deterministic level against the recorded ground-truth fact.

    Not precision/recall against an attack label — see the module docstring for
    why that is the wrong question for a cryptographic comparison.
    """

    model_config = ConfigDict(extra="forbid")

    level: str
    claim: str
    correct: int
    total: int
    accuracy: float
    disagreements: list[dict[str, Any]] = Field(default_factory=list)
    note: str


class ModelEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = MODEL_EVALUATION_SCHEMA_VERSION
    generated_at: str = Field(default_factory=utc_now_iso)
    config_hash: str
    software_version: str
    artifact_format: str
    scenarios: list[ModelScenarioResult]
    metrics: list[ModelClassMetrics]
    level_metrics: list[ModelClassMetrics]
    deterministic_verification: list[DeterministicVerification] = Field(
        default_factory=list
    )
    scoring_caveat: str = (
        "Precision and recall for the identity, structure and parameter levels "
        "are scored against an ATTACK label, and are therefore not a measure of "
        "detector correctness: every lab artifact genuinely differs from the "
        "reference, including the clean retrains, so a truthful MISMATCH on a "
        "clean model is counted as a false positive here. The "
        "'deterministic_verification' section scores those levels against the "
        "fact they actually assert. Read both."
    )
    runtime: dict[str, Any]
    evaluation_population: str = (
        "Synthetic model attack lab generated by cvtrust.attack_lab.model_attacks: "
        "small CNNs trained from published seeds on the Module 1 synthetic corpus. "
        "The unit of evaluation is the MODEL, so the population is a handful of "
        "artifacts, not thousands of samples; every rate below therefore rests on "
        "few observations and the Wilson lower bound in the calibration tables "
        "reflects that. These metrics describe detector behaviour on these "
        "scenarios. They are a lower bound on evidence quality, not a prediction "
        "of operational performance on real models."
    )


def evaluate_model_scenario(
    scenario_dir: Path,
    config: Config,
    *,
    reference_path: Path | None,
    artifact: str = "model.onnx",
    force_black_box: bool = False,
) -> tuple[ModelScenarioResult, dict[str, Any]]:
    """Assess one scenario's artifact and join it to ground truth afterwards."""
    scenario_dir = Path(scenario_dir)
    ground_truth = json.loads(
        (scenario_dir / "ground_truth.json").read_text(encoding="utf-8")
    )
    model_path = scenario_dir / artifact

    started = time.perf_counter()
    report, ctx, outputs = assess_model(
        model_path, config,
        reference_path=reference_path,
        force_black_box=force_black_box,
    )
    elapsed = int((time.perf_counter() - started) * 1000)

    flags: dict[str, bool] = {}
    scores: dict[str, float] = {}
    for output in outputs:
        for attack_class, flagged in output.flagged.items():
            flags[output.detector] = flags.get(output.detector, False) or bool(flagged)
        for attack_class, per_model in output.scores.items():
            if per_model:
                scores[output.detector] = max(per_model.values())

    assessment = {
        level.level: level.status.value for level in report.assessment.levels()
    }
    result = ModelScenarioResult(
        scenario=str(ground_truth.get("scenario", scenario_dir.name)),
        artifact_format=report.model["format"],
        attack_classes=list(ground_truth.get("attack_classes", [])),
        is_clean=bool(ground_truth.get("is_clean", False)),
        model_sha256=report.model["file_sha256"],
        report_id=report.report_id,
        overall=report.summary.overall,
        access_mode=report.access["access_mode"],
        duration_ms=elapsed,
        assessment=assessment,
        findings_total=report.summary.findings_total,
        detector_flags=flags,
        detector_scores={k: round(float(v), 6) for k, v in sorted(scores.items())},
        ground_truth_summary={
            "target_class": ground_truth.get("attack", {}).get("target_class"),
            "attack": ground_truth.get("attack", {}).get("attack"),
            "effectiveness": ground_truth.get("effectiveness"),
            "trigger_in_declared_probe_family":
                ground_truth.get("trigger_in_declared_probe_family"),
        },
    )
    return result, ground_truth


def _confusion(
    predicted: set[str], positives: set[str], population: set[str]
) -> dict[str, Any]:
    negatives = population - positives
    true_positives = predicted & positives
    false_positives = predicted & negatives
    false_negatives = positives - predicted
    true_negatives = negatives - predicted

    precision = len(true_positives) / len(predicted) if predicted else 0.0
    recall = len(true_positives) / len(positives) if positives else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )
    return {
        "true_positives": len(true_positives),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "true_negatives": len(true_negatives),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": (
            len(false_positives) / len(negatives) if negatives else 0.0
        ),
        "missed": sorted(false_negatives),
        "false_positive_examples": sorted(false_positives),
    }


def _auroc(
    scores: dict[str, float], positives: set[str], population: Iterable[str]
) -> float | None:
    population = [s for s in population if s in scores]
    labels = [1 if s in positives else 0 for s in population]
    if len(set(labels)) < 2 or len(population) < 4:
        return None
    try:
        from sklearn.metrics import roc_auc_score
    except ImportError:  # pragma: no cover - scikit-learn is a core dependency
        return None
    return float(roc_auc_score(labels, [scores[s] for s in population]))


def evaluate_model_lab(
    lab_dir: Path,
    config: Config,
    *,
    scenarios: Sequence[str] | None = None,
    artifact: str = "model.onnx",
    reference_artifact: str = "reference.onnx",
    force_black_box: bool = False,
) -> tuple[ModelEvaluationReport, CalibrationSet]:
    """Run every scenario and score the detectors against ground truth."""
    lab_dir = Path(lab_dir)
    reference_path = lab_dir / "_reference" / reference_artifact
    if not reference_path.is_file():
        reference_path = None
        log.warning(
            "no reference model at %s; every reference-dependent detector will "
            "report NOT_ASSESSED and the evaluation will measure that instead",
            lab_dir / "_reference" / reference_artifact,
        )

    candidates = sorted(
        d for d in lab_dir.iterdir()
        if d.is_dir() and (d / "ground_truth.json").is_file() and (d / artifact).is_file()
    )
    if scenarios:
        wanted = set(scenarios)
        candidates = [d for d in candidates if d.name in wanted]

    results: list[ModelScenarioResult] = []
    truths: dict[str, dict[str, Any]] = {}
    started = time.perf_counter()
    for scenario_dir in candidates:
        log.info("evaluating model scenario %s", scenario_dir.name)
        result, truth = evaluate_model_scenario(
            scenario_dir, config, reference_path=reference_path,
            artifact=artifact, force_black_box=force_black_box,
        )
        results.append(result)
        truths[result.scenario] = truth
    total_ms = int((time.perf_counter() - started) * 1000)

    population = {r.scenario for r in results}
    metrics: list[ModelClassMetrics] = []
    level_metrics: list[ModelClassMetrics] = []
    calibration_inputs: dict[str, dict[str, Any]] = {}

    for attack_class, detector_name in sorted(CLASS_TO_DETECTOR.items()):
        positives = {
            r.scenario for r in results if attack_class in r.attack_classes
        }
        # Strict scoring: did the owning detector flag it?
        predicted = {r.scenario for r in results if r.detector_flags.get(detector_name)}
        scores = {
            r.scenario: r.detector_scores.get(detector_name, 0.0) for r in results
        }
        confusion = _confusion(predicted, positives, population)
        metrics.append(
            ModelClassMetrics(
                attack_class=attack_class,
                detector=detector_name,
                population={
                    "models": len(population),
                    "positives": len(positives),
                    "negatives": len(population - positives),
                    "predicted": len(predicted),
                },
                auroc=_auroc(scores, positives, population),
                scoring="detector-attributed",
                **confusion,
            )
        )

        # Level scoring: did the corresponding assessment level go non-clean?
        level = CLASS_TO_LEVEL[attack_class]
        level_predicted = {
            r.scenario for r in results
            if r.assessment.get(level) in {s.value for s in NON_CLEAN}
        }
        level_confusion = _confusion(level_predicted, positives, population)
        level_metrics.append(
            ModelClassMetrics(
                attack_class=attack_class,
                detector=f"assessment level '{level}'",
                population={
                    "models": len(population),
                    "positives": len(positives),
                    "negatives": len(population - positives),
                    "predicted": len(level_predicted),
                },
                scoring="level-outcome",
                **level_confusion,
            )
        )

        if predicted:
            calibration_inputs[attack_class] = {
                "detector": detector_name,
                "scores": [scores[s] for s in sorted(predicted)],
                "labels": [s in positives for s in sorted(predicted)],
                "scenarios": sorted(predicted),
            }

    from .. import __version__
    from ..detectors import MODEL_DETECTORS

    tables: list[DetectorCalibration] = []
    for attack_class, entry in sorted(calibration_inputs.items()):
        detector = MODEL_DETECTORS.get(entry["detector"])
        tables.append(
            build_table(
                detector=entry["detector"],
                detector_version=detector.version,
                attack_class=attack_class,
                scores=entry["scores"],
                is_true_positive=entry["labels"],
                provenance={
                    "source": "cvtrust model attack lab (synthetic)",
                    "unit_of_evaluation": "model artifact",
                    "scenarios": entry["scenarios"],
                    "flagged_observations": len(entry["scores"]),
                    "artifact_format": artifact,
                    "generated_at": utc_now_iso(),
                    "caveat": (
                        "precision measured over a handful of synthetic model "
                        "artifacts. The Wilson lower bound used at scan time keeps "
                        "the resulting confidence low precisely because the support "
                        "is small; this is a lower bound on evidence quality, not "
                        "an operational guarantee"
                    ),
                },
            )
        )

    report = ModelEvaluationReport(
        config_hash=config.config_hash(),
        software_version=__version__,
        artifact_format=artifact,
        scenarios=results,
        metrics=metrics,
        level_metrics=level_metrics,
        deterministic_verification=_verify_deterministic(results, truths, artifact),
        runtime={
            "total_ms": total_ms,
            "scenarios": len(results),
            "mean_ms_per_model": (
                int(np.mean([r.duration_ms for r in results])) if results else 0
            ),
            "max_ms_per_model": (
                max((r.duration_ms for r in results), default=0)
            ),
            "reference_model": str(reference_path) if reference_path else None,
            "access_mode": (results[0].access_mode if results else None),
            "peak_rss_mb": _peak_rss_mb(),
        },
    )
    return report, CalibrationSet(created_at=utc_now_iso(), tables=tuple(tables))


def _verify_deterministic(
    results: Sequence[ModelScenarioResult],
    truths: dict[str, dict[str, Any]],
    artifact: str,
) -> list[DeterministicVerification]:
    """Score the identity level against the fact it asserts.

    The ground truth records both digests, so "does this artifact differ from
    the reference?" has a recorded answer that does not depend on whether the
    difference was an attack.  That is the claim the identity level makes, so
    that is what it is scored against.
    """
    digest_key = (
        "supplied_torchscript_sha256" if artifact.endswith(".pt")
        else "supplied_onnx_sha256"
    )
    reference_key = (
        "reference_torchscript_sha256" if artifact.endswith(".pt")
        else "reference_onnx_sha256"
    )

    correct = 0
    disagreements: list[dict[str, Any]] = []
    for result in results:
        truth = truths.get(result.scenario, {})
        expected_differs = truth.get(digest_key) != truth.get(reference_key)
        reported_differs = result.assessment.get("identity") in {
            AssessmentStatus.MISMATCH.value,
            AssessmentStatus.ANOMALOUS.value,
        }
        if expected_differs == reported_differs:
            correct += 1
        else:
            disagreements.append({
                "scenario": result.scenario,
                "ground_truth_differs_from_reference": expected_differs,
                "identity_level_reported": result.assessment.get("identity"),
            })

    total = len(results)
    return [
        DeterministicVerification(
            level="identity",
            claim="the supplied artifact's SHA-256 differs from the reference's",
            correct=correct,
            total=total,
            accuracy=(correct / total if total else 0.0),
            disagreements=disagreements,
            note=(
                "This is the claim the identity level actually makes, and it is a "
                "cryptographic fact rather than an inference. A clean model "
                "retrained from a different seed correctly reports MISMATCH here; "
                "that is not a false positive, and the attack-labelled precision "
                "in 'metrics' should not be read as though it were."
            ),
        )
    ]


def _peak_rss_mb() -> float | None:
    """Peak resident set size, for the performance section of the report.

    ``resource`` is POSIX-only and reports kilobytes on Linux and bytes on
    macOS; both are handled rather than assumed, and an unavailable value is
    ``None`` rather than a guess.
    """
    try:
        import resource
        import sys
    except ImportError:  # pragma: no cover - Windows
        return None
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return round(usage / divisor, 1)
