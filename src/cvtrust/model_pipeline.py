"""The Module 2 model assurance pipeline.

    model -> adapter -> manifest -> battery -> detectors
          -> findings -> assessment matrix -> coverage -> model assurance report

One entry point, one fixed order, one report.  The order is a real dependency
chain and is therefore fixed in code rather than taken from configuration:
``model_behaviour`` computes the fingerprints that ``model_activation`` and
``model_trigger`` consume, and ``model_identity`` publishes the identity
comparison the other detectors quote.

What the pipeline itself is responsible for — as opposed to the detectors — is
the contract that a level which could not be assessed is **visible**.  Every one
of the six assessment levels is populated for every run, including the ones no
detector could run, and each carries the machine-readable reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from .core.config import Config
from .core.context import RunContext
from .core.errors import AdapterError, DetectorUnavailable
from .core.evidence import Coverage, Finding, Severity
from .core.logging import get_logger
from .detectors import MODEL_DETECTORS, MODEL_EXECUTION_ORDER
from .detectors.base import DetectorOutput
from .detectors.model_base import ModelAnalysisContext, unavailable_output
from .models.base import (
    AccessMode,
    Capability,
    ModelAdapter,
    ModelHandle,
    detect_model_adapter,
)
from .models.battery import ReferenceBattery, build_battery
from .models.benchmark import benchmark_status
from .models.manifest import ModelManifest, build_model_manifest
from .reporting.model_report import (
    AssessmentLevel,
    AssessmentStatus,
    ModelAssessmentMatrix,
    ModelAssuranceReport,
    build_model_report,
)
from .reporting.report import DetectorReport
from .risk.calibration import CalibrationSet
from .risk.coverage import CoverageStatement
from .risk.disposition import DispositionPolicy
from .models import MODEL_ADAPTERS

log = get_logger("model_pipeline")

#: Modules whose attack classes this build actually assesses.  Module 1's
#: classes stay declared NOT_ASSESSED in a model report, and vice versa, so a
#: reader can never mistake one report for coverage of the other.
IMPLEMENTED_MODULES: tuple[int, ...] = (2,)

#: Which detector owns which row of the assessment matrix.
LEVEL_DETECTORS: dict[str, str] = {
    "identity": "model_identity",
    "structure": "model_structure",
    "parameters": "model_parameters",
    "behaviour": "model_behaviour",
    "activation": "model_activation",
    "trigger": "model_trigger",
}


def load_model(
    path: Path, config: Config, adapter_name: str | None = None
) -> tuple[ModelHandle, ModelAdapter]:
    """Load one artifact through its adapter."""
    path = Path(path)
    if not path.is_file():
        raise AdapterError(f"model artifact not found: {path}")
    adapter = (
        MODEL_ADAPTERS.get(adapter_name) if adapter_name else detect_model_adapter(path)
    )
    log.info("ingesting %s with the '%s' model adapter", path, adapter.name)
    return adapter.load(path, config), adapter


def _battery_for(
    handle: ModelHandle, config: Config, seed: int
) -> tuple[ReferenceBattery | None, str | None]:
    """Build the battery matching this model's declared input.

    Returns ``(None, reason)`` rather than raising when the input specification
    cannot be resolved to a concrete shape: a state-dict artifact has no input
    at all, and that is a reportable fact, not a crash.
    """
    if not handle.has(Capability.INFERENCE):
        return None, (
            f"no reference battery was built: the '{handle.model_format}' artifact "
            "cannot perform a forward pass, so there is nothing to probe"
        )
    try:
        shape = handle.batch_shape(1)[1:]
    except AdapterError as exc:
        return None, f"no reference battery could be built: {exc}"

    cfg = config.model.battery
    battery = build_battery(
        seed=seed,
        input_shape=tuple(int(d) for d in shape),
        clean_per_class=cfg.clean_per_class,
        borderline_pairs=cfg.borderline_pairs,
        ood_count=cfg.ood_count,
        trigger_bases=cfg.trigger_bases,
    )
    return battery, None


def assess_model(
    model_path: Path,
    config: Config,
    *,
    reference_path: Path | None = None,
    adapter_name: str | None = None,
    reference_adapter_name: str | None = None,
    detectors: Sequence[str] | None = None,
    force_black_box: bool = False,
) -> tuple[ModelAssuranceReport, ModelAnalysisContext, list[DetectorOutput]]:
    """Assess one model artifact and produce its assurance report.

    ``force_black_box`` drops every capability except ``inference``, which is
    how the black-box pathway is exercised on an artifact we happen to have full
    access to.  It is not a simulation: the detectors genuinely cannot reach the
    weights afterwards, so what the report says about black-box coverage is what
    black-box coverage actually is.
    """
    model_path = Path(model_path)
    supplied, supplied_adapter = load_model(model_path, config, adapter_name)
    if force_black_box:
        supplied = _restrict_to_black_box(supplied)

    run = RunContext.create(seed=config.seed, config_hash=config.config_hash())

    with run.timer("manifest"):
        supplied_manifest = build_model_manifest(
            supplied, supplied_adapter,
            reference_designation="supplied artifact under assessment",
        )

    reference: ModelHandle | None = None
    reference_adapter: ModelAdapter | None = None
    reference_manifest: ModelManifest | None = None
    if reference_path is not None:
        with run.timer("reference_manifest"):
            reference, reference_adapter = load_model(
                Path(reference_path), config, reference_adapter_name
            )
            if force_black_box:
                reference = _restrict_to_black_box(reference)
            reference_manifest = build_model_manifest(
                reference, reference_adapter, reference_designation="trusted reference",
            )

    # Re-derive the run id now that the model digest exists, so run_id stays a
    # pure function of (config, seed, model, reference) exactly as Module 1's is
    # a function of (config, seed, dataset).
    run = RunContext.create(
        seed=config.seed,
        config_hash=config.config_hash(),
        dataset_digest=None,
        extra={
            "model_digest": supplied_manifest.file_sha256,
            "reference_digest": (
                reference_manifest.file_sha256 if reference_manifest else None
            ),
        },
    )
    run.detector_versions = {
        name: MODEL_DETECTORS.get(name).version for name in MODEL_EXECUTION_ORDER
    }
    run.notes.append(f"model artifact: {supplied_manifest.model_id}")

    with run.timer("battery"):
        battery, battery_reason = _battery_for(supplied, config, config.seed)
    if battery_reason:
        run.notes.append(battery_reason)

    calibration = CalibrationSet.load(config.calibration_path)
    policy = DispositionPolicy(config.disposition)

    ctx = ModelAnalysisContext(
        supplied=supplied,
        supplied_adapter=supplied_adapter,
        supplied_manifest=supplied_manifest,
        reference=reference,
        reference_adapter=reference_adapter,
        reference_manifest=reference_manifest,
        battery=battery,
        config=config,
        run=run,
        calibration=calibration,
        policy=policy,
    )

    selected = tuple(detectors) if detectors is not None else config.model.detectors
    ordered = [name for name in MODEL_EXECUTION_ORDER if name in selected]
    unknown = sorted(set(selected) - set(MODEL_EXECUTION_ORDER))
    if unknown:
        raise AdapterError(f"unknown model detector(s) requested: {', '.join(unknown)}")

    outputs: list[DetectorOutput] = []
    findings: list[Finding] = []
    coverage_entries = []

    for name in ordered:
        detector = MODEL_DETECTORS.get(name)
        with run.timer(f"detector.{name}"):
            try:
                output = detector.run(ctx)
            except DetectorUnavailable as exc:
                # Contract, inherited from Module 1: an unmet requirement is
                # reported, never swallowed into "zero findings".
                log.warning("model detector %s unavailable: %s", name, exc)
                output = unavailable_output(detector, str(exc))
        outputs.append(output)
        findings.extend(output.findings)
        coverage_entries.extend(output.coverage)
        log.info(
            "model detector %-18s %2d finding(s)  %s",
            name, len(output.findings),
            ", ".join(f"{e.attack_class}={e.coverage.value}" for e in output.coverage),
        )

    matrix = build_assessment_matrix(ctx, outputs, ordered)
    run.finish()

    report = build_model_report(
        run=run,
        model={
            "path": str(model_path),
            "model_id": supplied_manifest.model_id,
            "manifest_id": supplied_manifest.manifest_id,
            "manifest_digest": supplied_manifest.digest,
            "format": supplied_manifest.model_format,
            "architecture_declared": supplied_manifest.architecture,
            "architecture_declared_is_untrusted": True,
            "file_sha256": supplied_manifest.file_sha256,
            "file_size_bytes": supplied_manifest.file_size_bytes,
            "graph_digest": supplied_manifest.graph_digest,
            "parameter_digest": supplied_manifest.parameter_digest,
            "parameter_count": supplied_manifest.parameter_count,
            "operators": supplied_manifest.operators,
            "layer_count": len(supplied_manifest.layers),
            "inputs": [s.model_dump(mode="json") for s in supplied_manifest.inputs],
            "outputs": [s.model_dump(mode="json") for s in supplied_manifest.outputs],
            "declared_metadata": {
                k: str(v) for k, v in supplied_manifest.declared_metadata.items()
            },
            "unavailable_fields": list(supplied_manifest.unavailable_fields),
            "notes": list(supplied_manifest.notes),
        },
        reference=(
            None if reference_manifest is None else {
                "path": str(reference_path),
                "model_id": reference_manifest.model_id,
                "manifest_id": reference_manifest.manifest_id,
                "format": reference_manifest.model_format,
                "file_sha256": reference_manifest.file_sha256,
                "graph_digest": reference_manifest.graph_digest,
                "parameter_digest": reference_manifest.parameter_digest,
                "parameter_count": reference_manifest.parameter_count,
                "designation": "trusted reference",
                "trust_assumption": "obtained through a channel independent of the "
                                    "one that supplied the artifact under assessment",
            }
        ),
        access={
            "access_mode": supplied.access_mode.value,
            "capabilities": sorted(c.value for c in supplied.capabilities),
            "capabilities_absent": sorted(
                c.value for c in Capability if c not in supplied.capabilities
            ),
            "forced_black_box": force_black_box,
            "adapter": supplied.adapter,
            "adapter_version": supplied.adapter_version,
            "runtime": dict(supplied.runtime),
            "consequences": _access_consequences(supplied),
        },
        battery=(battery.describe() if battery else {"built": False,
                                                     "reason": battery_reason}),
        configuration={
            "config_hash": config.config_hash(),
            "seed": config.seed,
            "values": config.model_dump(mode="json"),
        },
        calibration={
            "path": config.calibration_path,
            "tables": [
                {
                    "detector": t.detector,
                    "detector_version": t.detector_version,
                    "attack_class": t.attack_class,
                    "support": t.support,
                    "provenance": t.provenance,
                }
                for t in calibration.tables
            ],
            "status": (
                "loaded" if calibration.tables
                else "absent: threshold-based model detectors report "
                     "HEURISTIC_UNCALIBRATED confidence, capped by policy, and "
                     "cannot recommend QUARANTINE"
            ),
        },
        disposition_policy=policy.describe(),
        benchmark=benchmark_status(config.model.benchmark_dir),
        assessment=matrix,
        findings=findings,
        detectors=[
            DetectorReport(
                name=o.detector, version=o.version, findings=len(o.findings), stats=o.stats
            )
            for o in outputs
        ],
        coverage=CoverageStatement.build(coverage_entries, IMPLEMENTED_MODULES),
    )
    return report, ctx, outputs


def _restrict_to_black_box(handle: ModelHandle) -> ModelHandle:
    """Return a handle that genuinely cannot see inside the model.

    Capabilities are removed, not merely flagged, so every white-box method
    takes the same unavailable path it would take on a real black box.  A
    simulation that left the weights reachable would be measuring the wrong
    thing.
    """
    from dataclasses import replace

    return replace(
        handle,
        access_mode=AccessMode.BLACK_BOX,
        capabilities=frozenset({Capability.INFERENCE} & handle.capabilities),
        unavailable=tuple(sorted(set(handle.unavailable) | {
            "graph", "parameters", "activations", "gradients",
        })),
        notes=handle.notes + (
            "access deliberately restricted to BLACK_BOX: graph, parameter, "
            "activation and gradient access were removed before analysis, so "
            "white-box methods took their genuine unavailable path",
        ),
    )


def _access_consequences(handle: ModelHandle) -> list[str]:
    """What this artifact's capability set means for the assessment, in advance.

    Printed in the report's access section so a reader learns which methods
    could not run *before* reading a set of findings that silently omits them.
    """
    out: list[str] = []
    if Capability.GRADIENTS not in handle.capabilities:
        out.append(
            "no input gradients: Neural Cleanse trigger RECONSTRUCTION is not "
            "performed. A gradient-free sweep of the declared patch family runs "
            "instead, with PARTIAL coverage."
        )
    if Capability.ACTIVATIONS not in handle.capabilities:
        out.append(
            "no intermediate-tensor access: spectral-signature and "
            "activation-clustering analyses are NOT_ASSESSED."
        )
    if Capability.PARAMETERS not in handle.capabilities:
        out.append(
            "no weight access: layer statistics, reference weight comparison and "
            "peer-outlier screening are NOT_ASSESSED."
        )
    if Capability.GRAPH not in handle.capabilities:
        out.append(
            "no graph access: the structural fingerprint cannot be computed, so "
            "structural modification is NOT_ASSESSED."
        )
    if Capability.INFERENCE not in handle.capabilities:
        out.append(
            "no forward pass: every behavioural and backdoor assessment is "
            "NOT_ASSESSED. Only cryptographic identity and weight statistics are "
            "available."
        )
    if not out:
        out.append(
            "full white-box access: every assessment level in this build can run."
        )
    return out


# ----------------------------------------------------------------------
# The assessment matrix
# ----------------------------------------------------------------------

#: Attack class owned by each level, used to find the level's coverage entry.
LEVEL_ATTACK_CLASS: dict[str, str] = {
    "identity": "model_substitution",
    "structure": "model_tampering",
    "parameters": "model_tampering",
    "behaviour": "model_tampering",
    "activation": "model_backdoor",
    "trigger": "model_backdoor",
}


def build_assessment_matrix(
    ctx: ModelAnalysisContext,
    outputs: Sequence[DetectorOutput],
    ordered: Sequence[str],
) -> ModelAssessmentMatrix:
    """Populate all six levels, including the ones that did not run.

    A level with no detector output is ``NOT_ASSESSED`` with a reason, never
    absent and never blank: the whole point of the matrix is that an analyst can
    see the gaps at a glance.
    """
    by_detector = {o.detector: o for o in outputs}
    levels: dict[str, AssessmentLevel] = {}
    for level, detector_name in LEVEL_DETECTORS.items():
        output = by_detector.get(detector_name)
        if output is None:
            levels[level] = AssessmentLevel(
                level=level,
                status=AssessmentStatus.NOT_ASSESSED,
                detail="This assessment level did not run.",
                reason=(
                    f"detector '{detector_name}' was not selected for this run"
                    if detector_name not in ordered
                    else f"detector '{detector_name}' produced no output"
                ),
                detector=detector_name,
            )
            continue
        levels[level] = _level_from(level, ctx, output)
    return ModelAssessmentMatrix(**levels)


def _level_from(
    level: str, ctx: ModelAnalysisContext, output: DetectorOutput
) -> AssessmentLevel:
    attack_class = LEVEL_ATTACK_CLASS[level]
    entries = [e for e in output.coverage if e.attack_class == attack_class]
    entry = entries[-1] if entries else None
    coverage = entry.coverage if entry else Coverage.NOT_ASSESSED
    reason = entry.reason if entry else "no coverage entry was produced"

    if coverage is Coverage.REQUIRES_WHITE_BOX:
        return AssessmentLevel(
            level=level, status=AssessmentStatus.REQUIRES_WHITE_BOX,
            detail="This method needs access the artifact does not provide.",
            reason=reason, detector=output.detector,
        )
    if coverage is Coverage.NOT_ASSESSED:
        return AssessmentLevel(
            level=level, status=AssessmentStatus.NOT_ASSESSED,
            detail="Not assessed. This is an open question, not a clean result.",
            reason=reason, detector=output.detector,
        )

    findings = [f for f in output.findings if f.attack_class == attack_class]
    if not findings:
        status, detail = _clean_status(level, ctx, coverage)
        return AssessmentLevel(
            level=level, status=status, detail=detail,
            reason=reason if coverage is Coverage.PARTIAL else None,
            detector=output.detector,
        )

    # Findings sort severity-descending then confidence-descending, so the
    # first is the one that most deserves to name this level.
    worst = sorted(findings, key=lambda f: f.sort_key())[0]
    status = _finding_status(level, worst)
    return AssessmentLevel(
        level=level,
        status=status,
        detail=worst.title,
        reason=reason if coverage is Coverage.PARTIAL else None,
        detector=output.detector,
        evidence_keys=tuple(item.kind for item in worst.evidence),
    )


def _clean_status(
    level: str, ctx: ModelAnalysisContext, coverage: Coverage
) -> tuple[AssessmentStatus, str]:
    """The status for a level that ran and found nothing.

    Note the vocabulary: identity and structure can be ``VERIFIED`` /
    ``CONSISTENT`` because they are cryptographic comparisons; behaviour,
    parameters, activation and trigger can only reach
    ``NO_ANOMALY_DETECTED``, because what they tested is finite.
    """
    scope = (
        " Scoped to what was tested; see the coverage statement."
        if coverage is Coverage.PARTIAL else ""
    )
    if level == "identity":
        if ctx.has_reference:
            return (
                AssessmentStatus.VERIFIED,
                "The artifact is byte-identical to the trusted reference.",
            )
        return (
            AssessmentStatus.NO_ANOMALY_DETECTED,
            "The artifact's digests were recorded; no reference to compare against.",
        )
    if level == "structure":
        return (
            AssessmentStatus.CONSISTENT,
            "The weight-blind structural fingerprint matches the reference."
            if ctx.has_reference
            else "The structural fingerprint was recorded as a baseline." + scope,
        )
    if level == "parameters":
        return (
            AssessmentStatus.NO_ANOMALY_DETECTED,
            "No weight difference from the reference and no non-finite weights."
            if ctx.has_reference
            else "No peer-group weight anomaly was detected." + scope,
        )
    if level == "behaviour":
        return (
            AssessmentStatus.NO_ANOMALY_DETECTED,
            "Behaviour matches the reference on the battery, and predictions were "
            "stable under semantics-preserving change."
            if ctx.has_reference
            else "Predictions were stable under semantics-preserving change." + scope,
        )
    if level == "activation":
        return (
            AssessmentStatus.NO_ANOMALY_DETECTED,
            "Representation analysis ran; it contributes context only, because it "
            "was measured not to discriminate backdoored from clean models in this "
            "build." + scope,
        )
    return (
        AssessmentStatus.NO_ANOMALY_DETECTED,
        "No trigger in the tested family produced targeted misclassification." + scope,
    )


def _finding_status(level: str, finding: Finding) -> AssessmentStatus:
    # An INFO finding is context, never a risk statement. The activation level
    # emits exactly that — localisation beside a signal another detector
    # established — and must not be promoted to a risk indicator by virtue of
    # having produced a finding at all.
    if finding.severity is Severity.INFO:
        return AssessmentStatus.NO_ANOMALY_DETECTED
    if level in ("identity", "structure"):
        return AssessmentStatus.MISMATCH
    if level in ("activation", "trigger"):
        return AssessmentStatus.HIGH_RISK_INDICATOR
    return AssessmentStatus.ANOMALOUS
