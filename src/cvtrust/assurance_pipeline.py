"""Module 4 orchestration: characterise shift, fuse evidence, decide, report.

The fourth entry point over the same evidence schema, the same disposition
machinery and the same coverage registry — and the first one that consumes all
three of the others rather than running beside them.

::

    REFERENCE POPULATION        CURRENT POPULATION
       (declared corpus,          (the operating batch
        or a declared subset)      under assessment)
            │                            │
            ▼  build_features            ▼  build_features
      PopulationView                PopulationView
            └──────────┬─────────────────┘
                       ▼  ShiftCharacterizer
                 ShiftAssessment  ── verdict from a closed vocabulary,
                       │             never a score, never "attack"
                       │
    M1 report ─┐       │
    M2 report ─┼───────┤  Finding[]  (carried VERBATIM, never rewritten)
    M3 report ─┘       │
                       ▼  normalise
                 NormalizedEvidence[]
                       ▼  build_graph      ← families, confounding, floors
                  EvidenceGraph
                       ▼  AssurancePolicyEngine   ← explicit versioned rules
                 ScopeDecision[] per scope
                       ▼  strictest across scopes
                  AssuranceDecision   ── disposition + lineage + gaps
                       ▼
             PipelineAssuranceReport  JSON + console/Markdown
                                      NO aggregate score, and there will not be one

Two ordering constraints, both real:

**Shift is characterised before fusion.**  A population shift is an *active
phenomenon* that determines which other evidence is confounded, so the graph
cannot be built until the shift verdict is known.  Building the graph first and
patching it afterwards would mean the confounding marks depended on the order
the patches arrived in.

**Nothing upstream is re-run.**  Module 4 consumes the reports the other three
modules already produced.  It never re-derives a digest, re-scores a detector or
re-dispositions a finding: a mismatch between what Module 2 reported and what
Module 4 says Module 2 reported would be undetectable and fatal, so there is no
path here that could produce one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from .assurance.decision import AssuranceDecision
from .assurance.fuse import FusionInputs, FusionResult, ModuleInput, fuse
from .assurance.policy import AssuranceDisposition, AssurancePolicyEngine, Scope
from .core.canonical import digest_safe
from .core.config import Config
from .core.context import RunContext
from .core.errors import ConfigError, DatasetError
from .core.evidence import Finding
from .core.logging import get_logger
from .datasets.base import RawDataset
from .datasets.contributors import ContributorResolver
from .datasets.manifest import build_manifest
from .features.store import build_features
from .pipeline import load_dataset
from .reporting.assurance_report import (
    PipelineAssuranceReport,
    ScopeSummary,
    build_assurance_report,
)
from .risk.calibration import CalibrationSet
from .risk.coverage import CoverageStatement
from .risk.disposition import DispositionPolicy
from .shift.characterize import ShiftAssessment, ShiftCharacterizer
from .shift.context import OperationalContext
from .shift.findings import findings_for_shift
from .shift.reference import (
    PopulationView,
    ReferenceMode,
    ReferencePopulation,
    ReferenceTrust,
    build_population,
    describe_reference,
)

log = get_logger("assurance_pipeline")

#: Which modules this build implements.  Module 5 (the analyst platform) is
#: declared absent, so its absence is a printed statement rather than a silence.
IMPLEMENTED_MODULES: tuple[int, ...] = (1, 2, 3, 4)


# ---------------------------------------------------------------------------
# Distribution shift
# ---------------------------------------------------------------------------


def characterise_shift(
    reference_root: Path | str | None,
    current_root: Path | str,
    config: Config,
    *,
    reference_sample_ids: Sequence[str] | None = None,
    current_sample_ids: Sequence[str] | None = None,
    adapter_name: str | None = None,
    reference_context: OperationalContext | None = None,
    current_context: OperationalContext | None = None,
    reference_provenance: str | None = None,
    reference_version: str | None = None,
    reference_trust: ReferenceTrust = ReferenceTrust.UNKNOWN,
    run: RunContext | None = None,
) -> tuple[ShiftAssessment, RunContext]:
    """Compare a current population against a reference population.

    Two supported shapes, and the difference between them is recorded in the
    reference's ``mode`` because it changes what the result means:

    * ``reference_root`` names a separate corpus — the strong form;
    * ``reference_root`` is ``None`` and ``reference_sample_ids`` names a subset
      of ``current_root`` — the weak form, in which the population under
      assessment contributed to its own baseline.

    Refusing the second shape would be cleaner and less useful: an analyst who
    has one delivery and wants to know whether its second half looks like its
    first has a real question, and the honest answer is to answer it with the
    caveat attached rather than to decline.
    """
    current_root = Path(current_root)
    current_dataset = load_dataset(current_root, adapter_name)
    current_features, _, _ = build_features(current_dataset, config, with_objects=False)
    current_resolver = ContributorResolver(config.contributor, current_root)
    current_manifest, _, current_attributions, _ = build_manifest(
        current_dataset, current_resolver, facts=current_features.facts
    )

    if reference_root is not None:
        reference_root = Path(reference_root)
        reference_dataset = load_dataset(reference_root, adapter_name)
        reference_features, _, _ = build_features(
            reference_dataset, config, with_objects=False
        )
        reference_resolver = ContributorResolver(config.contributor, reference_root)
        reference_manifest, _, reference_attributions, _ = build_manifest(
            reference_dataset, reference_resolver, facts=reference_features.facts
        )
        mode = ReferenceMode.DECLARED_CORPUS
        shared_digest = None
        current_exclude: set[str] = set()
    else:
        if not reference_sample_ids:
            raise ConfigError(
                "a shift analysis needs a reference population: supply a "
                "reference dataset root, or a list of sample ids inside the "
                "current dataset. Without one the result would be NOT_ASSESSED, "
                "which this function will not fabricate"
            )
        reference_dataset = current_dataset
        reference_features = current_features
        reference_manifest = current_manifest
        reference_attributions = current_attributions
        mode = ReferenceMode.DECLARED_SUBSET
        shared_digest = current_manifest.digest
        current_exclude = set(reference_sample_ids)

    reference_view = build_population(
        "reference",
        features=reference_features,
        sample_ids=reference_sample_ids,
        labels=_labels(reference_dataset),
        contributors={
            sid: attribution.contributor
            for sid, attribution in reference_attributions.items()
        },
        metadata=_metadata(reference_attributions),
    )
    # When the reference is a subset of the current dataset, the current
    # population is everything *else*. Comparing a population against a
    # reference it is a member of would measure a population against itself and
    # understate every distance.
    current_ids = (
        list(current_sample_ids)
        if current_sample_ids is not None
        else [
            sid
            for sid in current_features.sample_ids
            if sid not in current_exclude
        ]
        if current_exclude
        else None
    )
    current_view = build_population(
        "current",
        features=current_features,
        sample_ids=current_ids,
        labels=_labels(current_dataset),
        contributors={
            sid: attribution.contributor
            for sid, attribution in current_attributions.items()
        },
        metadata=_metadata(current_attributions),
    )

    reference = describe_reference(
        reference_view,
        mode=mode,
        feature_space=reference_features.extractor,
        sample_digests=[
            reference_features.facts[sid].file_sha256 or sid
            for sid in reference_view.sample_ids
        ],
        trust=reference_trust,
        provenance=reference_provenance,
        version=reference_version,
        manifest_id=reference_manifest.manifest_id,
        manifest_digest=reference_manifest.digest,
        locator=str(reference_root) if reference_root else str(current_root),
        shared_dataset_digest=shared_digest,
    )

    run = run or RunContext.create(
        seed=config.seed,
        config_hash=config.config_hash(),
        dataset_digest=current_manifest.digest,
        extra={
            "module": 4,
            "reference_digest": reference.digest,
            "reference_mode": mode.value,
            "current_samples": current_view.size,
        },
    )
    run.detector_versions["distribution_shift"] = ShiftCharacterizer.version

    with run.timer("shift"):
        assessment = ShiftCharacterizer(config.shift).run(
            reference_view=reference_view,
            current_view=current_view,
            reference=reference,
            run=run,
            reference_context=reference_context,
            current_context=current_context,
            current_descriptor={
                "name": current_manifest.dataset.get("name", "dataset"),
                "root": str(current_root),
                "digest": current_manifest.digest,
                "manifest_id": current_manifest.manifest_id,
            },
        )
    log.info(
        "shift: %s (reference %d samples, current %d samples)",
        assessment.verdict.value,
        reference_view.size,
        current_view.size,
    )
    return assessment, run


def _labels(dataset: RawDataset) -> dict[str, str]:
    """Sample-level class label, where the adapter supplies one.

    A detection sample with several categories has no single class, so it is
    omitted rather than assigned its first annotation's label: a class-mix
    comparison built on an arbitrary choice would move whenever annotation order
    changed.
    """
    labels: dict[str, str] = {}
    for sample in dataset.samples:
        categories = set(sample.labels) | {a.category for a in sample.annotations}
        if len(categories) == 1:
            labels[sample.sample_id] = next(iter(categories))
    return labels


def _metadata(attributions: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Declared, categorical acquisition metadata, as distributions.

    Contributor, batch and source are claims made alongside the imagery. They
    are compared as distributions because a change in *who supplied the data* is
    a genuine operational signal — and they are never treated as establishing
    what physically produced an image.
    """
    out: dict[str, dict[str, str]] = {"contributor": {}, "batch": {}, "source": {}}
    for sample_id, attribution in attributions.items():
        out["contributor"][sample_id] = attribution.contributor
        if getattr(attribution, "batch", None):
            out["batch"][sample_id] = str(attribution.batch)
        if getattr(attribution, "source", None):
            out["source"][sample_id] = str(attribution.source)
    return {k: v for k, v in out.items() if v}


# ---------------------------------------------------------------------------
# Loading upstream reports
# ---------------------------------------------------------------------------


def _load_json(path: Path | str) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ConfigError(f"report is not a JSON object: {path}")
    return payload


def _findings_of(payload: dict[str, Any], path: Path | str) -> list[Finding]:
    """Validate the findings out of an upstream report.

    Validation rather than trust: a report handed to this command is an
    untrusted file like any other, and a malformed or hand-edited finding must
    be refused loudly rather than fused silently. ``Finding`` forbids extra
    fields and enforces the confidence contract, so a fabricated
    ``DETERMINISTIC`` finding at confidence 0.4 cannot enter the evidence graph.
    """
    raw = payload.get("findings")
    if raw is None:
        raise ConfigError(
            f"{path} has no 'findings' array; it does not look like a cvtrust "
            "assurance report"
        )
    if not isinstance(raw, list):
        raise ConfigError(f"{path}: 'findings' must be an array")
    findings: list[Finding] = []
    for index, item in enumerate(raw):
        try:
            findings.append(Finding.model_validate(item))
        except Exception as exc:
            raise ConfigError(
                f"{path}: finding {index} does not satisfy the evidence schema: "
                f"{exc}"
            ) from exc
    return findings


def _coverage_of(payload: dict[str, Any]) -> CoverageStatement | None:
    raw = payload.get("coverage")
    if raw is None:
        return None
    try:
        return CoverageStatement.model_validate(raw)
    except Exception:  # pragma: no cover - a coverage section we cannot read
        return None


def load_module_input(
    path: Path | str, *, module: int, expect_module: str | None = None
) -> ModuleInput:
    """Load one upstream report into a fusion input."""
    payload = _load_json(path)
    declared = str(payload.get("module", ""))
    if expect_module and not declared.startswith(expect_module):
        raise ConfigError(
            f"{path} declares module '{declared}', which is not the module "
            f"'{expect_module}' this argument expects. Supplying a model report "
            "where a dataset report belongs would silently assess the wrong "
            "scope"
        )
    asset: dict[str, Any] = {}
    for key in ("dataset", "model", "log"):
        section = payload.get(key)
        if isinstance(section, dict):
            asset[key] = {
                k: v
                for k, v in section.items()
                if k in ("digest", "manifest_id", "file_sha256", "graph_digest",
                         "parameter_digest", "log_id", "head_entry_digest",
                         "entry_count", "model_id", "path", "adapter")
            }
    return ModuleInput(
        module=module,
        findings=_findings_of(payload, path),
        report_id=str(payload.get("report_id")) if payload.get("report_id") else None,
        run_id=(payload.get("run") or {}).get("run_id"),
        coverage=_coverage_of(payload),
        asset=asset,
        supplied=True,
    )


# ---------------------------------------------------------------------------
# The assurance run
# ---------------------------------------------------------------------------


def assess_pipeline(
    config: Config,
    *,
    dataset_report: Path | str | None = None,
    model_report: Path | str | None = None,
    provenance_report: Path | str | None = None,
    shift: ShiftAssessment | None = None,
    calibration: CalibrationSet | None = None,
    run: RunContext | None = None,
) -> tuple[PipelineAssuranceReport, FusionResult]:
    """Fuse the supplied evidence and produce the pipeline assurance report."""
    dataset_input = (
        load_module_input(dataset_report, module=1, expect_module="1")
        if dataset_report
        else None
    )
    model_input = (
        load_module_input(model_report, module=2, expect_module="2")
        if model_report
        else None
    )
    provenance_input = (
        load_module_input(provenance_report, module=3, expect_module="3")
        if provenance_report
        else None
    )

    shift_findings: list[Finding] = []
    if shift is not None:
        shift_findings = findings_for_shift(
            shift,
            calibration=calibration or CalibrationSet.load(config.calibration_path),
            policy=DispositionPolicy(config.disposition),
            locator=str(shift.current.get("root") or ""),
        )

    inputs = FusionInputs(
        dataset=dataset_input,
        model=model_input,
        provenance=provenance_input,
        shift=shift,
        shift_findings=shift_findings,
    )

    run = run or RunContext.create(
        seed=config.seed,
        config_hash=config.config_hash(),
        extra={
            "module": 4,
            "dataset_report": dataset_input.report_id if dataset_input else None,
            "model_report": model_input.report_id if model_input else None,
            "provenance_report": (
                provenance_input.report_id if provenance_input else None
            ),
            "shift_assessment": shift.assessment_id if shift else None,
            "policy_version": AssurancePolicyEngine.version,
        },
    )
    run.detector_versions["assurance_policy"] = AssurancePolicyEngine.version
    if shift is not None:
        run.detector_versions["distribution_shift"] = ShiftCharacterizer.version

    engine = AssurancePolicyEngine()
    with run.timer("fusion"):
        result = fuse(
            inputs,
            config,
            policy=engine,
            run_context={
                "run_id": run.run_id,
                "seed": run.seed,
                "config_hash": run.config_hash,
                "software_version": run.software_version,
                "policy_version": engine.version,
            },
        )

    with run.timer("report"):
        report = build_assurance_report(
            run=run.finish(),
            inputs=_inputs_payload(inputs),
            configuration={
                "config_hash": config.config_hash(),
                "seed": config.seed,
                "shift": config.shift.model_dump(mode="json"),
                "assurance": config.assurance.model_dump(mode="json"),
                "disposition": config.disposition.model_dump(mode="json"),
            },
            policy=engine.describe(),
            scope_summaries=_scope_summaries(inputs, result),
            shift=shift,
            evidence=result.graph,
            evidence_summary=result.evidence_summary,
            source_findings=result.source_findings,
            decision=result.decision,
            coverage=result.coverage,
            capabilities=result.capabilities,
        )
    log.info(
        "assurance: %s (%d evidence item(s), %d independent phenomenon/phenomena)",
        report.decision.disposition.value,
        len(result.graph.evidence),
        len(result.graph.independent_families()),
    )
    return report, result


def _inputs_payload(inputs: FusionInputs) -> dict[str, Any]:
    supplied = inputs.supplied_scopes()
    payload: dict[str, Any] = {
        "supplied": {scope.value: present for scope, present in sorted(
            supplied.items(), key=lambda kv: kv[0].value
        )},
        "missing": sorted(
            scope.value for scope, present in supplied.items() if not present
        ),
        "note": "a scope that was not supplied is reported NOT_ASSESSED. A "
        "fusion over one input and a fusion over four must not look alike.",
    }
    for name, module_input in (
        ("dataset", inputs.dataset),
        ("model", inputs.model),
        ("provenance", inputs.provenance),
    ):
        if module_input is None:
            continue
        payload[name] = {
            "report_id": module_input.report_id,
            "run_id": module_input.run_id,
            "findings": len(module_input.findings),
            "asset": module_input.asset,
        }
    if inputs.shift is not None:
        payload["distribution"] = {
            "assessment_id": inputs.shift.assessment_id,
            "verdict": inputs.shift.verdict.value,
            "reference": inputs.shift.reference,
            "current": inputs.shift.current,
        }
    return payload


def _scope_summaries(
    inputs: FusionInputs, result: FusionResult
) -> dict[str, ScopeSummary | None]:
    decision = result.decision
    supporting_by_scope: dict[str, int] = {}
    for reference in decision.supporting_evidence:
        scope = {
            "DATA_INTEGRITY": "dataset",
            "MODEL_INTEGRITY": "model",
            "PROVENANCE_INTEGRITY": "provenance",
            "DISTRIBUTION_SHIFT": "distribution",
            "OPERATIONAL_CONTEXT": "distribution",
        }[reference.evidence_class]
        supporting_by_scope[scope] = supporting_by_scope.get(scope, 0) + 1

    summaries: dict[str, ScopeSummary | None] = {}
    for name, scope, module_input in (
        ("dataset", Scope.DATASET, inputs.dataset),
        ("model", Scope.MODEL, inputs.model),
        ("provenance", Scope.PROVENANCE, inputs.provenance),
        ("distribution", Scope.DISTRIBUTION, None),
    ):
        scope_decision = decision.scope_decision(scope)
        if scope_decision is None:
            summaries[name] = None
            continue
        summaries[name] = ScopeSummary(
            scope=name,
            disposition=scope_decision.disposition.value,
            governing_rule=scope_decision.governing_rule,
            statement=scope_decision.statement,
            assessed=scope_decision.assessed,
            source_report_id=(
                module_input.report_id
                if module_input is not None
                else (inputs.shift.assessment_id if inputs.shift else None)
            ),
            findings=(
                len(module_input.findings)
                if module_input is not None
                else len(inputs.shift_findings)
            ),
            supporting_evidence=supporting_by_scope.get(name, 0),
        )
    return summaries


def exit_code_for(report: PipelineAssuranceReport) -> int:
    """0 accept, 1 review, 2 not assessed, 3 quarantine.

    ``NOT_ASSESSED`` gets its own code rather than sharing one with ACCEPT,
    because a pipeline that composes these commands must be able to tell "we
    checked and found nothing" from "we checked nothing".
    """
    return {
        AssuranceDisposition.ACCEPT: 0,
        AssuranceDisposition.REVIEW: 1,
        AssuranceDisposition.NOT_ASSESSED: 2,
        AssuranceDisposition.QUARANTINE: 3,
    }[report.decision.disposition]


__all__ = [
    "IMPLEMENTED_MODULES", "characterise_shift", "assess_pipeline",
    "load_module_input", "exit_code_for",
]
