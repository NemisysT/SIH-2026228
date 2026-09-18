"""The unified evidence pipeline.

    dataset -> ingest -> manifest -> features -> detectors -> aggregation
            -> disposition -> coverage -> assurance report

One entry point, one order, one report.  The detectors are not five independent
demos: ``near_duplicate`` publishes clusters that ``label_consistency`` excludes
from its neighbourhoods, and ``label_consistency`` publishes the suggestions
that ``systematic_mislabel`` tests.  That chain is why execution order is fixed
in code rather than taken from configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Sequence

from .core.config import Config
from .core.context import RunContext
from .core.errors import DatasetError, DetectorUnavailable
from .core.evidence import Coverage, Finding
from .core.logging import get_logger
from .datasets.base import ADAPTERS, RawDataset, detect_adapter
from .datasets.contributors import ContributorResolver
from .datasets.manifest import DatasetManifest, build_manifest
from .detectors import DETECTORS, EXECUTION_ORDER
from .detectors.base import AnalysisContext, DetectorOutput
from .features.store import build_features
from .reporting.report import AssuranceReport, DetectorReport, build_report
from .risk.aggregate import ContributorAggregator
from .risk.calibration import CalibrationSet
from .risk.coverage import CoverageStatement
from .risk.disposition import DispositionPolicy

log = get_logger("pipeline")

IMPLEMENTED_MODULES: tuple[int, ...] = (1,)


def load_dataset(root: Path, adapter_name: str | None = None) -> RawDataset:
    adapter = ADAPTERS.get(adapter_name) if adapter_name else detect_adapter(root)
    log.info("ingesting %s with the '%s' adapter", root, adapter.name)
    dataset = adapter.load(root)
    if not dataset.samples:
        raise DatasetError(f"adapter '{adapter.name}' found no samples under {root}")
    return dataset


def analyse(
    root: Path,
    config: Config,
    *,
    adapter_name: str | None = None,
    reference_sample_ids: Iterable[str] | None = None,
    detectors: Sequence[str] | None = None,
) -> tuple[AssuranceReport, AnalysisContext, list[DetectorOutput]]:
    root = Path(root)
    dataset = load_dataset(root, adapter_name)
    resolver = ContributorResolver(config.contributor, root)

    run = RunContext.create(seed=config.seed, config_hash=config.config_hash())

    with run.timer("features"):
        features, objects, feature_issues = build_features(dataset, config)

    with run.timer("manifest"):
        manifest, _, attributions, manifest_issues = build_manifest(
            dataset, resolver, facts=features.facts
        )

    # The dataset digest is part of the run identity, so it is folded in after
    # the manifest exists. Re-deriving the run id keeps it a pure function of
    # (config, seed, dataset).
    run = RunContext.create(
        seed=config.seed,
        config_hash=config.config_hash(),
        dataset_digest=manifest.digest,
    )
    run.detector_versions = {
        name: DETECTORS.get(name).version for name in EXECUTION_ORDER
    }

    if objects is not None:
        objects.contributors = [
            attributions[sid].contributor if sid in attributions else
            config.contributor.unknown_label
            for sid, _ in objects.keys
        ]

    calibration = CalibrationSet.load(config.calibration_path)
    policy = DispositionPolicy(config.disposition)

    ctx = AnalysisContext(
        dataset=dataset,
        manifest=manifest,
        features=features,
        objects=objects,
        attributions=attributions,
        issues=[*feature_issues, *manifest_issues],
        config=config,
        run=run,
        calibration=calibration,
        policy=policy,
        reference_sample_ids=(
            frozenset(reference_sample_ids) if reference_sample_ids else None
        ),
    )

    selected = tuple(detectors) if detectors is not None else config.detectors
    ordered = [name for name in EXECUTION_ORDER if name in selected]
    unknown = sorted(set(selected) - set(EXECUTION_ORDER))
    if unknown:
        raise DatasetError(f"unknown detector(s) requested: {', '.join(unknown)}")

    outputs: list[DetectorOutput] = []
    findings: list[Finding] = []
    coverage_entries = []

    for name in ordered:
        detector = DETECTORS.get(name)
        with run.timer(f"detector.{name}"):
            try:
                output = detector.run(ctx)
            except DetectorUnavailable as exc:
                # Contract: an unmet requirement is reported, never swallowed.
                from .detectors.base import coverage_entry

                log.warning("detector %s unavailable: %s", name, exc)
                output = DetectorOutput(detector=name, version=detector.version)
                for attack_class in detector.attack_classes:
                    output.coverage.append(
                        coverage_entry(
                            attack_class, Coverage.NOT_ASSESSED,
                            detector=name, detector_version=detector.version,
                            reason=str(exc),
                        )
                    )
        outputs.append(output)
        findings.extend(output.findings)
        coverage_entries.extend(output.coverage)
        log.info(
            "detector %-20s %3d finding(s)  %s",
            name, len(output.findings),
            ", ".join(f"{e.attack_class}={e.coverage.value}" for e in output.coverage),
        )

    coverage_by_class = {e.attack_class: e.coverage for e in coverage_entries}

    with run.timer("aggregation"):
        aggregator = ContributorAggregator(
            config.aggregation, policy, config.contributor.unknown_label
        )
        contributor_findings, contributor_summary = aggregator.run(
            findings, manifest, coverage_by_class
        )
    findings.extend(contributor_findings)

    run.finish()
    throughput = (
        len(dataset.samples) / (run.duration_ms / 1000)
        if run.duration_ms else 0.0
    )

    report = build_report(
        run=run,
        dataset={
            "root": str(root),
            "manifest_id": manifest.manifest_id,
            "digest": manifest.digest,
            "adapter": manifest.dataset.get("adapter"),
            "task": manifest.dataset.get("task"),
            "counts": manifest.counts,
            "classes": list(manifest.classes),
            "contributors": manifest.contributors,
            "attribution": manifest.attribution,
            "throughput_samples_per_s": round(throughput, 2),
        },
        configuration={
            "config_hash": config.config_hash(),
            "seed": config.seed,
            "values": config.model_dump(mode="json"),
        },
        feature_space=features.extractor,
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
                else "absent: threshold-based detectors report "
                     "HEURISTIC_UNCALIBRATED confidence, capped by policy"
            ),
        },
        disposition_policy=policy.describe(),
        findings=findings,
        contributor_risk=contributor_summary,
        detectors=[
            DetectorReport(
                name=o.detector, version=o.version, findings=len(o.findings), stats=o.stats
            )
            for o in outputs
        ],
        coverage=CoverageStatement.build(coverage_entries, IMPLEMENTED_MODULES),
    )
    return report, ctx, outputs
