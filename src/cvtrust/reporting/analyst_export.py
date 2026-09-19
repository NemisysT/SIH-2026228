"""Module 5's backend boundary: the analyst platform's data feed.

This module contains **no forensic logic**. It runs the existing Module 1-4
pipelines exactly as ``cvtrust lab assurance-evaluate`` does, and writes what
comes back to disk in a layout a frontend can read without a Python process
alive. Nothing here reinterprets, re-scores, or summarises a module's output:
every file written is ``model_dump_json`` of an object one of the four modules
built.

The layout it writes::

    <out>/index.json                      the scenario catalogue
    <out>/capabilities.json               the build's coverage statement
    <out>/scenarios/<name>/assurance.json Module 4 PipelineAssuranceReport
    <out>/scenarios/<name>/dataset.json   Module 1 report, when supplied
    <out>/scenarios/<name>/model.json     Module 2 report, when supplied
    <out>/scenarios/<name>/provenance.json Module 3 report, when supplied
    <out>/scenarios/<name>/shift.json     Module 4 ShiftAssessment, when supplied

``index.json`` is the only file this module invents a shape for, and it is a
catalogue, not an assessment: names, paths, the scenario's declared
expectation, and the disposition the policy engine actually produced. A
scenario whose upstream lab is absent is written with ``status="NOT_RUN"`` and
the reason, never fabricated and never dropped -- the frontend is expected to
render that state, because a demo that silently hides a missing input teaches
the wrong thing.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ..core.config import Config
from ..core.context import RunContext
from ..core.errors import CvTrustError
from ..core.logging import get_logger

log = get_logger(__name__)

#: Bumped when the catalogue shape changes. The per-scenario report files carry
#: their own module schema versions and are not covered by this one.
EXPORT_SCHEMA_VERSION = "1.0"

#: The scenarios the brief (§18) asks the demo to make visible, in the order an
#: analyst should walk them. Every name here is a real entry in
#: ``PIPELINE_SPECS``; this tuple only fixes presentation order and marks which
#: ones are the headline demonstrations.
FEATURED_SCENARIOS: tuple[str, ...] = (
    "clean_baseline",
    "operational_shift",
    "dataset_anomaly",
    "model_anomaly_uncalibrated",
    "provenance_tampering",
    "combined_attack",
)


@dataclass(frozen=True)
class ExportedScenario:
    """One row of the catalogue."""

    name: str
    status: str
    expected_disposition: str
    observed_disposition: str | None
    note: str
    reason: str | None
    files: dict[str, str]
    summary: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "featured": self.name in FEATURED_SCENARIOS,
            "expected_disposition": self.expected_disposition,
            "observed_disposition": self.observed_disposition,
            "note": self.note,
            "reason": self.reason,
            "files": self.files,
            "summary": self.summary,
        }


def load_assurance_lab(lab_dir: Path) -> Any:
    """Rehydrate a built Module 4 lab from its on-disk spec.

    Mirrors what the CLI does for ``lab assurance-evaluate``; it is here so the
    export has one entry point rather than asking the caller to assemble the
    lab object.
    """
    from ..attack_lab.assurance_scenarios import AssuranceLab, PopulationPair

    lab_dir = Path(lab_dir)
    spec_path = lab_dir / "lab_spec.json"
    if not spec_path.is_file():
        raise CvTrustError(
            f"{lab_dir} does not contain lab_spec.json; run "
            "`cvtrust lab assurance-build` first"
        )
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    pairs = []
    for name in spec["pairs"]:
        truth = json.loads((lab_dir / name / "ground_truth.json").read_text(encoding="utf-8"))
        context = json.loads((lab_dir / name / "context.json").read_text(encoding="utf-8"))
        pairs.append(
            PopulationPair(
                name=name,
                reference_root=lab_dir / "_reference" / "dataset",
                current_root=lab_dir / name / "dataset",
                reference_context=context["reference"],
                current_context=context["current"],
                ground_truth=truth,
            )
        )
    return AssuranceLab(
        root=lab_dir,
        baseline_root=lab_dir / "_reference" / "dataset",
        pairs=pairs,
        spec=spec,
    )


def _scenario_summary(report: Any) -> dict[str, Any]:
    """The catalogue row's at-a-glance fields, all copied from the report.

    Every value here also exists verbatim inside ``assurance.json``; the
    catalogue carries them so a scenario list renders without loading twelve
    multi-megabyte reports. It is a projection, never a recomputation.
    """
    decision = report.decision
    return {
        "report_id": report.report_id,
        "decision_id": decision.decision_id,
        "policy_version": decision.policy_version,
        "statement": decision.summary,
        "scopes": {
            scope.scope: {
                "disposition": scope.disposition,
                "assessed": scope.assessed,
                "governing_rule": scope.governing_rule,
                "statement": scope.statement,
                "findings": scope.findings,
            }
            for scope in report.scopes()
        },
        "fired_rules": sorted({outcome.rule_id for outcome in decision.fired_rules}),
        "evidence_total": len(report.evidence.evidence),
        "source_findings_total": len(report.source_findings),
        "confounded_evidence": sum(
            1 for item in report.evidence.evidence if item.active_confounders
        ),
        "independent_families": [
            family.value for family in report.evidence.independent_families()
        ],
        "unassessed_areas": len(decision.unassessed_areas),
        "inputs_supplied": dict(report.inputs.get("supplied", {})),
        "shift_verdict": (
            report.distribution_shift.verdict.value
            if report.distribution_shift is not None
            else None
        ),
    }


def export_scenarios(
    out_dir: Path,
    config: Config,
    *,
    assurance_lab: Any,
    dataset_lab_root: Path | None = None,
    model_lab_root: Path | None = None,
    provenance_lab_root: Path | None = None,
    work_dir: Path | None = None,
    specs: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run every pipeline scenario for real and write the analyst feed.

    Returns the catalogue that was written. The upstream module reports are
    produced by :func:`cvtrust.attack_lab.assurance_evaluate.build_pipeline_scenarios`,
    which is the same code path the Module 4 evaluation uses -- the analyst
    platform and the evaluation therefore cannot disagree about what a scenario
    produced.
    """
    from ..assurance_pipeline import assess_pipeline, characterise_shift
    from ..attack_lab.assurance_evaluate import PIPELINE_SPECS, build_pipeline_scenarios
    from ..shift.context import OperationalContext
    from ..risk.coverage import CoverageStatement, build_capability_statement
    from .. import __version__

    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "scenarios").mkdir(parents=True, exist_ok=True)

    scenarios = build_pipeline_scenarios(
        work_dir or (Path(assurance_lab.root) / "_scenarios"),
        config,
        assurance_lab=assurance_lab,
        dataset_lab_root=dataset_lab_root,
        model_lab=model_lab_root,
        provenance_lab_root=provenance_lab_root,
        specs=specs,
    )
    spec_by_name = {str(spec["name"]): spec for spec in (specs or PIPELINE_SPECS)}

    shift_cache: dict[str, Any] = {}
    rows: list[ExportedScenario] = []

    for scenario in scenarios:
        directory = out_dir / "scenarios" / scenario.name
        directory.mkdir(parents=True, exist_ok=True)
        files: dict[str, str] = {}

        if scenario.status != "RUN":
            rows.append(
                ExportedScenario(
                    name=scenario.name,
                    status=scenario.status,
                    expected_disposition=scenario.expected_disposition,
                    observed_disposition=None,
                    note=scenario.note,
                    reason=scenario.reason,
                    files=files,
                    summary={},
                )
            )
            log.warning("scenario %-32s NOT_RUN — %s", scenario.name, scenario.reason)
            continue

        shift = None
        if scenario.shift_pair:
            if scenario.shift_pair not in shift_cache:
                pair = assurance_lab.pair(scenario.shift_pair)
                assessment, _ = characterise_shift(
                    pair.reference_root,
                    pair.current_root,
                    config,
                    reference_context=OperationalContext.from_mapping(pair.reference_context),
                    current_context=OperationalContext.from_mapping(pair.current_context),
                )
                shift_cache[scenario.shift_pair] = assessment
            shift = shift_cache[scenario.shift_pair]

        report, _ = assess_pipeline(
            config,
            dataset_report=scenario.dataset_report,
            model_report=scenario.model_report,
            provenance_report=scenario.provenance_report,
            shift=shift,
        )

        (directory / "assurance.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )
        files["assurance"] = f"scenarios/{scenario.name}/assurance.json"

        # The upstream reports are copied byte-for-byte, not re-rendered: the
        # dataset page must show the same JSON the dataset module wrote.
        for key, source in (
            ("dataset", scenario.dataset_report),
            ("model", scenario.model_report),
            ("provenance", scenario.provenance_report),
        ):
            if source is not None and Path(source).is_file():
                shutil.copyfile(source, directory / f"{key}.json")
                files[key] = f"scenarios/{scenario.name}/{key}.json"

        if shift is not None:
            (directory / "shift.json").write_text(
                shift.model_dump_json(indent=2), encoding="utf-8"
            )
            files["shift"] = f"scenarios/{scenario.name}/shift.json"

        spec = spec_by_name.get(scenario.name, {})
        rows.append(
            ExportedScenario(
                name=scenario.name,
                status="RUN",
                expected_disposition=scenario.expected_disposition,
                observed_disposition=report.decision.disposition.value,
                note=scenario.note,
                reason=None,
                files=files,
                summary={
                    **_scenario_summary(report),
                    "expected_rules": list(scenario.expected_rules),
                    "lab_inputs": {
                        "dataset": spec.get("dataset"),
                        "model": spec.get("model"),
                        "provenance": spec.get("provenance"),
                        "shift": spec.get("shift"),
                    },
                },
            )
        )
        log.info(
            "scenario %-32s %-13s (%s)",
            scenario.name,
            report.decision.disposition.value,
            "as expected"
            if report.decision.disposition.value == scenario.expected_disposition
            else f"expected {scenario.expected_disposition}",
        )

    run = RunContext.create(seed=config.seed, config_hash=config.config_hash())
    catalogue = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "generated_at": run.started_at,
        "software_version": __version__,
        "config_hash": config.config_hash(),
        "source": "attack-lab",
        "kind": "DEMO",
        "scenarios": [row.as_dict() for row in rows],
    }
    (out_dir / "index.json").write_text(
        json.dumps(catalogue, indent=2, sort_keys=False), encoding="utf-8"
    )
    (out_dir / "capabilities.json").write_text(
        json.dumps(
            {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "software_version": __version__,
                "coverage": CoverageStatement.build([], (1, 2, 3, 4)).model_dump(mode="json"),
                "capabilities": build_capability_statement().model_dump(mode="json"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return catalogue


__all__ = [
    "EXPORT_SCHEMA_VERSION",
    "FEATURED_SCENARIOS",
    "ExportedScenario",
    "export_scenarios",
    "load_assurance_lab",
]
