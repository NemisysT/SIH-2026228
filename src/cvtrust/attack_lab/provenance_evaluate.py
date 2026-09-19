"""Measuring the provenance verifier against lab ground truth.

Different in kind from the Module 1 and Module 2 harnesses, and the difference
is the point of the module: there is nothing here to calibrate.

Modules 1 and 2 measure *precision and recall*, because their detectors produce
scores and a score needs a measured relationship to reality before it can be
called a confidence.  Module 3 produces neither.  A signature verifies or it
does not; a digest matches or it does not.  So this harness asserts **exact set
equality** between the failure codes each scenario is expected to produce and
the ones it does — per record, per position.

That is a far stricter standard than an ROC curve.  A verifier that raises an
*extra* failure fails the evaluation exactly as hard as one that misses a
failure, because a spurious CHAIN_BREAK on a clean log is as damaging to an
analyst as a missed one on a forged one.  No threshold can be tuned to make this
pass; either the expectations in ``ground_truth.json`` describe what the code
does, or one of the two is wrong.

No calibration table is produced, and that absence is deliberate and recorded:
Module 3 findings are ``DETERMINISTIC`` at confidence 1.0, and a calibration
table for an equality test would be a number pretending to be a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..core.config import Config
from ..core.errors import ProvenanceError
from ..core.evidence import utc_now_iso
from ..core.logging import get_logger
from ..provenance.chain import LogAnchor
from ..provenance.log import ProvenanceLog
from ..provenance.replay import ReplayDatabase
from ..provenance.trust import TrustStore
from ..provenance.verify import ExpectedBinding
from ..provenance_pipeline import verify_log
from .provenance_attacks import PROVENANCE_LAB_VERSION

log = get_logger("attack_lab.provenance_evaluate")

EVALUATION_SCHEMA_VERSION = "1.0"

#: Scenarios whose expected outcome only exists once the replay database has
#: already observed the clean log.  Evaluating them with a fresh database would
#: measure something different from what their ground truth describes, so the
#: harness primes the database and records that it did.
REPLAY_PRIMED: frozenset[str] = frozenset({"replay_exact", "legitimate_reprocess"})

#: Scenarios whose expectation must be re-derived from the scenario's own
#: artifacts rather than from the clean baseline.  There is exactly one, and it
#: is the case where the cryptography is flawless and the deployment is not.
ARTIFACT_DERIVED_EXPECTATION: frozenset[str] = frozenset({"modified_model_artifact"})


class PositionResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    position: int
    record_id: str | None
    expected_failures: tuple[str, ...]
    observed_failures: tuple[str, ...]
    expected_replay: str | None
    observed_replay: str
    failures_match: bool
    replay_match: bool

    @property
    def ok(self) -> bool:
        return self.failures_match and self.replay_match


class ScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    description: str
    attack_classes: tuple[str, ...]
    passed: bool
    record_count_expected: int
    record_count_observed: int
    chain_status_expected: str
    chain_status_observed: str
    truncation_expected: str
    truncation_observed: str
    malformed_expected: int
    malformed_observed: int
    replay_primed: bool
    expectation_source: str
    positions: tuple[PositionResult, ...]
    mismatches: tuple[str, ...]
    overall: str
    findings_total: int
    report_id: str


class ProvenanceEvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = EVALUATION_SCHEMA_VERSION
    lab_version: str = PROVENANCE_LAB_VERSION
    generated_at: str = Field(default_factory=utc_now_iso)
    scenarios_total: int
    scenarios_passed: int
    scenarios_failed: int
    calibration: str = (
        "No calibration table is produced for Module 3. Every finding it emits "
        "is DETERMINISTIC at confidence 1.0, because SHA-256 equality and "
        "Ed25519 verification are not inferences. A calibration table for an "
        "equality test would be a number pretending to be a measurement."
    )
    scoring: str = (
        "Exact set equality between expected and observed failure codes, per "
        "record. An extra failure fails the scenario exactly as hard as a "
        "missed one."
    )
    results: tuple[ScenarioResult, ...]

    @property
    def all_passed(self) -> bool:
        return self.scenarios_failed == 0


def evaluate_scenario(
    scenario_dir: Path | str,
    config: Config,
    *,
    lab_root: Path | str | None = None,
) -> ScenarioResult:
    """Verify one scenario and compare the result against its ground truth."""
    directory = Path(scenario_dir)
    truth_path = directory / "ground_truth.json"
    if not truth_path.is_file():
        raise ProvenanceError(f"no ground_truth.json in {directory}")
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    name = directory.name

    provenance_log = ProvenanceLog.load(directory / "log.jsonl")
    store = TrustStore.load(directory / "trust_store.json")
    anchor_path = directory / "anchor.json"
    anchor = (
        LogAnchor.model_validate(json.loads(anchor_path.read_text(encoding="utf-8")))
        if anchor_path.is_file() and truth.get("anchor_supplied", True)
        else None
    )

    expected, expectation_source = _expectation_for(
        name, directory, lab_root, truth
    )

    database = ReplayDatabase.empty()
    primed = name in REPLAY_PRIMED
    if primed:
        clean_log = ProvenanceLog.load(_clean_root(directory, lab_root) / "log.jsonl")
        for entry in clean_log.entries:
            database = database.record(entry)

    report, _, _ = verify_log(
        provenance_log,
        config,
        trust_store=store,
        expected=expected,
        replay_database=database,
        anchor=anchor,
        log_locator=str(directory / "log.jsonl"),
    )

    expected_failures: dict[int, list[str]] = {
        int(position): list(codes)
        for position, codes in truth["expected_failures_by_position"].items()
    }
    expected_replay: dict[int, str] = {
        int(position): verdict
        for position, verdict in truth.get("expected_replay_by_position", {}).items()
    }

    positions: list[PositionResult] = []
    mismatches: list[str] = []
    for record in report.records:
        index = record.position if record.position is not None else -1
        want = sorted(expected_failures.get(index, ["VALID"]))
        got = sorted(record.failures)
        want_replay = expected_replay.get(index)
        failures_match = want == got
        replay_match = want_replay is None or want_replay == record.replay_verdict
        if not failures_match:
            mismatches.append(
                f"position {index}: expected {want}, observed {got}"
            )
        if not replay_match:
            mismatches.append(
                f"position {index}: expected replay {want_replay}, observed "
                f"{record.replay_verdict}"
            )
        positions.append(
            PositionResult(
                position=index,
                record_id=record.record_id,
                expected_failures=tuple(want),
                observed_failures=tuple(got),
                expected_replay=want_replay,
                observed_replay=record.replay_verdict,
                failures_match=failures_match,
                replay_match=replay_match,
            )
        )

    chain_expected = str(truth["expected_chain_status"])
    chain_observed = report.summary.chain_status
    if chain_expected != chain_observed:
        mismatches.append(
            f"chain status: expected {chain_expected}, observed {chain_observed}"
        )

    truncation_expected = str(truth["expected_truncation_status"])
    truncation_observed = report.summary.truncation_status
    if truncation_expected != truncation_observed:
        mismatches.append(
            f"truncation status: expected {truncation_expected}, observed "
            f"{truncation_observed}"
        )

    count_expected = int(truth["expected_record_count"])
    if count_expected != len(report.records):
        mismatches.append(
            f"record count: expected {count_expected}, observed {len(report.records)}"
        )

    malformed_expected = int(truth.get("expected_malformed_lines", 0))
    if malformed_expected != report.summary.malformed_lines:
        mismatches.append(
            f"malformed lines: expected {malformed_expected}, observed "
            f"{report.summary.malformed_lines}"
        )

    return ScenarioResult(
        scenario=name,
        description=str(truth.get("description", "")),
        attack_classes=tuple(truth.get("attack_classes", ())),
        passed=not mismatches,
        record_count_expected=count_expected,
        record_count_observed=len(report.records),
        chain_status_expected=chain_expected,
        chain_status_observed=chain_observed,
        truncation_expected=truncation_expected,
        truncation_observed=truncation_observed,
        malformed_expected=malformed_expected,
        malformed_observed=report.summary.malformed_lines,
        replay_primed=primed,
        expectation_source=expectation_source,
        positions=tuple(positions),
        mismatches=tuple(mismatches),
        overall=report.summary.overall,
        findings_total=report.summary.findings_total,
        report_id=report.report_id,
    )


def evaluate_lab(
    lab_dir: Path | str,
    config: Config,
    *,
    scenarios: Sequence[str] | None = None,
) -> ProvenanceEvaluationReport:
    """Evaluate every scenario in a built lab."""
    root = Path(lab_dir)
    if not root.is_dir():
        raise ProvenanceError(f"provenance lab directory not found: {root}")

    directories = sorted(
        d for d in root.iterdir()
        if d.is_dir() and (d / "ground_truth.json").is_file()
    )
    if scenarios:
        wanted = set(scenarios)
        directories = [d for d in directories if d.name in wanted]
    if not directories:
        raise ProvenanceError(
            f"no built scenarios found under {root}; run `cvtrust provenance "
            "lab-build` first"
        )

    results = [evaluate_scenario(d, config, lab_root=root) for d in directories]
    for result in results:
        if not result.passed:
            log.warning(
                "scenario %s FAILED: %s", result.scenario, "; ".join(result.mismatches)
            )
    return ProvenanceEvaluationReport(
        scenarios_total=len(results),
        scenarios_passed=sum(1 for r in results if r.passed),
        scenarios_failed=sum(1 for r in results if not r.passed),
        results=tuple(results),
    )


def _clean_root(scenario_dir: Path, lab_root: Path | str | None) -> Path:
    root = Path(lab_root) if lab_root else scenario_dir.parent
    return root / "_clean"


def _expectation_for(
    name: str, directory: Path, lab_root: Path | str | None, truth: dict[str, Any]
) -> tuple[ExpectedBinding | None, str]:
    """Build the analyst's independently held expectation for a scenario.

    For every scenario but one this comes from the lab manifest, which records
    what the clean baseline actually was.  For ``modified_model_artifact`` it is
    re-derived from the scenario's own artifacts directory, because that
    scenario's whole point is that the artifact on disk no longer matches the
    records — and an expectation taken from the baseline would test the opposite
    thing.
    """
    if not truth.get("expectations_supplied", True):
        return None, "none supplied"

    manifest_path = _clean_root(directory, lab_root).parent / "lab_manifest.json"
    if not manifest_path.is_file():
        return None, "lab manifest not found"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base = dict(manifest["expected_source"])

    if name in ARTIFACT_DERIVED_EXPECTATION:
        from ..core.hashing import sha256_file
        import hashlib

        model_path = directory / "artifacts" / "model.bin"
        digest = sha256_file(model_path)
        base.update(
            {
                "model_file_sha256": digest,
                "model_graph_digest": hashlib.sha256(
                    f"graph|{digest}".encode()
                ).hexdigest(),
                "model_parameter_digest": hashlib.sha256(
                    f"params|{digest}".encode()
                ).hexdigest(),
                "model_id": f"M-{digest[:16]}",
                "source": f"re-derived from {model_path.name} on disk",
            }
        )
        return ExpectedBinding.model_validate(base), str(base["source"])

    return ExpectedBinding.model_validate(base), str(base["source"])


__all__ = [
    "EVALUATION_SCHEMA_VERSION", "PositionResult", "ScenarioResult",
    "ProvenanceEvaluationReport", "evaluate_scenario", "evaluate_lab",
    "REPLAY_PRIMED", "ARTIFACT_DERIVED_EXPECTATION",
]
