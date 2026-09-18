"""CLI surface: the commands a judge will actually type."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


def _run(*args: str, expect: int | None = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, "-m", "cvtrust", *args], capture_output=True, text=True
    )
    if expect is not None:
        assert result.returncode == expect, (
            f"exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def test_version_is_reported():
    assert "cvtrust" in _run("version").stdout


def test_info_prints_the_coverage_statement():
    out = _run("info").stdout
    assert "NOT_ASSESSED" in out
    assert "trigger_injection" in out
    assert "inference_replay" in out


def test_scan_of_a_clean_dataset_exits_without_quarantine(clean_root, tmp_path):
    report_path = tmp_path / "report.json"
    result = _run("-q", "dataset", "scan", str(clean_root), "--out", str(report_path),
                  expect=None)
    assert result.returncode in (0, 1), result.stdout
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["summary"]["overall"] != "QUARANTINE REQUIRED"
    assert payload["schema_version"]
    assert payload["coverage"]["entries"]


def test_scan_json_report_round_trips_through_the_model(clean_root, tmp_path):
    from cvtrust.reporting.report import AssuranceReport

    report_path = tmp_path / "report.json"
    _run("-q", "dataset", "scan", str(clean_root), "--out", str(report_path), expect=None)
    report = AssuranceReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    assert report.report_id.startswith("R-")


def test_manifest_and_verify_round_trip(clean_root, tmp_path):
    manifest_path = tmp_path / "manifest.json"
    out = _run("-q", "dataset", "manifest", str(clean_root),
               "--out", str(manifest_path)).stdout
    assert "manifest_id" in out
    assert _run("-q", "dataset", "verify", str(manifest_path), str(clean_root)).returncode == 0


def test_verify_fails_on_a_tampered_dataset(clean_root, tmp_path):
    import shutil

    root = tmp_path / "dataset"
    shutil.copytree(clean_root, root)
    manifest_path = tmp_path / "manifest.json"
    _run("-q", "dataset", "manifest", str(root), "--out", str(manifest_path))

    victim = sorted(root.rglob("*.jpg"))[0]
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0xFF
    victim.write_bytes(bytes(data))

    result = _run("-q", "dataset", "verify", str(manifest_path), str(root), expect=3)
    assert "FAIL" in result.stdout
    assert "MODIFIED" in result.stdout


def test_scan_exits_3_when_quarantine_is_recommended(clean_root, tmp_path):
    from cvtrust.attack_lab import attacks

    scenario = attacks.duplicate_flood(clean_root, tmp_path / "flood")
    result = _run("-q", "dataset", "scan", str(scenario.root), expect=None)
    assert result.returncode == 3, result.stdout


def test_unknown_detector_is_rejected_with_a_clear_error(clean_root):
    result = _run("-q", "dataset", "scan", str(clean_root),
                  "--detectors", "not_a_detector", expect=2)
    assert "unknown detector" in result.stderr


def test_a_missing_dataset_is_an_explained_failure_not_a_traceback(tmp_path):
    result = _run("-q", "dataset", "scan", str(tmp_path / "nope"), expect=2)
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_lab_generate_attack_evaluate_end_to_end(tmp_path):
    lab = tmp_path / "lab"
    _run("-q", "lab", "generate", "--out", str(lab / "_clean"),
         "--per-class", "6", "--no-coco")
    clean_root = lab / "_clean" / "dataset"
    assert clean_root.is_dir()

    _run("-q", "lab", "attack", str(clean_root), str(lab / "combined"),
         "--scenario", "combined")
    ground_truth = json.loads(
        (lab / "combined" / "ground_truth.json").read_text(encoding="utf-8")
    )
    assert ground_truth["affected_count"] > 0

    evaluation = tmp_path / "evaluation.json"
    calibration = tmp_path / "calibration.json"
    _run("-q", "lab", "evaluate", str(lab), "--out", str(evaluation),
         "--calibration-out", str(calibration))

    payload = json.loads(evaluation.read_text(encoding="utf-8"))
    assert payload["scenarios"]
    assert payload["evaluation_population"]

    tables = json.loads(calibration.read_text(encoding="utf-8"))["tables"]
    assert tables
    assert all(table["provenance"]["caveat"] for table in tables)


def test_a_calibrated_scan_reports_measured_confidence(tmp_path):
    """The whole point of calibration: confidence stops being a prior."""
    lab = tmp_path / "lab"
    _run("-q", "lab", "generate", "--out", str(lab / "_clean"),
         "--per-class", "8", "--no-coco")
    clean_root = lab / "_clean" / "dataset"
    _run("-q", "lab", "attack", str(clean_root), str(lab / "near_duplicate_flood"),
         "--scenario", "near_duplicate_flood")
    calibration = tmp_path / "calibration.json"
    _run("-q", "lab", "evaluate", str(lab), "--out", str(tmp_path / "eval.json"),
         "--calibration-out", str(calibration))

    report_path = tmp_path / "report.json"
    _run("-q", "dataset", "scan", str(lab / "near_duplicate_flood" / "dataset"),
         "--calibration", str(calibration), "--out", str(report_path), expect=None)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert payload["calibration"]["status"] == "loaded"
    bases = {f["confidence_basis"] for f in payload["findings"]}
    assert "CALIBRATED" in bases


def test_demo_runs_end_to_end(tmp_path):
    result = _run("-q", "demo", "--workdir", str(tmp_path / "attack_lab"),
                  "--per-class", "6")
    assert "tampering detected" in result.stdout
    reports = tmp_path / "attack_lab" / "reports"
    assert (reports / "demo_attacked.json").is_file()
    assert (reports / "demo_attacked.md").is_file()
