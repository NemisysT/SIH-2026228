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


# ---------------------------------------------------------------------------
# Module 3 — the provenance commands
# ---------------------------------------------------------------------------


def test_provenance_keygen_refuses_an_unencrypted_key_without_the_opt_in(tmp_path):
    result = _run(
        "provenance", "keygen", "--out", str(tmp_path / "k.pem"), expect=2
    )
    assert "refusing to write an unencrypted private key" in result.stderr


def test_provenance_keygen_writes_both_halves_and_warns_about_trust(tmp_path):
    out = _run(
        "provenance", "keygen", "--out", str(tmp_path / "k.pem"),
        "--allow-unencrypted", "--label", "demo",
    ).stdout
    assert "key_id" in out
    assert "trusted by nobody yet" in out
    assert (tmp_path / "k.pem").is_file()
    assert (tmp_path / "k.pub.json").is_file()


def test_the_provenance_lifecycle_runs_end_to_end_from_the_cli(tmp_path):
    """keygen -> trust -> record -> anchor -> verify-log, exactly as documented."""
    key = tmp_path / "k.pem"
    store = tmp_path / "trust.json"
    log = tmp_path / "log.jsonl"
    image = tmp_path / "image.bin"
    model = tmp_path / "model.bin"
    output = tmp_path / "output.json"
    image.write_bytes(b"an-input-image")
    model.write_bytes(b"a-model-artifact")
    output.write_text(
        json.dumps({"task": "classification", "scores": {"defect": 0.91, "clean": 0.09}})
    )

    _run("provenance", "keygen", "--out", str(key), "--allow-unencrypted")
    _run(
        "provenance", "trust", "add", str(tmp_path / "k.pub.json"),
        "--store", str(store), "--provenance", "generated locally for this test",
    )
    for _ in range(3):
        _run(
            "provenance", "record", str(image), str(output),
            "--key", str(key), "--log", str(log),
            "--model-artifact", str(model),
        )

    anchor = tmp_path / "anchor.json"
    _run("provenance", "anchor", str(log), "--out", str(anchor))

    report_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    result = _run(
        "provenance", "verify-log", str(log),
        "--store", str(store), "--anchor", str(anchor),
        "--replay-db", str(tmp_path / "replay.json"),
        "--out", str(report_path), "--markdown-out", str(markdown_path),
    )
    assert "PROVENANCE VERIFIED" in result.stdout
    payload = json.loads(report_path.read_text())
    assert payload["summary"]["records_valid"] == 3
    assert payload["summary"]["chain_status"] == "INTACT"
    assert payload["summary"]["truncation_status"] == "VERIFIED_COMPLETE"
    assert "Inference Provenance Report" in markdown_path.read_text()


def test_a_record_must_bind_a_model(tmp_path):
    image = tmp_path / "i.bin"
    output = tmp_path / "o.json"
    image.write_bytes(b"x")
    output.write_text(json.dumps({"task": "raw", "value": 1}))
    _run("provenance", "keygen", "--out", str(tmp_path / "k.pem"), "--allow-unencrypted")
    result = _run(
        "provenance", "record", str(image), str(output),
        "--key", str(tmp_path / "k.pem"), "--log", str(tmp_path / "l.jsonl"),
        expect=2,
    )
    assert "must bind a model" in result.stderr


def test_verify_log_without_a_trust_store_does_not_report_clean(tmp_path):
    key = tmp_path / "k.pem"
    log = tmp_path / "log.jsonl"
    image = tmp_path / "i.bin"
    model = tmp_path / "m.bin"
    output = tmp_path / "o.json"
    image.write_bytes(b"x")
    model.write_bytes(b"y")
    output.write_text(json.dumps({"task": "classification", "scores": {"a": 0.5}}))
    _run("provenance", "keygen", "--out", str(key), "--allow-unencrypted")
    _run(
        "provenance", "record", str(image), str(output), "--key", str(key),
        "--log", str(log), "--model-artifact", str(model),
    )
    result = _run("provenance", "verify-log", str(log), expect=None)
    # Exit 1 (review), not 3 (quarantine): a check that could not run is an open
    # question, not a compromise. But emphatically not 0 either.
    assert result.returncode == 1
    assert "PROVENANCE UNVERIFIED" in result.stdout
    assert "NOT SUPPLIED" in result.stdout


def test_a_tampered_log_exits_with_the_quarantine_code(tmp_path):
    key = tmp_path / "k.pem"
    store = tmp_path / "trust.json"
    log = tmp_path / "log.jsonl"
    image = tmp_path / "i.bin"
    model = tmp_path / "m.bin"
    output = tmp_path / "o.json"
    image.write_bytes(b"x")
    model.write_bytes(b"y")
    output.write_text(json.dumps({"task": "classification", "scores": {"a": 0.5}}))

    _run("provenance", "keygen", "--out", str(key), "--allow-unencrypted")
    _run("provenance", "trust", "add", str(tmp_path / "k.pub.json"), "--store", str(store))
    for _ in range(2):
        _run(
            "provenance", "record", str(image), str(output), "--key", str(key),
            "--log", str(log), "--model-artifact", str(model),
        )

    lines = log.read_text().splitlines()
    lines[0] = lines[0].replace('"producer":null', '"producer":"forged"')
    log.write_text("\n".join(lines) + "\n")

    result = _run("provenance", "verify-log", str(log), "--store", str(store), expect=3)
    assert "PROVENANCE COMPROMISED" in result.stdout


def test_trust_list_prints_how_each_key_was_obtained(tmp_path):
    store = tmp_path / "trust.json"
    _run("provenance", "keygen", "--out", str(tmp_path / "k.pem"), "--allow-unencrypted")
    _run(
        "provenance", "trust", "add", str(tmp_path / "k.pub.json"),
        "--store", str(store), "--label", "ops", "--provenance", "hand-carried",
    )
    out = _run("provenance", "trust", "list", "--store", str(store)).stdout
    assert "TRUSTED" in out
    assert "hand-carried" in out
    assert "No CA, no PKI" in out


def test_revoking_a_key_changes_the_verdict(tmp_path):
    key = tmp_path / "k.pem"
    store = tmp_path / "trust.json"
    log = tmp_path / "log.jsonl"
    image = tmp_path / "i.bin"
    model = tmp_path / "m.bin"
    output = tmp_path / "o.json"
    image.write_bytes(b"x")
    model.write_bytes(b"y")
    output.write_text(json.dumps({"task": "classification", "scores": {"a": 0.5}}))

    keygen_out = _run(
        "provenance", "keygen", "--out", str(key), "--allow-unencrypted"
    ).stdout
    key_id = keygen_out.split("key_id")[1].split()[0]
    _run("provenance", "trust", "add", str(tmp_path / "k.pub.json"), "--store", str(store))
    _run(
        "provenance", "record", str(image), str(output), "--key", str(key),
        "--log", str(log), "--model-artifact", str(model),
    )
    _run("provenance", "verify-log", str(log), "--store", str(store))

    _run(
        "provenance", "trust", "revoke", key_id, "--store", str(store),
        "--reason", "test revocation",
    )
    result = _run("provenance", "verify-log", str(log), "--store", str(store), expect=None)
    assert result.returncode != 0
    assert "REVOKED" in result.stdout


def test_the_provenance_lab_builds_and_evaluates_from_the_cli(tmp_path):
    lab = tmp_path / "provenance_lab"
    build = _run("lab", "provenance-build", "--out", str(lab), "--records", "6")
    assert "scenario(s) written" in build.stdout

    result = _run(
        "lab", "provenance-evaluate", str(lab),
        "--out", str(tmp_path / "evaluation.json"),
    )
    assert "reproduce exactly" in result.stdout
    payload = json.loads((tmp_path / "evaluation.json").read_text())
    assert payload["scenarios_failed"] == 0
    assert payload["scenarios_total"] >= 20


def test_the_benchmark_reports_storage_and_timings(tmp_path):
    out = tmp_path / "benchmark.json"
    result = _run("provenance", "benchmark", "--records", "40", "--out", str(out))
    assert "Provenance performance" in result.stdout
    payload = json.loads(out.read_text())
    assert payload["record_count"] == 40
    assert {t["operation"] for t in payload["timings"]} >= {
        "record_creation", "signing", "record_verification",
        "chain_verification_full_log", "replay_lookup",
    }
    assert payload["storage"]["log_bytes"] > 0


def test_info_now_declares_module_3_classes_as_covered():
    out = _run("info").stdout
    assert "provenance_key_trust" in out
    assert "chain_truncation" in out
