"""Module 5's backend boundary: the frontend must see what the engine decided.

These tests do not start a web server. They assert the property that makes the
frontend trustworthy: every file in the analyst feed is a verbatim module
report, and the catalogue projection never contradicts the report it points at.
A frontend built on a feed with this property cannot display a disposition the
engine did not produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cvtrust.attack_lab.assurance_evaluate import PIPELINE_SPECS
from cvtrust.core.config import Config
from cvtrust.reporting.analyst_export import (
    EXPORT_SCHEMA_VERSION,
    FEATURED_SCENARIOS,
    export_scenarios,
    load_assurance_lab,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEED = PROJECT_ROOT / "reports" / "analyst"

#: The scenarios §18 names. If any of these stops being exported the demo is
#: no longer the demo the brief asks for.
REQUIRED_SCENARIOS = (
    "clean_baseline",
    "operational_shift",
    "dataset_anomaly",
    "model_anomaly_uncalibrated",
    "provenance_tampering",
    "combined_attack",
)


@pytest.fixture(scope="module")
def catalogue() -> dict:
    if not (FEED / "index.json").is_file():
        pytest.skip("run `cvtrust analyst export` to build the analyst feed")
    return json.loads((FEED / "index.json").read_text(encoding="utf-8"))


def _rows(catalogue: dict) -> dict[str, dict]:
    return {row["name"]: row for row in catalogue["scenarios"]}


def test_catalogue_covers_the_whole_pipeline_matrix(catalogue: dict) -> None:
    exported = {row["name"] for row in catalogue["scenarios"]}
    declared = {str(spec["name"]) for spec in PIPELINE_SPECS}
    assert exported == declared, (
        "the feed must carry every scenario in the matrix, including any that "
        "did not run — a demo that quietly drops its own missing inputs is "
        "misleading"
    )
    assert catalogue["schema_version"] == EXPORT_SCHEMA_VERSION
    assert catalogue["kind"] == "DEMO"


def test_every_brief_scenario_is_present_and_ran(catalogue: dict) -> None:
    rows = _rows(catalogue)
    for name in REQUIRED_SCENARIOS:
        assert name in rows, f"§18 requires the {name} scenario"
        assert rows[name]["status"] == "RUN", (
            f"{name} did not run: {rows[name]['reason']}"
        )
    for name in FEATURED_SCENARIOS:
        assert rows[name]["featured"] is True


def test_catalogue_disposition_matches_the_report_it_points_at(catalogue: dict) -> None:
    """The projection must never disagree with the report.

    This is the property the frontend relies on: it renders the catalogue on
    list screens and the report on detail screens, and the two must be the same
    answer.
    """
    for row in catalogue["scenarios"]:
        if row["status"] != "RUN":
            assert row["observed_disposition"] is None
            assert row["reason"], "a NOT_RUN scenario must say why"
            continue

        report = json.loads((FEED / row["files"]["assurance"]).read_text(encoding="utf-8"))
        decision = report["decision"]

        assert row["observed_disposition"] == decision["disposition"]
        assert row["summary"]["report_id"] == report["report_id"]
        assert row["summary"]["decision_id"] == decision["decision_id"]
        assert row["summary"]["statement"] == decision["summary"]
        assert row["summary"]["policy_version"] == decision["policy_version"]
        assert row["summary"]["fired_rules"] == sorted(
            {outcome["rule_id"] for outcome in decision["fired_rules"]}
        )
        assert row["summary"]["evidence_total"] == len(report["evidence"]["evidence"])
        assert row["summary"]["source_findings_total"] == len(report["source_findings"])
        assert row["summary"]["unassessed_areas"] == len(decision["unassessed_areas"])

        for scope, projected in row["summary"]["scopes"].items():
            source = report[f"{scope}_assurance"]
            assert projected["disposition"] == source["disposition"]
            assert projected["assessed"] == source["assessed"]
            assert projected["governing_rule"] == source["governing_rule"]
            assert projected["statement"] == source["statement"]
            assert projected["findings"] == source["findings"]


def test_upstream_reports_are_byte_identical_to_what_the_modules_wrote(
    catalogue: dict,
) -> None:
    """The dataset page must show the dataset module's own JSON, not a rewrite."""
    for row in catalogue["scenarios"]:
        if row["status"] != "RUN":
            continue
        for key, module in (("dataset", "1"), ("model", "2"), ("provenance", "3")):
            path = row["files"].get(key)
            if path is None:
                continue
            report = json.loads((FEED / path).read_text(encoding="utf-8"))
            assert report["module"].startswith(module), (
                f"{row['name']}/{key}.json is not a Module {module} report"
            )
            assert "report_id" in report and "coverage" in report


def test_no_report_in_the_feed_carries_an_aggregate_score(catalogue: dict) -> None:
    """The architecture has no universal score; the feed must not grow one."""
    banned = {
        "trust_score",
        "security_score",
        "safety_score",
        "overall_score",
        "risk_score",
        "overall_confidence",
        "aggregate_score",
    }

    def walk(node: object, where: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                assert key not in banned, f"{where}: report grew a '{key}' field"
                walk(value, f"{where}.{key}")
        elif isinstance(node, list):
            for item in node[:20]:
                walk(item, where)

    for row in catalogue["scenarios"]:
        for key, path in (row.get("files") or {}).items():
            walk(
                json.loads((FEED / path).read_text(encoding="utf-8")),
                f"{row['name']}/{key}",
            )


def test_inputs_supplied_reflects_what_the_run_received(catalogue: dict) -> None:
    rows = _rows(catalogue)

    everything = rows["clean_baseline"]["summary"]["inputs_supplied"]
    assert all(everything.values()), "the clean baseline supplies all four inputs"

    nothing = rows["no_inputs"]
    assert nothing["observed_disposition"] == "NOT_ASSESSED", (
        "supplying nothing must produce NOT_ASSESSED, never ACCEPT"
    )
    assert not any(nothing["summary"]["inputs_supplied"].values())

    partial = rows["dataset_only"]
    assert partial["observed_disposition"] == "NOT_ASSESSED"
    assert partial["summary"]["inputs_supplied"]["dataset"] is True
    assert partial["summary"]["inputs_supplied"]["model"] is False


def test_the_operational_shift_control_does_not_escalate(catalogue: dict) -> None:
    """§18 scenario B: a legitimate declared change must not become an attack."""
    row = _rows(catalogue)["operational_shift"]
    assert row["observed_disposition"] == "ACCEPT"
    report = json.loads((FEED / row["files"]["assurance"]).read_text(encoding="utf-8"))

    # The declared night collection must be recognised as explaining the
    # movement. "attack class" is ordinary coverage vocabulary, so the thing to
    # assert is the claim, not the word: no scope may assert compromise.
    assert report["distribution_shift"]["context"]["explanation"] != "UNEXPLAINED"
    assert report["distribution_shift"]["verdict"] != "NOT_ASSESSED"

    claims = ("attack detected", "malicious", "compromise", "adversar")
    for scope in ("dataset", "model", "provenance", "distribution"):
        statement = report[f"{scope}_assurance"]["statement"].lower()
        assert all(claim not in statement for claim in claims), (
            f"{scope} asserted compromise on a legitimate declared change: {statement}"
        )
        assert report[f"{scope}_assurance"]["disposition"] == "ACCEPT"


def test_correlated_findings_are_not_counted_as_independent(catalogue: dict) -> None:
    """§13: one phenomenon seen by three detectors is not three attacks."""
    row = _rows(catalogue)["ood_without_attack"]
    report = json.loads((FEED / row["files"]["assurance"]).read_text(encoding="utf-8"))
    confounded = [
        item for item in report["evidence"]["evidence"] if item["active_confounders"]
    ]
    assert confounded, "this scenario exists to exercise confounding"
    assert report["evidence_summary"]["independent_families"] == [], (
        "a single legitimate sensor change must not read as independent evidence"
    )
    assert row["observed_disposition"] == "ACCEPT"


def test_combined_attack_keeps_its_scopes_apart(catalogue: dict) -> None:
    """§18 scenario E: multiple independent streams stay distinguishable."""
    row = _rows(catalogue)["combined_attack"]
    scopes = row["summary"]["scopes"]
    assert row["observed_disposition"] == "QUARANTINE"
    assert len({scope["disposition"] for scope in scopes.values()}) > 1, (
        "the report must not collapse four scopes into one narrative"
    )
    assert len(row["summary"]["independent_families"]) > 1


def test_export_is_deterministic(tmp_path: Path) -> None:
    """Two exports of the same labs must agree on every decision.

    Timestamps and durations differ between runs by design; the decisions,
    rules and evidence counts must not.
    """
    lab_dir = PROJECT_ROOT / "assurance_lab"
    if not (lab_dir / "lab_spec.json").is_file():
        pytest.skip("run `cvtrust lab assurance-build` first")

    config = Config.load(None)
    specs = tuple(
        spec for spec in PIPELINE_SPECS if spec["name"] in {"clean_baseline", "no_inputs"}
    )

    def run(out: Path) -> dict:
        return export_scenarios(
            out,
            config,
            assurance_lab=load_assurance_lab(lab_dir),
            dataset_lab_root=PROJECT_ROOT / "attack_lab",
            model_lab_root=PROJECT_ROOT / "model_lab",
            provenance_lab_root=PROJECT_ROOT / "provenance_lab",
            work_dir=tmp_path / "work",
            specs=specs,
        )

    first = run(tmp_path / "a")
    second = run(tmp_path / "b")

    def stable(catalogue: dict) -> list[tuple]:
        return [
            (
                row["name"],
                row["status"],
                row["observed_disposition"],
                tuple(row["summary"].get("fired_rules", ())),
                row["summary"].get("evidence_total"),
                row["summary"].get("report_id"),
            )
            for row in catalogue["scenarios"]
        ]

    assert stable(first) == stable(second)


def test_a_missing_upstream_lab_is_reported_not_fabricated(tmp_path: Path) -> None:
    """A scenario whose lab is absent must export as NOT_RUN with a reason."""
    lab_dir = PROJECT_ROOT / "assurance_lab"
    if not (lab_dir / "lab_spec.json").is_file():
        pytest.skip("run `cvtrust lab assurance-build` first")

    catalogue = export_scenarios(
        tmp_path / "feed",
        Config.load(None),
        assurance_lab=load_assurance_lab(lab_dir),
        dataset_lab_root=None,
        model_lab_root=None,
        provenance_lab_root=None,
        work_dir=tmp_path / "work",
        specs=(
            {
                "name": "provenance_tampering",
                "dataset": "_clean",
                "model": "_reference",
                "provenance": "modified_output",
                "shift": "clean_baseline",
                "expect": "QUARANTINE",
                "rules": (),
            },
        ),
    )
    row = catalogue["scenarios"][0]
    assert row["status"] == "NOT_RUN"
    assert row["observed_disposition"] is None
    assert "provenance lab scenario" in row["reason"]
    assert row["files"] == {}, "nothing must be written for a scenario that did not run"
