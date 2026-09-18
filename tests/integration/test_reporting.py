"""Reporting: the analyst view must be generated from the report object.

If the console/Markdown renderings were assembled independently of the JSON,
they would drift, and the human and machine records of an assessment would
disagree.  These tests run the renderers in-process over real reports.
"""

from __future__ import annotations

import pytest

from cvtrust.attack_lab import attacks
from cvtrust.core.errors import DetectorUnavailable
from cvtrust.pipeline import analyse
from cvtrust.reporting.render import (
    render_coverage,
    render_evaluation,
    render_markdown,
    render_report,
)

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def attacked(clean_root, tmp_path_factory):
    lab = tmp_path_factory.mktemp("report_lab")
    scenario = attacks.combined(clean_root, lab / "combined")
    from cvtrust.core.config import Config

    report, _, _ = analyse(
        scenario.root, Config(),
        reference_sample_ids=set(scenario.ground_truth["clean"]),
    )
    return report, scenario, lab


def test_console_rendering_runs_over_a_real_report(attacked, capsys):
    report, _, _ = attacked
    render_report(report, full=True)
    out = capsys.readouterr().out
    assert report.summary.overall in out
    assert "Coverage statement" in out
    assert "NOT ASSESSED — Module 2" in out


def test_console_rendering_of_a_clean_report_states_the_coverage_caveat(
    clean_root, config, capsys
):
    report, _, _ = analyse(clean_root, config)
    render_report(report)
    out = capsys.readouterr().out
    assert "Reproducibility" in out
    assert "Limitations of this assessment" in out


def test_markdown_carries_every_finding_and_its_evidence(attacked):
    report, _, _ = attacked
    markdown = render_markdown(report)
    for finding in report.findings:
        assert finding.finding_id in markdown
        assert finding.attack_class in markdown
        assert finding.disposition.value in markdown
        for item in finding.evidence:
            assert item.statement.split(".")[0][:40] in markdown


def test_markdown_carries_provenance_and_coverage(attacked):
    report, _, _ = attacked
    markdown = render_markdown(report)
    assert report.dataset["digest"] in markdown
    assert report.configuration["config_hash"] in markdown
    for entry in report.coverage.entries:
        assert entry.attack_class in markdown
    for limitation in report.limitations:
        assert limitation[:50] in markdown


def test_coverage_can_be_rendered_standalone(capsys):
    from cvtrust.risk.coverage import CoverageStatement

    render_coverage(CoverageStatement.build([], (1,)))
    out = capsys.readouterr().out
    assert "trigger_injection" in out
    assert "SUPPORTED and PARTIAL" in out


def test_evaluation_rendering_handles_inapplicable_metrics(attacked, capsys):
    """precision_actionable is None for contributor-level classes, not zero."""
    from cvtrust.attack_lab.evaluate import EvaluationReport, evaluate_scenario
    from cvtrust.core.config import Config

    _, _, lab = attacked
    result, _ = evaluate_scenario(lab / "combined", Config())
    render_evaluation(
        EvaluationReport(
            config_hash=Config().config_hash(), software_version="test",
            scenarios=[result],
        )
    )
    out = capsys.readouterr().out
    assert "Evaluation population" in out
    inapplicable = [m for m in result.metrics if m.precision_actionable is None]
    if inapplicable:
        assert "n/a" in out


def test_the_demo_runs_in_process_and_writes_its_artifacts(tmp_path, capsys):
    from cvtrust.reporting.demo import run_demo

    run_demo(tmp_path / "lab", per_class=6, reports_dir=tmp_path / "reports")
    out = capsys.readouterr().out
    assert "STEP 1" in out and "STEP 8" in out
    assert "tampering detected" in out
    for name in ("demo_clean.json", "demo_attacked.json", "demo_attacked.md"):
        assert (tmp_path / "reports" / name).is_file()
