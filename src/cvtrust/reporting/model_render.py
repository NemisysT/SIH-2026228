"""Human rendering of the model assurance report.

Generated *from* the report object, never assembled separately, so the analyst
view and the machine view cannot drift apart — the same rule Module 1's
renderer follows.

The screen leads with the **assessment matrix**, because that is the artifact
that answers an analyst's actual question: not "how bad is this model" but
"which of these six things did you check, what did each say, and what could you
not check at all".
"""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.evidence import Finding
from .render import (
    BASIS_NOTE,
    _finding_panel,
    render_coverage,
)
from .model_report import AssessmentStatus, ModelAssuranceReport

console = Console()

STATUS_STYLE: dict[AssessmentStatus, str] = {
    AssessmentStatus.VERIFIED: "bold green",
    AssessmentStatus.NO_ANOMALY_DETECTED: "green",
    AssessmentStatus.CONSISTENT: "green",
    AssessmentStatus.MISMATCH: "bold red",
    AssessmentStatus.ANOMALOUS: "yellow",
    AssessmentStatus.HIGH_RISK_INDICATOR: "bold white on red",
    AssessmentStatus.REQUIRES_WHITE_BOX: "magenta",
    AssessmentStatus.NOT_ASSESSED: "dim",
    AssessmentStatus.ASSESSMENT_UNAVAILABLE: "dim",
}

STATUS_MARK: dict[AssessmentStatus, str] = {
    AssessmentStatus.VERIFIED: "✓",
    AssessmentStatus.NO_ANOMALY_DETECTED: "✓",
    AssessmentStatus.CONSISTENT: "✓",
    AssessmentStatus.MISMATCH: "⚠",
    AssessmentStatus.ANOMALOUS: "⚠",
    AssessmentStatus.HIGH_RISK_INDICATOR: "‼",
    AssessmentStatus.REQUIRES_WHITE_BOX: "—",
    AssessmentStatus.NOT_ASSESSED: "—",
    AssessmentStatus.ASSESSMENT_UNAVAILABLE: "—",
}

OVERALL_STYLE = {
    "QUARANTINE REQUIRED": "bold white on red",
    "REVIEW REQUIRED — HIGH-RISK INDICATOR": "bold white on red",
    "REVIEW REQUIRED": "bold red",
    "REVIEW RECOMMENDED": "bold yellow",
    "NO ANOMALY DETECTED — PARTIAL COVERAGE": "bold yellow",
    "NO ANOMALY DETECTED": "bold green",
}

LEVEL_TITLE: dict[str, str] = {
    "identity": "Identity",
    "structure": "Structure",
    "parameters": "Parameters",
    "behaviour": "Behaviour",
    "activation": "Activation",
    "trigger": "Trigger assessment",
}


def render_model_report(
    report: ModelAssuranceReport, *, full: bool = False, max_findings: int = 12
) -> None:
    console.print()
    console.print(
        Panel(
            Group(
                Text(
                    report.summary.overall,
                    style=OVERALL_STYLE.get(report.summary.overall, "bold"),
                ),
                Text(report.summary.rationale, style="dim"),
            ),
            title="[bold]MODEL ASSURANCE[/bold]",
            subtitle=f"report {report.report_id} · run {report.run.run_id}",
            border_style="blue",
        )
    )

    _render_identity(report)
    _render_access(report)
    _render_matrix(report)
    _render_findings(report, full=full, max_findings=max_findings)
    render_coverage(report.coverage)
    _render_battery(report)
    _render_provenance(report)


def _render_identity(report: ModelAssuranceReport) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim", width=22)
    table.add_column()
    model = report.model
    table.add_row("model", Text(str(model["path"]), style="bold"))
    table.add_row("model id", model["model_id"])
    table.add_row("format", model["format"])
    table.add_row("SHA-256 (artifact)", model["file_sha256"])
    table.add_row("graph digest", model["graph_digest"] or Text("unavailable", style="dim"))
    table.add_row(
        "parameter digest", model["parameter_digest"] or Text("unavailable", style="dim")
    )
    table.add_row("parameters", str(model["parameter_count"]))
    declared = model.get("architecture_declared")
    table.add_row(
        "architecture",
        Text.assemble(
            (str(declared or "not declared"), "white"),
            ("  (declared by the artifact — untrusted, not used for identity)", "dim"),
        ),
    )
    if report.reference:
        table.add_row("", "")
        table.add_row("reference", Text(str(report.reference["path"]), style="bold"))
        table.add_row("reference SHA-256", report.reference["file_sha256"])
    console.print(Panel(table, title="Model identity", border_style="dim"))


def _render_access(report: ModelAssuranceReport) -> None:
    access = report.access
    body: list[Any] = [
        Text.assemble(
            ("Access mode: ", "dim"),
            (access["access_mode"], "bold"),
            (f"   adapter {access['adapter']} v{access['adapter_version']}", "dim"),
        ),
        Text.assemble(
            ("Available:   ", "dim"), (", ".join(access["capabilities"]) or "none", "green")
        ),
        Text.assemble(
            ("Absent:      ", "dim"),
            (", ".join(access["capabilities_absent"]) or "none", "yellow"),
        ),
        Text(""),
    ]
    for line in access["consequences"]:
        body.append(Text(f"• {line}", style="dim"))
    console.print(
        Panel(Group(*body), title="Access assessment", border_style="dim")
    )


def _render_matrix(report: ModelAssuranceReport) -> None:
    table = Table(
        box=None, show_header=False, pad_edge=False,
        caption="Six levels, kept separate on purpose. There is no single "
                "'model trust' score, and there will not be one.",
    )
    table.add_column(style="bold", width=18)
    table.add_column(width=3)
    table.add_column(width=24)
    table.add_column()
    for level in report.assessment.levels():
        style = STATUS_STYLE.get(level.status, "white")
        table.add_row(
            LEVEL_TITLE.get(level.level, level.level),
            Text(STATUS_MARK.get(level.status, "?"), style=style),
            Text(level.status.value, style=style),
            Text(level.detail, style="dim"),
        )
        if level.reason:
            table.add_row("", "", "", Text(f"  reason: {level.reason}", style="dim italic"))
    console.print(Panel(table, title="Assessment", border_style="blue"))


def _render_findings(report: ModelAssuranceReport, *, full: bool, max_findings: int) -> None:
    findings: list[Finding] = report.findings
    if not findings:
        console.print(
            Panel(
                Text(
                    "No findings. This is a statement about the assessment levels "
                    "that ran and the attack classes declared SUPPORTED or PARTIAL "
                    "below, and about nothing else. It is not a statement that the "
                    "model is safe.",
                    style="green",
                ),
                title="Findings",
                border_style="green",
            )
        )
        return
    shown = findings if full else findings[:max_findings]
    for finding in shown:
        console.print(_finding_panel(finding))
    if len(shown) < len(findings):
        console.print(
            Text(
                f"  … {len(findings) - len(shown)} further finding(s); use --full "
                "or read the JSON report.",
                style="dim",
            )
        )


def _render_battery(report: ModelAssuranceReport) -> None:
    battery = report.battery
    if not battery or battery.get("built") is False:
        console.print(
            Panel(
                Text(str(battery.get("reason", "no battery")), style="dim"),
                title="Reference battery",
                border_style="dim",
            )
        )
        return
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim", width=22)
    table.add_column()
    table.add_row("battery version", battery["battery_version"])
    table.add_row("battery digest", battery["battery_digest"])
    table.add_row("input shape", str(battery["input_shape"]))
    table.add_row("probes", str(battery["total_probes"]))
    table.add_row(
        "by category",
        ", ".join(f"{k}={v}" for k, v in battery["probes_by_category"].items()),
    )
    table.add_row("trigger family", f"{len(battery['trigger_family'])} declared members")
    for member in battery["trigger_family"]:
        table.add_row(
            "",
            Text(
                f"  {member['position']} · size {member['size_fraction']} · "
                f"{member['pattern']}",
                style="dim",
            ),
        )
    console.print(
        Panel(
            table,
            title="Reference battery — the scope of every behavioural claim",
            border_style="dim",
        )
    )


def _render_provenance(report: ModelAssuranceReport) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim", width=22)
    table.add_column()
    table.add_row("model digest", report.model["file_sha256"])
    table.add_row("manifest id", report.model["manifest_id"])
    table.add_row("config hash", report.configuration["config_hash"])
    table.add_row("run id", report.run.run_id)
    table.add_row("seed", str(report.run.seed))
    table.add_row("software", f"cvtrust {report.run.software_version}")
    for name, version in sorted(report.access["runtime"].items()):
        table.add_row(f"runtime {name}", version)
    table.add_row("calibration", report.calibration["status"])
    table.add_row(
        "benchmark",
        report.benchmark.get("benchmark", "not available")
        if report.benchmark.get("available")
        else "NOT_ASSESSED — no local artifacts (never downloaded)",
    )
    console.print(Panel(table, title="Reproducibility", border_style="dim"))

    limitations = Table(box=None, show_header=False, pad_edge=False)
    limitations.add_column(style="dim", width=2)
    limitations.add_column(style="dim")
    for limitation in report.limitations:
        limitations.add_row("!", limitation)
    console.print(
        Panel(limitations, title="Limitations of this assessment", border_style="dim")
    )


def render_model_markdown(report: ModelAssuranceReport) -> str:
    """Markdown rendering of the same report object, for archival and review."""
    lines: list[str] = [
        f"# Model Assurance Report — {report.report_id}",
        "",
        f"**Overall assessment: {report.summary.overall}**",
        "",
        report.summary.rationale,
        "",
        "## Model identity",
        "",
        "| field | value |",
        "|---|---|",
        f"| path | `{report.model['path']}` |",
        f"| model id | `{report.model['model_id']}` |",
        f"| format | {report.model['format']} |",
        f"| SHA-256 (artifact) | `{report.model['file_sha256']}` |",
        f"| graph digest | `{report.model['graph_digest'] or 'unavailable'}` |",
        f"| parameter digest | `{report.model['parameter_digest'] or 'unavailable'}` |",
        f"| parameters | {report.model['parameter_count']} |",
        f"| declared architecture | {report.model['architecture_declared'] or 'not declared'} "
        "(untrusted; not used for identity) |",
        "",
        "## Access",
        "",
        f"- **Mode**: `{report.access['access_mode']}`",
        f"- **Available capabilities**: {', '.join(report.access['capabilities']) or 'none'}",
        f"- **Absent capabilities**: {', '.join(report.access['capabilities_absent']) or 'none'}",
        "",
    ]
    for line in report.access["consequences"]:
        lines.append(f"- {line}")
    lines += ["", "## Assessment", "", "| level | status | detail |", "|---|---|---|"]
    for level in report.assessment.levels():
        detail = level.detail + (f" _(reason: {level.reason})_" if level.reason else "")
        lines.append(
            f"| {LEVEL_TITLE.get(level.level, level.level)} | "
            f"**{level.status.value}** | {detail} |"
        )

    lines += ["", "## Findings", ""]
    if not report.findings:
        lines += [
            "No findings within the declared coverage. This is not a statement "
            "that the model is safe.",
            "",
        ]
    for finding in report.findings:
        lines += [
            f"### {finding.finding_id} — {finding.title}",
            "",
            f"- **Asset**: `{finding.asset.type.value}:{finding.asset.id}`",
            f"- **Attack class**: `{finding.attack_class}`",
            f"- **Severity**: {finding.severity.value} · "
            f"**Confidence**: {finding.confidence:.2f} "
            f"({BASIS_NOTE[finding.confidence_basis]}) · "
            f"**Coverage**: {finding.coverage.value}",
            f"- **Method**: `{finding.method}` v{finding.method_version}",
            f"- **Recommended disposition**: **{finding.disposition.value}** "
            f"(rule `{finding.disposition_rule}`)",
            "",
            "**Evidence**",
            "",
        ]
        for item in finding.evidence:
            lines.append(f"- {item.statement}")
        if finding.limitations:
            lines += ["", "**Limitations**", ""]
            lines += [f"- {limitation}" for limitation in finding.limitations]
        lines.append("")

    lines += [
        "## Coverage", "",
        "| attack class | coverage | module | detector / reason |",
        "|---|---|---|---|",
    ]
    for entry in report.coverage.entries:
        lines.append(
            f"| `{entry.attack_class}` | {entry.coverage.value} | {entry.owning_module} | "
            f"{entry.detector or (entry.reason or '')} |"
        )
    lines += ["", "## Limitations of this assessment", ""]
    lines += [f"- {limitation}" for limitation in report.limitations]
    return "\n".join(lines) + "\n"


def render_model_evaluation(report) -> None:
    """Console rendering of the model evaluation report."""
    for scoring, metrics in (
        ("detector-attributed", report.metrics),
        ("level-outcome", report.level_metrics),
    ):
        table = Table(
            title=f"Model detector metrics — {scoring} scoring "
                  f"({len(report.scenarios)} model artifacts, format {report.artifact_format})",
            caption="The unit of evaluation is the MODEL, so every rate rests on "
                    "few observations.",
        )
        table.add_column("Attack class", style="bold")
        table.add_column("Detector / level")
        table.add_column("P", justify="right")
        table.add_column("R", justify="right")
        table.add_column("F1", justify="right")
        table.add_column("FPR", justify="right")
        table.add_column("AUROC", justify="right")
        table.add_column("TP/FP/FN/TN", justify="right")
        for metric in metrics:
            table.add_row(
                metric.attack_class,
                metric.detector or "-",
                f"{metric.precision:.3f}",
                f"{metric.recall:.3f}",
                f"{metric.f1:.3f}",
                f"{metric.false_positive_rate:.3f}",
                "-" if metric.auroc is None else f"{metric.auroc:.3f}",
                f"{metric.true_positives}/{metric.false_positives}/"
                f"{metric.false_negatives}/{metric.true_negatives}",
            )
        console.print(table)

    scenarios = Table(title="Per-scenario outcome")
    scenarios.add_column("Scenario", style="bold")
    scenarios.add_column("Ground truth")
    scenarios.add_column("Identity")
    scenarios.add_column("Struct")
    scenarios.add_column("Param")
    scenarios.add_column("Behav")
    scenarios.add_column("Activ")
    scenarios.add_column("Trigger")
    scenarios.add_column("ms", justify="right")
    for result in report.scenarios:
        assessment = result.assessment
        scenarios.add_row(
            result.scenario,
            ", ".join(result.attack_classes),
            *[
                Text(
                    _abbrev(assessment.get(level, "?")),
                    style=STATUS_STYLE.get(
                        AssessmentStatus(assessment[level]) if level in assessment else
                        AssessmentStatus.NOT_ASSESSED, "white",
                    ),
                )
                for level in ("identity", "structure", "parameters", "behaviour",
                              "activation", "trigger")
            ],
            str(result.duration_ms),
        )
    console.print(scenarios)

    if getattr(report, "deterministic_verification", None):
        verification = Table(
            title="Deterministic verification — scored against the fact asserted, "
                  "not against an attack label",
        )
        verification.add_column("Level", style="bold")
        verification.add_column("Claim")
        verification.add_column("Correct", justify="right")
        verification.add_column("Accuracy", justify="right")
        for entry in report.deterministic_verification:
            verification.add_row(
                entry.level,
                entry.claim,
                f"{entry.correct}/{entry.total}",
                Text(
                    f"{entry.accuracy:.3f}",
                    style="bold green" if entry.accuracy >= 1.0 else "yellow",
                ),
            )
        console.print(verification)
        console.print(Text(report.scoring_caveat, style="dim"))

    runtime = Table(box=None, show_header=False, pad_edge=False)
    runtime.add_column(style="dim", width=24)
    runtime.add_column()
    for key, value in sorted(report.runtime.items()):
        runtime.add_row(key, str(value))
    console.print(Panel(runtime, title="Performance", border_style="dim"))
    console.print(
        Panel(
            Text(report.evaluation_population, style="dim"),
            title="Evaluation population",
            border_style="dim",
        )
    )


def _abbrev(status: str) -> str:
    return {
        "VERIFIED": "VERIF", "NO_ANOMALY_DETECTED": "clean", "CONSISTENT": "match",
        "MISMATCH": "MISM", "ANOMALOUS": "ANOM", "HIGH_RISK_INDICATOR": "RISK",
        "REQUIRES_WHITE_BOX": "wbox", "NOT_ASSESSED": "n/a",
        "ASSESSMENT_UNAVAILABLE": "unav",
    }.get(status, status[:5])
