"""Human-readable rendering of the assurance report.

The screen is for an analyst, not a developer, so it answers the six questions
in order and nothing else:

    What happened?  Why?  How confident are we?  What proves it?
    What asset is affected?  What should I do?

Deliberately absent: score gauges, risk dials, and any number that is not
traceable to an observation printed beside it.
"""

from __future__ import annotations

from typing import Any, Iterable

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.evidence import (
    SEVERITY_ORDER,
    ConfidenceBasis,
    Coverage,
    Disposition,
    Finding,
    Severity,
)
from ..risk.coverage import CoverageStatement

console = Console()

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

DISPOSITION_STYLE: dict[Disposition, str] = {
    Disposition.QUARANTINE: "bold red",
    Disposition.REVIEW: "yellow",
    Disposition.ACCEPT: "green",
}

COVERAGE_STYLE: dict[Coverage, str] = {
    Coverage.SUPPORTED: "green",
    Coverage.PARTIAL: "yellow",
    Coverage.NOT_SUPPORTED: "red",
    Coverage.NOT_ASSESSED: "dim",
    Coverage.REQUIRES_WHITE_BOX: "magenta",
}

BASIS_NOTE: dict[ConfidenceBasis, str] = {
    ConfidenceBasis.DETERMINISTIC: "verified fact",
    ConfidenceBasis.STATISTICAL: "hypothesis test",
    ConfidenceBasis.CALIBRATED: "measured precision",
    ConfidenceBasis.HEURISTIC_UNCALIBRATED: "uncalibrated prior",
}

OVERALL_STYLE = {
    "QUARANTINE REQUIRED": "bold white on red",
    "REVIEW REQUIRED": "bold red",
    "REVIEW RECOMMENDED": "bold yellow",
    "NO ACTIONABLE FINDINGS": "bold green",
}


def render_report(report, *, full: bool = False, max_findings: int = 12) -> None:
    console.print()
    console.print(
        Panel(
            Group(
                Text(report.summary.overall, style=OVERALL_STYLE.get(report.summary.overall, "bold")),
                Text(report.summary.rationale, style="dim"),
            ),
            title="[bold]PIPELINE ASSURANCE — DATASET[/bold]",
            subtitle=f"report {report.report_id} · run {report.run.run_id}",
            border_style="blue",
        )
    )

    _render_domains(report)
    _render_findings(report, full=full, max_findings=max_findings)
    _render_contributors(report)
    render_coverage(report.coverage)
    _render_provenance(report)


def _render_domains(report) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="bold", width=16)
    table.add_column()

    counts = report.summary.by_severity
    worst = max(
        (Severity(s) for s, n in counts.items() if n), key=lambda s: SEVERITY_ORDER[s],
        default=Severity.INFO,
    )
    table.add_row("Dataset", _status_text(worst, report.summary.findings_total))
    for domain, module in (("Model", 2), ("Inference", 3), ("Distribution", 4)):
        table.add_row(
            domain,
            Text(f"NOT ASSESSED — Module {module} is not part of this build", style="dim"),
        )
    console.print(Panel(table, title="Assurance domains", border_style="dim"))


def _status_text(worst: Severity, total: int) -> Text:
    if total == 0:
        return Text("VERIFIED — no findings within declared coverage", style="green")
    return Text(
        f"{worst.value} — {total} finding(s)", style=SEVERITY_STYLE.get(worst, "white")
    )


def _render_findings(report, *, full: bool, max_findings: int) -> None:
    findings: list[Finding] = report.findings
    if not findings:
        console.print(
            Panel(
                Text(
                    "No findings. This is a statement about the attack classes "
                    "declared SUPPORTED or PARTIAL below, and about nothing else.",
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
                f"  … {len(findings) - len(shown)} further finding(s); "
                "use --full or read the JSON report.",
                style="dim",
            )
        )


def _finding_panel(finding: Finding) -> Panel:
    header = Table(box=None, show_header=False, pad_edge=False)
    header.add_column(style="bold", width=13)
    header.add_column()
    header.add_row("Asset", f"{finding.asset.type.value}:{finding.asset.id}")
    if finding.contributor:
        header.add_row("Contributor", finding.contributor)
    header.add_row(
        "Assessment",
        Text.assemble(
            (finding.severity.value, SEVERITY_STYLE.get(finding.severity, "white")),
            ("  ·  confidence ", "dim"),
            (f"{finding.confidence:.2f}", "bold"),
            (f"  ({BASIS_NOTE[finding.confidence_basis]})", "dim"),
            ("  ·  coverage ", "dim"),
            (finding.coverage.value, COVERAGE_STYLE.get(finding.coverage, "white")),
        ),
    )
    header.add_row("Method", f"{finding.method} v{finding.method_version}")

    evidence = Table(box=None, show_header=False, pad_edge=False)
    evidence.add_column(style="dim", width=2)
    evidence.add_column()
    for item in finding.evidence:
        evidence.add_row("•", Text(item.statement))
        keys = ", ".join(f"{k}" for k in list(item.observation)[:6])
        evidence.add_row("", Text(f"  observation: {keys}", style="dim italic"))

    footer = Text.assemble(
        ("Recommended disposition: ", "dim"),
        (finding.disposition.value, DISPOSITION_STYLE[finding.disposition]),
        (f"   [rule {finding.disposition_rule}]", "dim"),
    )

    body: list[Any] = [header, Text("\nEvidence", style="bold"), evidence]
    if finding.limitations:
        limitations = Table(box=None, show_header=False, pad_edge=False)
        limitations.add_column(style="dim", width=2)
        limitations.add_column(style="dim")
        for limitation in finding.limitations:
            limitations.add_row("!", limitation)
        body += [Text("\nLimitations", style="bold dim"), limitations]
    body += [Text(""), footer]

    return Panel(
        Group(*body),
        title=Text.assemble(
            (f"{finding.finding_id}  ", "dim"), (finding.title, "bold")
        ),
        subtitle=Text(finding.attack_class, style="dim"),
        border_style=SEVERITY_STYLE.get(finding.severity, "white").replace("bold ", ""),
    )


def _render_contributors(report) -> None:
    rows = [r for r in report.contributor_risk if r.get("flagged")]
    if not rows:
        return
    table = Table(title="Contributor risk (rate vs leave-one-out cohort baseline)")
    table.add_column("Contributor", style="bold")
    table.add_column("Attack class")
    table.add_column("Flagged", justify="right")
    table.add_column("Rate", justify="right")
    table.add_column("Cohort", justify="right")
    table.add_column("Ratio", justify="right")
    table.add_column("q-value", justify="right")
    table.add_column("Significant")
    for row in rows[:20]:
        significant = row.get("significant")
        table.add_row(
            row["contributor"],
            row["attack_class"],
            f"{row['flagged']}/{row['samples']}",
            f"{row['rate']:.1%}",
            f"{row['cohort_rate']:.2%}",
            "inf" if row["rate_ratio"] == float("inf") else f"{row['rate_ratio']:.1f}x",
            f"{row['q_value']:.2e}",
            Text("YES", style="bold red") if significant else Text("no", style="dim"),
        )
    console.print(table)


def render_coverage(coverage: CoverageStatement) -> None:
    table = Table(
        title="Coverage statement — what was assessed, and what was not",
        caption="A clean result covers only the SUPPORTED and PARTIAL rows.",
    )
    table.add_column("Attack class", style="bold")
    table.add_column("Coverage")
    table.add_column("Module", justify="right")
    table.add_column("Detector / reason")
    for entry in coverage.entries:
        table.add_row(
            entry.attack_class,
            Text(entry.coverage.value, style=COVERAGE_STYLE.get(entry.coverage, "white")),
            str(entry.owning_module),
            entry.detector or Text(entry.reason or "", style="dim"),
        )
    console.print(table)


def _render_provenance(report) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim", width=22)
    table.add_column()
    table.add_row("dataset digest", report.dataset["digest"])
    table.add_row("manifest id", report.dataset["manifest_id"])
    table.add_row("config hash", report.configuration["config_hash"])
    table.add_row("run id", report.run.run_id)
    table.add_row("seed", str(report.run.seed))
    table.add_row("software", f"cvtrust {report.run.software_version}")
    table.add_row("feature space", f"{report.feature_space['name']} v{report.feature_space['version']} "
                                   f"({report.feature_space['dim']}-d)")
    table.add_row("calibration", report.calibration["status"])
    table.add_row("samples/s", str(report.dataset["throughput_samples_per_s"]))
    console.print(Panel(table, title="Reproducibility", border_style="dim"))

    limitations = Table(box=None, show_header=False, pad_edge=False)
    limitations.add_column(style="dim", width=2)
    limitations.add_column(style="dim")
    for limitation in report.limitations:
        limitations.add_row("!", limitation)
    console.print(Panel(limitations, title="Limitations of this assessment", border_style="dim"))


def render_evaluation(report) -> None:
    for scenario in report.scenarios:
        table = Table(
            title=f"{scenario.scenario}  —  {scenario.total_samples} samples, "
                  f"{scenario.affected_samples} affected  ·  {scenario.overall_assessment}",
            caption=f"seed {scenario.seed} · dataset {scenario.dataset_digest[:12]} · "
                    f"{scenario.duration_ms} ms · "
                    f"{scenario.throughput_samples_per_s:.0f} samples/s",
        )
        table.add_column("Attack class", style="bold")
        table.add_column("Cov")
        table.add_column("P", justify="right")
        table.add_column("R", justify="right")
        table.add_column("F1", justify="right")
        table.add_column("P(actionable)", justify="right")
        table.add_column("FPR clean", justify="right")
        table.add_column("AUROC", justify="right")
        table.add_column("TP/FP/FN", justify="right")
        for metric in scenario.metrics:
            if metric.population["positives"] == 0 and metric.population["predicted"] == 0:
                continue
            table.add_row(
                metric.attack_class,
                Text(
                    (metric.coverage or "-")[:4],
                    style=COVERAGE_STYLE.get(Coverage(metric.coverage), "white")
                    if metric.coverage else "white",
                ),
                f"{metric.precision:.3f}",
                f"{metric.recall:.3f}",
                f"{metric.f1:.3f}",
                "n/a" if metric.precision_actionable is None
                else f"{metric.precision_actionable:.3f}",
                f"{metric.fpr_clean:.4f}",
                "-" if metric.auroc is None else f"{metric.auroc:.3f}",
                f"{metric.true_positives}/{metric.false_positives}/{metric.false_negatives}",
            )
        console.print(table)
    console.print(
        Panel(
            Text(report.evaluation_population, style="dim"),
            title="Evaluation population",
            border_style="dim",
        )
    )


def render_markdown(report) -> str:
    """Markdown rendering of the same report object, for archival and review."""
    lines: list[str] = [
        f"# Dataset Assurance Report — {report.report_id}",
        "",
        f"**Overall assessment: {report.summary.overall}**",
        "",
        report.summary.rationale,
        "",
        "## Provenance",
        "",
        f"| field | value |",
        f"|---|---|",
        f"| dataset digest | `{report.dataset['digest']}` |",
        f"| manifest id | `{report.dataset['manifest_id']}` |",
        f"| config hash | `{report.configuration['config_hash']}` |",
        f"| run id | `{report.run.run_id}` |",
        f"| seed | {report.run.seed} |",
        f"| software | cvtrust {report.run.software_version} |",
        f"| feature space | {report.feature_space['name']} v{report.feature_space['version']} |",
        f"| calibration | {report.calibration['status']} |",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines += ["No findings within the declared coverage.", ""]
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

    lines += ["## Coverage", "", "| attack class | coverage | module | detector / reason |", "|---|---|---|---|"]
    for entry in report.coverage.entries:
        lines.append(
            f"| `{entry.attack_class}` | {entry.coverage.value} | {entry.owning_module} | "
            f"{entry.detector or (entry.reason or '')} |"
        )
    lines += ["", "## Limitations of this assessment", ""]
    lines += [f"- {limitation}" for limitation in report.limitations]
    return "\n".join(lines) + "\n"
