"""Analyst-facing rendering of the pipeline assurance report.

Generated *from* the report object, never assembled separately, so the console
view and the JSON cannot drift apart.

The screen answers the brief's §30 questions in order, and the order is the
argument:

    What was assessed?        (scopes, with the unassessed ones visible)
    What was found?           (per scope, kept apart)
    What evidence supports it? (lineage, rule by rule)
    What was NOT assessed?     (its own panel, not a footnote)
    What is the confidence basis?
    What is the operational context?
    Is there integrity failure? Is there a model/data anomaly? Is there shift?
    What disposition, and why? (the rule, by id)
    What are the limitations?

Deliberately absent: a gauge, a dial, a percentage, and any number not
traceable to an observation printed beside it.
"""

from __future__ import annotations

from typing import Any

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..assurance.policy import AssuranceDisposition
from ..core.evidence import ConfidenceBasis, Coverage, Severity
from ..shift.characterize import ShiftVerdict
from .render import COVERAGE_STYLE, SEVERITY_STYLE

console = Console()

DISPOSITION_STYLE: dict[str, str] = {
    "QUARANTINE": "bold white on red",
    "REVIEW": "bold yellow",
    "NOT_ASSESSED": "bold magenta",
    "ACCEPT": "bold green",
}

VERDICT_STYLE: dict[str, str] = {
    ShiftVerdict.NO_SHIFT_DETECTED.value: "green",
    ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT.value: "cyan",
    ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED.value: "yellow",
    ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT.value: "bold yellow",
    ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT.value: "yellow",
    ShiftVerdict.INSUFFICIENT_SAMPLE.value: "magenta",
    ShiftVerdict.NOT_ASSESSED.value: "magenta",
}

BASIS_NOTE: dict[str, str] = {
    ConfidenceBasis.DETERMINISTIC.value: "verified fact",
    ConfidenceBasis.STATISTICAL.value: "hypothesis test",
    ConfidenceBasis.CALIBRATED.value: "measured precision",
    ConfidenceBasis.HEURISTIC_UNCALIBRATED.value: "uncalibrated prior",
}


def render_assurance_report(report, *, full: bool = False) -> None:
    decision = report.decision
    console.print()
    console.print(
        Panel(
            Group(
                Text(
                    decision.disposition.value,
                    style=DISPOSITION_STYLE.get(decision.disposition.value, "bold"),
                ),
                Text(decision.summary, style="dim"),
                Text(""),
                Text(decision.rationale),
            ),
            title="[bold]PIPELINE ASSURANCE — CROSS-MODULE[/bold]",
            subtitle=f"decision {decision.decision_id} · report {report.report_id} · "
            f"policy v{decision.policy_version}",
            border_style="blue",
        )
    )

    _render_scopes(report)
    _render_shift(report)
    _render_evidence(report)
    _render_lineage(report, full=full)
    _render_unassessed(report)
    _render_conflicts(report)
    _render_capabilities(report)
    _render_reproducibility(report)


def _render_scopes(report) -> None:
    """The four scopes as four rows.  Never merged into one status."""
    table = Table(
        title="Assurance scopes — kept separate on purpose",
        caption="A model finding and a provenance finding are different facts "
        "about different properties. They are never combined into one number.",
    )
    table.add_column("Scope", style="bold")
    table.add_column("Disposition")
    table.add_column("Rule")
    table.add_column("Findings", justify="right")
    table.add_column("Statement")
    for scope in report.scopes():
        table.add_row(
            scope.scope,
            Text(scope.disposition, style=DISPOSITION_STYLE.get(scope.disposition, "white")),
            scope.governing_rule or "-",
            str(scope.findings),
            Text(scope.statement, style="" if scope.assessed else "dim"),
        )
    console.print(table)


def _render_shift(report) -> None:
    shift = report.distribution_shift
    if shift is None:
        console.print(
            Panel(
                Text(
                    "No reference population was supplied, so population-level "
                    "distribution shift was NOT assessed. This is a gap, not a "
                    "stable population.",
                    style="magenta",
                ),
                title="Distribution shift",
                border_style="magenta",
            )
        )
        return

    header = Table(box=None, show_header=False, pad_edge=False)
    header.add_column(style="bold", width=22)
    header.add_column()
    header.add_row(
        "Verdict",
        Text(shift.verdict.value, style=VERDICT_STYLE.get(shift.verdict.value, "white")),
    )
    header.add_row("Reference", f"{shift.reference.get('reference_id')} "
                                f"({shift.reference.get('mode')}, "
                                f"{shift.reference.get('sample_count')} samples, "
                                f"trust {shift.reference.get('trust')})")
    header.add_row("Current", f"{shift.current.get('sample_count')} samples")
    if shift.context is not None:
        declared = shift.context.delta
        header.add_row(
            "Declared change",
            ", ".join(
                f"{k}: {declared.reference.get(k, '-')} → {declared.current.get(k, '-')}"
                for k in (*declared.changed, *declared.declared_only_on_one_side)
            )
            or Text("none declared", style="dim"),
        )
        header.add_row(
            "Views that moved",
            ", ".join(shift.context.moved_blocks) or Text("none", style="dim"),
        )
        header.add_row(
            "Unexplained",
            Text(", ".join(shift.context.unexplained_blocks), style="yellow")
            if shift.context.unexplained_blocks
            else Text("none", style="green"),
        )

    metrics = Table(box=None)
    metrics.add_column("Metric", style="bold")
    metrics.add_column("Status")
    metrics.add_column("Statistic", justify="right")
    metrics.add_column("p", justify="right")
    metrics.add_column("Reads")
    for result in shift.metrics:
        metrics.add_row(
            result.metric,
            Text(
                result.status.value,
                style="green" if result.status.value == "ASSESSED" else "magenta",
            ),
            "-" if result.statistic is None else f"{result.statistic:.4g}",
            "-" if result.p_value is None else f"{result.p_value:.4g}",
            Text(
                result.interpretation
                if result.status.value == "ASSESSED"
                else (result.reason or result.interpretation),
                style="" if result.status.value == "ASSESSED" else "dim",
            ),
        )

    console.print(
        Panel(
            Group(header, Text(""), metrics, Text(""), Text(shift.statement, style="italic")),
            title="Distribution shift — population level, not per sample",
            subtitle=Text(shift.reference.get("caveat", ""), style="dim"),
            border_style="blue",
        )
    )


def _render_evidence(report) -> None:
    graph = report.evidence
    if not graph.groups:
        console.print(
            Panel(
                Text(
                    "No findings were supplied by any module. This is a "
                    "statement about the assessments that ran, listed above, "
                    "and about nothing else.",
                    style="green",
                ),
                title="Evidence",
                border_style="green",
            )
        )
        return

    table = Table(
        title="Evidence families — one phenomenon per row, never one per finding",
        caption="A family contributes at most one unit of independent support. "
        "Confounded evidence is kept and reported; it does not corroborate.",
    )
    table.add_column("Family", style="bold")
    table.add_column("Class")
    table.add_column("Findings", justify="right")
    table.add_column("Detectors", justify="right")
    table.add_column("Max severity")
    table.add_column("Bases")
    table.add_column("Independent")
    for group in graph.groups:
        table.add_row(
            group.family.value,
            group.evidence_class.value,
            str(len(group.evidence_ids)),
            str(len(group.detectors)),
            Text(
                group.max_severity.value,
                style=SEVERITY_STYLE.get(Severity(group.max_severity), "white"),
            ),
            ", ".join(BASIS_NOTE.get(b, b) for b in group.bases),
            Text("yes", style="green")
            if group.counts_as_independent_support()
            else Text(
                f"no — confounded by {', '.join(f.value for f in group.active_confounders)}"
                if group.confounded
                else "no — below the corroboration floor",
                style="dim",
            ),
        )
    console.print(table)


def _render_lineage(report, *, full: bool) -> None:
    """decision → rule → finding → detector, as rows an analyst can follow."""
    nodes = report.decision.lineage
    if not nodes:
        return
    shown = nodes if full else nodes[:20]
    table = Table(
        title="Decision lineage — why this disposition, one hop at a time",
        caption="Every row is a rule that fired and the evidence that made it "
        "fire. An analyst answers 'why?' without reading source code.",
    )
    table.add_column("Rule", style="bold")
    table.add_column("Scope")
    table.add_column("→")
    table.add_column("Finding")
    table.add_column("From")
    table.add_column("Detail")
    for node in shown:
        table.add_row(
            node.rule_id,
            node.scope.value,
            Text(
                node.disposition.value,
                style=DISPOSITION_STYLE.get(node.disposition.value, "white"),
            ),
            node.finding_id or Text("—", style="dim"),
            f"M{node.source_module} {node.source_detector}"
            if node.source_module
            else Text("(no finding required)", style="dim"),
            node.detail,
        )
    console.print(table)
    if len(shown) < len(nodes):
        console.print(
            Text(
                f"  … {len(nodes) - len(shown)} further lineage row(s); use --full "
                "or read the JSON report.",
                style="dim",
            )
        )


def _render_unassessed(report) -> None:
    areas = report.decision.unassessed_areas
    if not areas:
        console.print(
            Panel(
                Text(
                    "Every scope had an input and every attack class in the "
                    "registry was reported on.",
                    style="green",
                ),
                title="What was NOT assessed",
                border_style="green",
            )
        )
        return
    table = Table(box=None)
    table.add_column("", style="dim", width=2)
    table.add_column("Area", style="bold")
    table.add_column("Kind", style="dim")
    table.add_column("Reason")
    table.add_column("Remedy", style="dim")
    for area in areas:
        table.add_row("!", area.area, area.kind, area.reason, area.remedy or "-")
    console.print(
        Panel(
            table,
            title="What was NOT assessed — open questions, not clean results",
            subtitle=Text(
                "A pipeline with major unassessed classes is not equivalent to a "
                "comprehensively assessed clean one.",
                style="dim",
            ),
            border_style="magenta",
        )
    )


def _render_conflicts(report) -> None:
    conflicts = report.decision.conflicts
    contradicting = report.decision.contradicting_evidence
    if not conflicts and not contradicting:
        return
    body: list[Any] = []
    for statement in conflicts:
        body.append(Text(f"• {statement}"))
    if contradicting:
        body.append(Text(""))
        body.append(
            Text(
                "Evidence marked confounded — kept and reported, but not counted "
                "as independent corroboration:",
                style="bold",
            )
        )
        for reference in contradicting[:10]:
            body.append(
                Text(
                    f"  • {reference.finding_id} ({reference.attack_class}, "
                    f"{reference.severity.value}) — confounded by "
                    f"{', '.join(reference.confounded_by)}",
                    style="dim",
                )
            )
    console.print(
        Panel(
            Group(*body),
            title="Conflicting and confounded evidence — preserved, not resolved",
            border_style="yellow",
        )
    )


def _render_capabilities(report) -> None:
    table = Table(
        title="Module 4 capability coverage",
        caption="The attack-class coverage statement is in the JSON report; this "
        "table covers the capabilities that are not attack classes.",
    )
    table.add_column("Capability", style="bold")
    table.add_column("Coverage")
    table.add_column("Reason / limitation")
    for entry in report.capabilities.entries:
        limitation = "; ".join(entry.limitations)
        table.add_row(
            entry.capability,
            Text(entry.coverage.value, style=COVERAGE_STYLE.get(Coverage(entry.coverage), "white")),
            (entry.reason or "") + (f"  [{limitation}]" if limitation else ""),
        )
    console.print(table)


def _render_reproducibility(report) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="dim", width=22)
    table.add_column()
    table.add_row("report id", report.report_id)
    table.add_row("decision id", report.decision.decision_id)
    table.add_row("run id", report.run.run_id)
    table.add_row("policy version", report.decision.policy_version)
    table.add_row("config hash", report.configuration["config_hash"])
    table.add_row("seed", str(report.run.seed))
    table.add_row("software", f"cvtrust {report.run.software_version}")
    for name, section in sorted(report.inputs.items()):
        if isinstance(section, dict) and section.get("report_id"):
            table.add_row(f"{name} report", str(section["report_id"]))
    console.print(Panel(table, title="Reproducibility", border_style="dim"))

    confidence = report.decision.confidence_summary
    bases = Table(box=None)
    bases.add_column("Confidence basis", style="bold")
    bases.add_column("Evidence", justify="right")
    bases.add_column("Supporting", justify="right")
    bases.add_column("Range", justify="right")
    for basis, detail in sorted(confidence.get("by_basis", {}).items()):
        bases.add_row(
            f"{basis} ({BASIS_NOTE.get(basis, '')})",
            str(detail["count"]),
            str(detail["supporting"]),
            f"{detail['min_confidence']:.2f}–{detail['max_confidence']:.2f}",
        )
    if confidence.get("by_basis"):
        console.print(
            Panel(
                Group(bases, Text(""), Text(confidence["note"], style="dim")),
                title="Confidence basis — reported per basis, never pooled",
                border_style="dim",
            )
        )

    limitations = Table(box=None, show_header=False, pad_edge=False)
    limitations.add_column(style="dim", width=2)
    limitations.add_column(style="dim")
    for limitation in report.limitations:
        limitations.add_row("!", limitation)
    console.print(
        Panel(limitations, title="Limitations of this assessment", border_style="dim")
    )


def render_assurance_markdown(report) -> str:
    """Markdown rendering of the same report object, for archival and review."""
    decision = report.decision
    lines: list[str] = [
        f"# Pipeline Assurance Report — {report.report_id}",
        "",
        f"**Disposition: {decision.disposition.value}**",
        "",
        decision.summary,
        "",
        decision.rationale,
        "",
        "## Assurance scopes",
        "",
        "| scope | disposition | rule | findings | statement |",
        "|---|---|---|---:|---|",
    ]
    for scope in report.scopes():
        lines.append(
            f"| {scope.scope} | **{scope.disposition}** | "
            f"`{scope.governing_rule or '-'}` | {scope.findings} | {scope.statement} |"
        )

    shift = report.distribution_shift
    lines += ["", "## Distribution shift", ""]
    if shift is None:
        lines += [
            "No reference population was supplied, so population-level "
            "distribution shift was **NOT assessed**. This is a gap, not a "
            "stable population.",
            "",
        ]
    else:
        lines += [
            f"**Verdict: {shift.verdict.value}**",
            "",
            shift.statement,
            "",
            f"Reference: `{shift.reference.get('reference_id')}` "
            f"({shift.reference.get('mode')}, "
            f"{shift.reference.get('sample_count')} samples, trust "
            f"{shift.reference.get('trust')})",
            "",
            f"> {shift.reference.get('caveat', '')}",
            "",
            "| metric | status | statistic | p | reads |",
            "|---|---|---:|---:|---|",
        ]
        for result in shift.metrics:
            lines.append(
                f"| `{result.metric}` | {result.status.value} | "
                f"{'-' if result.statistic is None else f'{result.statistic:.4g}'} | "
                f"{'-' if result.p_value is None else f'{result.p_value:.4g}'} | "
                f"{result.interpretation if result.status.value == 'ASSESSED' else (result.reason or '')} |"
            )

    lines += [
        "",
        "## Evidence families",
        "",
        "| family | class | findings | detectors | max severity | independent |",
        "|---|---|---:|---:|---|---|",
    ]
    for group in report.evidence.groups:
        independent = (
            "yes"
            if group.counts_as_independent_support()
            else (
                f"no — confounded by {', '.join(f.value for f in group.active_confounders)}"
                if group.confounded
                else "no — below the corroboration floor"
            )
        )
        lines.append(
            f"| `{group.family.value}` | {group.evidence_class.value} | "
            f"{len(group.evidence_ids)} | {len(group.detectors)} | "
            f"{group.max_severity.value} | {independent} |"
        )

    lines += [
        "",
        "## Decision lineage",
        "",
        "| rule | scope | disposition | finding | from | detail |",
        "|---|---|---|---|---|---|",
    ]
    for node in decision.lineage:
        lines.append(
            f"| `{node.rule_id}` | {node.scope.value} | {node.disposition.value} | "
            f"{f'`{node.finding_id}`' if node.finding_id else '—'} | "
            f"{f'M{node.source_module} {node.source_detector}' if node.source_module else '—'} | "
            f"{node.detail} |"
        )

    lines += ["", "## What was NOT assessed", ""]
    if not decision.unassessed_areas:
        lines.append("Every scope had an input and every attack class was reported on.")
    for area in decision.unassessed_areas:
        remedy = f" _Remedy: {area.remedy}_" if area.remedy else ""
        lines.append(f"- **{area.area}** ({area.kind}) — {area.reason}.{remedy}")

    if decision.conflicts:
        lines += ["", "## Conflicting evidence", ""]
        lines += [f"- {statement}" for statement in decision.conflicts]

    lines += ["", "## Policy", "", f"Policy version `{decision.policy_version}`.", ""]
    lines += [
        f"- {report.policy['combination']}",
        f"- {report.policy['counting_unit']}",
        f"- {report.policy['no_scoring']}",
        "",
        "| rule | scope | if | then | rationale |",
        "|---|---|---|---|---|",
    ]
    for rule in report.policy["rules"]:
        lines.append(
            f"| `{rule['id']}` | {rule['scope']} | {rule['if']} | "
            f"**{rule['then']}** | {rule['rationale']} |"
        )

    lines += ["", "## Limitations of this assessment", ""]
    lines += [f"- {limitation}" for limitation in report.limitations]
    return "\n".join(lines) + "\n"


__all__ = ["render_assurance_report", "render_assurance_markdown"]
