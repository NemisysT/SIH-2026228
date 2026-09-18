"""Human-readable rendering of the provenance verification report.

Generated *from* the report object, never assembled separately, so the console
view and the JSON cannot drift apart.  The order answers the questions the
module brief asks a provenance report to answer, in the order an analyst asks
them:

    What was verified?  What failed?  Why?  Which artifact?  Which key?
    Is that key trusted?  Was there a replay?  What is the chain status?
    What are the limitations?

Deliberately absent: any aggregate percentage.  A "97% integrity" line over
forty records would be the single most misleading thing this report could print.
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.evidence import Finding
from ..provenance.verify import CheckOutcome
from .provenance_report import ProvenanceReport
from .render import BASIS_NOTE, DISPOSITION_STYLE, SEVERITY_STYLE, render_coverage

console = Console()

OVERALL_STYLE = {
    "PROVENANCE COMPROMISED": "bold white on red",
    "PROVENANCE UNVERIFIED": "bold red",
    "PROVENANCE VERIFIED WITH FINDINGS": "bold yellow",
    "PROVENANCE VERIFIED — PARTIAL COVERAGE": "bold yellow",
    "PROVENANCE VERIFIED": "bold green",
    "NO RECORDS": "dim",
}

OUTCOME_STYLE = {
    CheckOutcome.PASS.value: "green",
    CheckOutcome.FAIL.value: "bold red",
    CheckOutcome.NOT_CHECKED.value: "yellow",
    CheckOutcome.NOT_APPLICABLE.value: "dim",
    CheckOutcome.OBSERVED.value: "cyan",
}

CHAIN_STYLE = {
    "INTACT": "green",
    "BROKEN": "bold red",
    "EMPTY": "dim",
}

TRUNCATION_STYLE = {
    "VERIFIED_COMPLETE": "green",
    "TRUNCATION_DETECTED": "bold red",
    "ANCHOR_MISMATCH": "bold red",
    # Not red: a log that has grown past its anchor is an appended log, not an
    # attack. Yellow says "the newer entries are unattested", which is the
    # actionable part.
    "ANCHOR_STALE": "yellow",
    "FRONT_TRUNCATION_DETECTED": "bold red",
    "NOT_DETECTABLE": "yellow",
}

#: Checks whose names are not self-explanatory to someone who has not read the
#: source.  Printed beside the tally so the matrix is readable on its own.
CHECK_GLOSS: dict[str, str] = {
    "schema_supported": "record schema is implemented by this build",
    "record_id_matches_content": "the id is the content digest",
    "preprocessing_digest_self_consistent": "digest hashes the inline config",
    "inference_config_digest_self_consistent": "digest hashes the inline config",
    "output_digest_self_consistent": "digest hashes the inline output",
    "required_fields_present": "nonce, timestamp and log id are present",
    "timestamp_present": "a claim by the producer, never a proof of time",
    "nonce_present": "distinguishes repeats; does not prevent replay",
    "signature_valid": "Ed25519 over the canonical bytes",
    "key_known": "the signing key is in the trust store",
    "key_trusted": "and the operator trusts it",
    "signed_before_revocation": "self-asserted, reported not judged",
    "key_within_validity_window": "rotation window, under the stated policy",
    "key_purpose_permitted": "the key is authorised for this use",
    "input_digest_match": "vs the input artifact held independently",
    "normalized_input_digest_match": "vs the preprocessed tensor",
    "model_digest_match": "vs the model the analyst assured",
    "model_graph_digest_match": "vs the assured architecture",
    "model_parameter_digest_match": "vs the assured weights",
    "model_id_match": "vs the assured model id",
    "preprocessing_digest_match": "vs the declared preprocessing",
    "inference_config_digest_match": "vs the declared inference config",
    "output_digest_match": "vs the output held independently",
    "log_id_match": "vs the expected log",
    "replay_detected": "seen before by the local replay database",
    "previous_record_valid": "hash-chain linkage to the predecessor",
    "sequence_valid": "contiguous sequence from genesis",
}


def render_provenance_report(
    report: ProvenanceReport, *, full: bool = False, max_records: int = 15
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
            title="[bold]PIPELINE ASSURANCE — INFERENCE PROVENANCE[/bold]",
            subtitle=f"report {report.report_id} · run {report.run.run_id}",
            border_style="blue",
        )
    )

    _render_cryptographic(report)
    _render_chain(report)
    _render_matrix(report)
    _render_records(report, full=full, max_records=max_records)
    _render_findings(report, full=full)
    render_coverage(report.coverage)
    _render_provenance_footer(report)


def _render_cryptographic(report: ProvenanceReport) -> None:
    crypto = report.cryptographic
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="bold", width=24)
    table.add_column()

    table.add_row("Record schema", crypto.record_schema_version)
    table.add_row("Hash", crypto.hash_algorithm)
    table.add_row("Signature", crypto.signature_algorithm)
    table.add_row("Validity policy", crypto.validity_policy)
    table.add_row(
        "Trust store",
        Text(
            f"{crypto.trusted_key_count} trusted, {crypto.revoked_key_count} revoked "
            f"(digest {(crypto.trust_store_digest or '')[:16]}…)",
            style="green" if crypto.trusted_key_count else "yellow",
        )
        if crypto.trust_store_supplied
        else Text(
            "NOT SUPPLIED — every key is UNKNOWN and authenticity was not assessed",
            style="bold yellow",
        ),
    )
    table.add_row(
        "Replay database",
        Text(f"{crypto.replay_observations} prior observation(s)", style="green")
        if crypto.replay_database_supplied
        else Text(
            "NOT SUPPLIED — replay was not assessed. A valid signature does not "
            "establish that an inference happened once",
            style="bold yellow",
        ),
    )
    table.add_row(
        "Log anchor",
        Text("supplied — tail truncation is assessable", style="green")
        if crypto.anchor_supplied
        else Text(
            "NOT SUPPLIED — tail truncation is NOT DETECTABLE. A truncated chain "
            "is internally perfect",
            style="bold yellow",
        ),
    )
    table.add_row(
        "Expectations",
        Text(crypto.expectation_source or "supplied", style="green")
        if crypto.expectations_supplied
        else Text(
            "NOT SUPPLIED — only internal consistency and signatures were "
            "checked; no binding was corroborated against an artifact",
            style="bold yellow",
        ),
    )
    console.print(Panel(table, title="Cryptographic basis", border_style="dim"))


def _render_chain(report: ProvenanceReport) -> None:
    chain = report.chain
    status = str(chain.get("status", "EMPTY"))
    truncation = str(chain.get("truncation_status", "NOT_DETECTABLE"))

    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="bold", width=24)
    table.add_column()
    table.add_row("Linkage", Text(status, style=CHAIN_STYLE.get(status, "white")))
    table.add_row(
        "Completeness",
        Text(truncation, style=TRUNCATION_STYLE.get(truncation, "white")),
    )
    table.add_row("Entries", str(chain.get("entry_count", 0)))
    table.add_row("Head digest", str(chain.get("head_entry_digest") or "—")[:32] + "…")
    if chain.get("first_break_position") is not None:
        table.add_row(
            "First break",
            Text(f"position {chain['first_break_position']}", style="bold red"),
        )
    table.add_row("", Text(str(chain.get("detail", "")), style="dim"))
    table.add_row("", Text(str(chain.get("truncation_detail", "")), style="dim"))

    console.print(
        Panel(
            table,
            title="Chain integrity — a local hash-linked audit log, not a blockchain",
            border_style="dim",
        )
    )

    guarantees = chain.get("guarantees", {})
    if guarantees:
        detect = Table(box=None, show_header=True, pad_edge=False)
        detect.add_column("attack", style="bold", width=24)
        detect.add_column("this chain")
        for name, verdict in guarantees.items():
            style = "green" if verdict.startswith("DETECTED") else "yellow"
            detect.add_row(name.replace("_", " "), Text(verdict, style=style))
        console.print(Panel(detect, title="What the chain establishes", border_style="dim"))


def _render_matrix(report: ProvenanceReport) -> None:
    matrix = report.matrix
    table = Table(box=None, pad_edge=False)
    table.add_column("check", style="bold", width=36)
    table.add_column("result")
    table.add_column("what it means", style="dim")

    for name, counts in matrix.checks.items():
        parts = [
            Text(f"{outcome} {count}", style=OUTCOME_STYLE.get(outcome, "white"))
            for outcome, count in counts.items()
            if count
        ]
        line = Text()
        for index, part in enumerate(parts):
            if index:
                line.append("  ")
            line.append_text(part)
        table.add_row(name, line, CHECK_GLOSS.get(name, ""))

    console.print(
        Panel(
            table,
            title=f"Verification matrix — {matrix.total_records} record(s)",
            border_style="dim",
        )
    )
    blind = matrix.never_checked()
    if blind:
        console.print(
            Panel(
                Text(
                    "These checks produced neither a pass nor a fail on any "
                    "record, so they contribute nothing to this result:\n  "
                    + "\n  ".join(blind),
                    style="yellow",
                ),
                title="Not assessed in this run",
                border_style="yellow",
            )
        )


def _render_records(
    report: ProvenanceReport, *, full: bool, max_records: int
) -> None:
    records = report.records
    if not records:
        return
    shown = records if full else records[:max_records]

    table = Table(box=None, pad_edge=False)
    table.add_column("#", width=4)
    table.add_column("record", width=20)
    table.add_column("key", width=18)
    table.add_column("output", width=24)
    table.add_column("replay", width=18)
    table.add_column("result")

    for record in shown:
        if record.valid:
            result = Text("VALID", style="green")
        elif record.cryptographically_intact:
            result = Text(", ".join(record.failures), style="yellow")
        else:
            result = Text(", ".join(record.failures), style="bold red")
        key_style = {
            "TRUSTED": "green", "REVOKED": "bold red", "UNKNOWN": "yellow",
        }.get(record.key_status, "white")
        table.add_row(
            str(record.position),
            record.record_id or "—",
            Text(
                f"{(record.signing_key_id or '—')[:10]}… {record.key_status}",
                style=key_style,
            ),
            record.output_summary or "—",
            Text(
                record.replay_verdict,
                style="bold red"
                if record.replay_verdict
                in ("REPLAY_EXACT", "NONCE_REUSE", "SEQUENCE_COLLISION")
                else "cyan" if record.replay_verdict == "DUPLICATE_SUBJECT"
                else "dim",
            ),
            result,
        )

    title = f"Records — {report.summary.records_valid} of {report.summary.records_total} verify"
    if len(shown) < len(records):
        title += f" (showing {len(shown)}; --full for all)"
    console.print(Panel(table, title=title, border_style="dim"))


def _render_findings(report: ProvenanceReport, *, full: bool) -> None:
    findings = report.findings
    if not findings:
        console.print(
            Panel(
                Text(
                    "No integrity findings. This is a statement about the "
                    "records' integrity and the checks that actually ran — see "
                    "the matrix above — and not about the inferences themselves.",
                    style="green",
                ),
                title="Findings",
                border_style="green",
            )
        )
        return

    limit = len(findings) if full else min(len(findings), 10)
    for finding in findings[:limit]:
        console.print(_finding_panel(finding))
    if limit < len(findings):
        console.print(
            Text(f"  … {len(findings) - limit} further finding(s); --full to show all",
                 style="dim")
        )


def _finding_panel(finding: Finding) -> Panel:
    body = Table(box=None, show_header=False, pad_edge=False)
    body.add_column(style="bold", width=14)
    body.add_column()

    body.add_row("Asset", f"{finding.asset.type.value}:{finding.asset.id}")
    body.add_row("Attack class", finding.attack_class)
    body.add_row(
        "Confidence",
        Text(
            f"{finding.confidence:.2f} ({BASIS_NOTE[finding.confidence_basis]})",
            style="green",
        ),
    )
    body.add_row(
        "Disposition",
        Text(
            f"{finding.disposition.value} (rule {finding.disposition_rule})",
            style=DISPOSITION_STYLE.get(finding.disposition, "white"),
        ),
    )
    body.add_row("", Text(""))
    for item in finding.evidence:
        body.add_row("Evidence", Text(item.statement, style="dim"))
    for limitation in finding.limitations:
        body.add_row("Limitation", Text(limitation, style="yellow"))

    return Panel(
        body,
        title=Text(
            f"{finding.severity.value} · {finding.title}",
            style=SEVERITY_STYLE.get(finding.severity, "white"),
        ),
        subtitle=finding.finding_id,
        border_style=SEVERITY_STYLE.get(finding.severity, "white").split()[-1],
    )


def _render_provenance_footer(report: ProvenanceReport) -> None:
    table = Table(box=None, show_header=False, pad_edge=False)
    table.add_column(style="bold", width=20)
    table.add_column()
    table.add_row("Log", str(report.log.get("path") or report.log.get("log_id")))
    table.add_row("Software", report.run.software_version)
    table.add_row("Config hash", report.run.config_hash[:16] + "…")
    table.add_row("Report digest", report.stable_digest()[:16] + "…")
    console.print(Panel(table, title="Provenance of this report", border_style="dim"))

    console.print(
        Panel(
            Text("\n".join(f"• {line}" for line in report.limitations), style="dim"),
            title="Limitations of this verification",
            border_style="dim",
        )
    )


def render_provenance_markdown(report: ProvenanceReport) -> str:
    """Markdown rendering of the same report object, for archival and review."""
    crypto = report.cryptographic
    chain = report.chain
    lines: list[str] = [
        f"# Inference Provenance Report — {report.report_id}",
        "",
        f"**{report.summary.overall}**",
        "",
        report.summary.rationale,
        "",
        "## What was verified",
        "",
        "| field | value |",
        "|---|---|",
        f"| log | `{report.log.get('log_id')}` |",
        f"| records | {report.summary.records_total} "
        f"({report.summary.records_valid} verify) |",
        f"| malformed lines | {report.summary.malformed_lines} |",
        f"| record schema | {crypto.record_schema_version} |",
        f"| hash | {crypto.hash_algorithm} |",
        f"| signature | {crypto.signature_algorithm} |",
        f"| canonicalisation | {crypto.canonicalisation} |",
        f"| validity policy | `{crypto.validity_policy}` |",
        f"| trust store | {'supplied — ' if crypto.trust_store_supplied else '**NOT SUPPLIED**'}"
        f"{f'{crypto.trusted_key_count} trusted, {crypto.revoked_key_count} revoked' if crypto.trust_store_supplied else ''} |",
        f"| replay database | {'supplied' if crypto.replay_database_supplied else '**NOT SUPPLIED** — replay not assessed'} |",
        f"| log anchor | {'supplied' if crypto.anchor_supplied else '**NOT SUPPLIED** — tail truncation NOT DETECTABLE'} |",
        f"| expectations | {crypto.expectation_source or ('supplied' if crypto.expectations_supplied else '**NOT SUPPLIED**')} |",
        "",
        "## Chain status",
        "",
        f"- **Linkage**: `{chain.get('status')}` — {chain.get('detail')}",
        f"- **Completeness**: `{chain.get('truncation_status')}` — "
        f"{chain.get('truncation_detail')}",
        "",
        "| attack | this chain |",
        "|---|---|",
    ]
    for name, verdict in chain.get("guarantees", {}).items():
        lines.append(f"| {name.replace('_', ' ')} | {verdict} |")

    lines += [
        "",
        "## Verification matrix",
        "",
        "| check | outcomes | what it means |",
        "|---|---|---|",
    ]
    for name, counts in report.matrix.checks.items():
        tally = ", ".join(f"{outcome} {count}" for outcome, count in counts.items() if count)
        lines.append(f"| `{name}` | {tally} | {CHECK_GLOSS.get(name, '')} |")

    blind = report.matrix.never_checked()
    if blind:
        lines += [
            "",
            "**Not assessed in this run** (neither a pass nor a fail on any record):",
            "",
        ]
        lines += [f"- `{name}`" for name in blind]

    lines += [
        "",
        "## Records",
        "",
        "| # | record | signing key | key status | replay | result |",
        "|---|---|---|---|---|---|",
    ]
    for record in report.records:
        lines.append(
            f"| {record.position} | `{record.record_id}` | "
            f"`{(record.signing_key_id or '—')[:16]}` | {record.key_status} | "
            f"{record.replay_verdict} | {', '.join(record.failures)} |"
        )

    lines += ["", "## Findings", ""]
    if not report.findings:
        lines += [
            "No integrity findings within the checks that actually ran. See the "
            "matrix above for which checks those were.",
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
            f"({BASIS_NOTE[finding.confidence_basis]})",
            f"- **Recommended disposition**: **{finding.disposition.value}** "
            f"(rule `{finding.disposition_rule}`)",
            "",
            "**Why it failed**",
            "",
        ]
        lines += [f"- {item.statement}" for item in finding.evidence]
        if finding.assumptions:
            lines += ["", "**Assumptions**", ""]
            lines += [f"- {item}" for item in finding.assumptions]
        if finding.limitations:
            lines += ["", "**Limitations**", ""]
            lines += [f"- {item}" for item in finding.limitations]
        lines.append("")

    lines += [
        "## Coverage", "",
        "| attack class | coverage | module | detector / reason |",
        "|---|---|---|---|",
    ]
    for entry in report.coverage.entries:
        lines.append(
            f"| `{entry.attack_class}` | {entry.coverage.value} | "
            f"{entry.owning_module} | {entry.detector or (entry.reason or '')} |"
        )

    lines += ["", "## Limitations of this verification", ""]
    lines += [f"- {limitation}" for limitation in report.limitations]
    return "\n".join(lines) + "\n"


def render_provenance_evaluation(report) -> None:
    """Console rendering of the provenance lab evaluation."""
    table = Table(box=None, pad_edge=False)
    table.add_column("scenario", style="bold", width=30)
    table.add_column("classes", width=34)
    table.add_column("records", width=8)
    table.add_column("chain", width=9)
    table.add_column("result")

    for result in report.results:
        table.add_row(
            result.scenario,
            ", ".join(result.attack_classes),
            str(result.record_count_observed),
            Text(
                result.chain_status_observed,
                style=CHAIN_STYLE.get(result.chain_status_observed, "white"),
            ),
            Text("as expected", style="green")
            if result.passed
            else Text("; ".join(result.mismatches)[:80], style="bold red"),
        )

    console.print(
        Panel(
            table,
            title=f"Provenance lab — {report.scenarios_passed}/"
            f"{report.scenarios_total} scenarios reproduce exactly",
            border_style="green" if report.all_passed else "red",
        )
    )
    console.print(
        Panel(
            Text(report.scoring + "\n\n" + report.calibration, style="dim"),
            title="Scoring",
            border_style="dim",
        )
    )


__all__ = [
    "render_provenance_report", "render_provenance_markdown",
    "render_provenance_evaluation",
]
