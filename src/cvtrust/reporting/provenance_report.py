"""The provenance verification report.

Structurally parallel to Modules 1 and 2 — same ``RunContext``, same ``Finding``
objects, same ``CoverageStatement``, same disposition machinery — with one
section neither of the others has, and one field neither of them has either.

The section is the **verification matrix**: a per-check tally across every
record, so an analyst can see at a glance that all forty records had a valid
signature and thirty-nine of them had a matching model digest.

The field is ``cryptographic_summary``, and what it deliberately excludes is a
score.  There is no ``integrity_score``, no ``trust_percentage`` and no
aggregate number of any kind in this schema.  Cryptographic verification is
deterministic: a record either verifies or it does not, and averaging forty
booleans produces a number whose only use is to make a failure look survivable.
The roll-up that does exist is a worst-case label with a named rationale,
exactly as in Modules 1 and 2.

The other invariant this file enforces is §27's: nothing here reads a Module 1
or Module 2 confidence, and nothing here emits one.  Provenance findings arrive
``DETERMINISTIC`` at confidence 1.0 and leave that way.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import digest_safe
from ..core.context import RunContext
from ..core.evidence import (
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    Disposition,
    Finding,
    Severity,
    utc_now_iso,
)
from ..core.hashing import sha256_canonical, short
from ..risk.coverage import CoverageStatement
from .report import DetectorReport, _strip_volatile

PROVENANCE_REPORT_SCHEMA_VERSION = "1.0"


class RecordSummary(BaseModel):
    """One row per record: what it was about, and how it verified."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    position: int | None
    record_id: str | None
    entry_digest: str | None
    sequence_number: int | None
    timestamp: str | None
    signing_key_id: str | None
    key_status: str
    failures: tuple[str, ...]
    replay_verdict: str
    input_digest: str | None
    model_id: str | None
    model_file_sha256: str | None
    output_summary: str | None
    valid: bool
    cryptographically_intact: bool


class VerificationMatrix(BaseModel):
    """Per-check tallies across the whole log.

    The point of the matrix is the same as Module 2's assessment matrix: a
    reader must be able to tell ``NOT_CHECKED`` from ``PASS``.  Forty records
    whose model digest was never corroborated is a very different log from forty
    whose model digest matched, and a single "39/40 valid" would report them
    identically.
    """

    model_config = ConfigDict(extra="forbid")

    total_records: int
    checks: dict[str, dict[str, int]] = Field(
        description="check name -> {PASS, FAIL, NOT_CHECKED, NOT_APPLICABLE, "
        "OBSERVED} counts."
    )

    def never_checked(self) -> list[str]:
        """Checks that ran on no record at all — the report's blind spots."""
        return sorted(
            name
            for name, counts in self.checks.items()
            if counts.get("PASS", 0) == 0 and counts.get("FAIL", 0) == 0
        )


class CryptographicSummary(BaseModel):
    """The primitives and parameters in force, recorded rather than assumed."""

    model_config = ConfigDict(extra="forbid")

    record_schema_version: str
    hash_algorithm: str
    signature_algorithm: str
    canonicalisation: str
    quantization_places: int
    validity_policy: str
    trust_store_supplied: bool
    trust_store_digest: str | None
    trusted_key_count: int
    revoked_key_count: int
    replay_database_supplied: bool
    replay_observations: int
    anchor_supplied: bool
    expectations_supplied: bool
    expectation_source: str | None


class ProvenanceAssessmentSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall: str
    rationale: str
    records_total: int
    records_valid: int
    records_cryptographically_intact: int
    records_failed: int
    malformed_lines: int
    findings_total: int
    by_severity: dict[str, int]
    by_disposition: dict[str, int]
    by_attack_class: dict[str, int]
    by_failure_code: dict[str, int]
    chain_status: str
    truncation_status: str
    replay_detected: int


class ProvenanceReport(BaseModel):
    """The machine-readable record of one provenance verification."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = PROVENANCE_REPORT_SCHEMA_VERSION
    evidence_schema_version: str = SCHEMA_VERSION
    report_id: str
    generated_at: str = Field(default_factory=utc_now_iso)
    module: str = "3: inference provenance and cryptographic integrity"

    run: RunContext
    log: dict[str, Any]
    cryptographic: CryptographicSummary
    configuration: dict[str, Any]
    disposition_policy: dict[str, Any]

    chain: dict[str, Any]
    matrix: VerificationMatrix
    records: list[RecordSummary]
    verifications: list[dict[str, Any]] = Field(
        default_factory=list,
        description="The full per-record check evidence. Large, and the reason "
        "an analyst can recompute any claim in this report.",
    )

    summary: ProvenanceAssessmentSummary
    findings: list[Finding]
    detectors: list[DetectorReport]
    coverage: CoverageStatement
    limitations: list[str]

    def stable_digest(self) -> str:
        return sha256_canonical(
            digest_safe(_strip_volatile(self.model_dump(mode="json")))
        )


#: Global limitations printed on every provenance report.  Properties of the
#: approach, not of any particular log.
PROVENANCE_GLOBAL_LIMITATIONS: tuple[str, ...] = (
    "This report is about the integrity of the *record* of an inference, not "
    "about the inference. A cryptographically perfect provenance chain over a "
    "backdoored model is entirely possible, and so is a forged record of a "
    "sound one. Module 2's assessment and this one are separate facts and are "
    "never combined into a single number.",
    "A valid signature establishes that the holder of the matching private key "
    "produced these bytes. It does not establish that the key is authorised: "
    "the public key travels inside the record, so anyone can produce a record "
    "that verifies. Authority comes from the trust store and nowhere else.",
    "The trust store is administrative and local. Its guarantee is only as "
    "strong as the channel through which each key was obtained; a store "
    "populated from the same source as the records establishes nothing.",
    "Timestamps are the producer's own clock. Signing one binds the claim, not "
    "the time: there is no timestamp authority in an air-gapped deployment, and "
    "a holder of a signing key controls the timestamp too.",
    "A nonce does not prevent replay. It makes two legitimately distinct "
    "inferences over the same input distinguishable; detecting a second "
    "presentation requires a local replay database, and a negative result is "
    "bounded by that database's retention.",
    "Tail truncation of a log is not detectable from the log itself: a "
    "truncated chain is internally perfect. It is assessed only against an "
    "anchor recorded out of band, and without one the outcome is reported as "
    "NOT_DETECTABLE rather than clean.",
    "Binding proves that the record describes these artifacts. It does not "
    "prove the inference was executed: a producer able to sign can sign a "
    "record for an inference it never ran. Detecting that requires trusted "
    "execution, which this build does not implement and does not claim.",
    "This software cannot protect a private key from a compromised signing "
    "host. An adversary with code execution as the signing user can read the "
    "key, or simply ask this software to sign.",
    "No distributed ledger is used, and none is needed: see ADR-009. This is a "
    "local cryptographically linked audit log with one writer, not a "
    "blockchain, and it makes no Byzantine-agreement claim.",
)


def build_matrix(verifications: list[Any]) -> VerificationMatrix:
    counts: dict[str, dict[str, int]] = {}
    for verification in verifications:
        for check in verification.checks:
            bucket = counts.setdefault(check.name, {})
            bucket[check.outcome.value] = bucket.get(check.outcome.value, 0) + 1
    return VerificationMatrix(
        total_records=len(verifications),
        checks={name: dict(sorted(v.items())) for name, v in sorted(counts.items())},
    )


def _overall(
    findings: list[Finding],
    *,
    records_total: int,
    records_failed: int,
    chain_intact: bool,
    chain_status: str,
    truncation_status: str,
    unassessed_classes: int,
) -> tuple[str, str]:
    """Worst-case roll-up by explicit rule.  Never an average.

    One forged record among a thousand valid ones is the case that matters, and
    a mean would report it as 99.9% healthy.
    """
    caveat = (
        " This covers the integrity of the records presented and says nothing "
        "about the quality of the inferences they describe."
    )
    quarantine = [f for f in findings if f.disposition is Disposition.QUARANTINE]
    if quarantine:
        return (
            "PROVENANCE COMPROMISED",
            f"{len(quarantine)} finding(s) meet the quarantine rule: the chain of "
            "custody for these inferences cannot be relied on." + caveat,
        )
    if not chain_intact:
        return (
            "PROVENANCE COMPROMISED",
            "the provenance chain does not verify, so the ordering and "
            "completeness of this log cannot be established." + caveat,
        )
    # Only claim the chain is intact if it was actually checked. It is not when
    # records were verified individually rather than as a log.
    chain_clause = (
        " and the chain is intact" if chain_status == "INTACT" else ""
    )
    severe = [
        f for f in findings
        if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.HIGH]
    ]
    if severe:
        return (
            "PROVENANCE UNVERIFIED",
            f"{len(severe)} high-severity integrity finding(s) require analyst "
            "review before these records are relied on." + caveat,
        )
    if findings:
        return (
            "PROVENANCE VERIFIED WITH FINDINGS",
            f"every record's bindings and signature verify, but {len(findings)} "
            "lower-severity finding(s) warrant review." + caveat,
        )
    if records_total == 0:
        return (
            "NO RECORDS",
            "there was nothing to verify." + caveat,
        )
    if unassessed_classes or truncation_status == "NOT_DETECTABLE":
        return (
            "PROVENANCE VERIFIED — PARTIAL COVERAGE",
            f"all {records_total} record(s) verify{chain_clause}, but "
            f"{unassessed_classes} attack class(es) could not be assessed with "
            "what was supplied. An unassessed class is an open question, not a "
            "clean result." + caveat,
        )
    return (
        "PROVENANCE VERIFIED",
        f"all {records_total} record(s) verify against trusted keys, the chain "
        "is intact, and the log matches its anchor." + caveat,
    )


def build_provenance_report(
    *,
    run: RunContext,
    log: dict[str, Any],
    cryptographic: CryptographicSummary,
    configuration: dict[str, Any],
    disposition_policy: dict[str, Any],
    chain: dict[str, Any],
    verifications: list[Any],
    records: list[RecordSummary],
    findings: list[Finding],
    detectors: list[DetectorReport],
    coverage: CoverageStatement,
    malformed_lines: int,
    extra_limitations: list[str] | None = None,
) -> ProvenanceReport:
    ordered = sorted(findings, key=lambda f: f.sort_key())
    matrix = build_matrix(verifications)

    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_disposition: dict[str, int] = {d.value: 0 for d in Disposition}
    by_attack_class: dict[str, int] = {}
    for finding in ordered:
        by_severity[finding.severity.value] += 1
        by_disposition[finding.disposition.value] += 1
        by_attack_class[finding.attack_class] = (
            by_attack_class.get(finding.attack_class, 0) + 1
        )

    by_failure: dict[str, int] = {}
    for record in records:
        for code in record.failures:
            by_failure[code] = by_failure.get(code, 0) + 1

    # "NOT_ASSESSED" means the records were verified individually. That is not
    # a broken chain, so it must not drive the COMPROMISED verdict.
    chain_status = str(chain.get("status", "EMPTY"))
    chain_intact = chain_status in ("INTACT", "EMPTY", "NOT_ASSESSED")
    truncation_status = str(chain.get("truncation_status", "NOT_DETECTABLE"))
    unassessed = len(
        [
            entry
            for entry in coverage.entries
            if entry.owning_module == 3 and entry.coverage.value == "NOT_ASSESSED"
        ]
    )
    records_failed = sum(1 for r in records if not r.valid)
    overall, rationale = _overall(
        ordered,
        records_total=len(records),
        records_failed=records_failed,
        chain_intact=chain_intact,
        chain_status=chain_status,
        truncation_status=truncation_status,
        unassessed_classes=unassessed,
    )

    summary = ProvenanceAssessmentSummary(
        overall=overall,
        rationale=rationale,
        records_total=len(records),
        records_valid=sum(1 for r in records if r.valid),
        records_cryptographically_intact=sum(
            1 for r in records if r.cryptographically_intact
        ),
        records_failed=records_failed,
        malformed_lines=malformed_lines,
        findings_total=len(ordered),
        by_severity=by_severity,
        by_disposition=by_disposition,
        by_attack_class=dict(sorted(by_attack_class.items())),
        by_failure_code=dict(sorted(by_failure.items())),
        chain_status=chain_status,
        truncation_status=truncation_status,
        replay_detected=sum(
            1
            for r in records
            if r.replay_verdict in ("REPLAY_EXACT", "NONCE_REUSE", "SEQUENCE_COLLISION")
        ),
    )

    report = ProvenanceReport(
        report_id="",
        run=run,
        log=log,
        cryptographic=cryptographic,
        configuration=configuration,
        disposition_policy=disposition_policy,
        chain=chain,
        matrix=matrix,
        records=records,
        verifications=[v.model_dump(mode="json") for v in verifications],
        summary=summary,
        findings=ordered,
        detectors=detectors,
        coverage=coverage,
        limitations=list(PROVENANCE_GLOBAL_LIMITATIONS) + list(extra_limitations or []),
    )
    object.__setattr__(report, "report_id", f"PR-{short(report.stable_digest(), 16)}")
    return report


__all__ = [
    "PROVENANCE_REPORT_SCHEMA_VERSION", "RecordSummary", "VerificationMatrix",
    "CryptographicSummary", "ProvenanceAssessmentSummary", "ProvenanceReport",
    "PROVENANCE_GLOBAL_LIMITATIONS", "build_provenance_report", "build_matrix",
]
