"""Module 3 orchestration: verify a provenance log and produce a report.

The shape mirrors :mod:`cvtrust.pipeline` and :mod:`cvtrust.model_pipeline` — a
``RunContext`` whose ``run_id`` is derived from the inputs, a fixed sequence of
checks, one report object from which every human view is rendered — with one
ordering constraint the other two do not have:

    **Chain verification runs before record verification.**

A record's ``previous_record_valid`` and ``sequence_valid`` checks are answers
about its position in the log, and a position is a property of the whole
sequence.  Verifying records first and then the chain would mean every record's
position check reported ``NOT_CHECKED`` in a log verification, which is the
report saying it did not look at the thing it was asked to look at.

The replay database is threaded through the loop rather than consulted once,
because a log that contains the same record twice must have the second one
flagged, and that is only visible if the first has already been recorded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from .core.canonical import digest_safe
from .core.config import Config
from .core.context import RunContext
from .core.evidence import Finding
from .core.hashing import HASH_ALGORITHM
from .core.logging import get_logger
from .provenance.binding import CONFIG_QUANT_PLACES
from .provenance.chain import ChainVerification, LogAnchor, verify_chain
from .provenance.findings import (
    METHOD,
    METHOD_VERSION,
    findings_for_chain,
    findings_for_record,
    malformed_entry_findings,
    provenance_coverage,
)
from .provenance.keys import SIGNATURE_ALGORITHM
from .provenance.log import ProvenanceLog
from .provenance.record import PROVENANCE_SCHEMA_VERSION, SignedRecord
from .provenance.replay import ReplayDatabase
from .provenance.trust import KeyPurpose, KeyStatus, TrustStore, ValidityPolicy
from .provenance.verify import (
    ExpectedBinding,
    FailureCode,
    RecordVerification,
    verify_record,
)
from .reporting.provenance_report import (
    CryptographicSummary,
    ProvenanceReport,
    RecordSummary,
    build_provenance_report,
)
from .reporting.report import DetectorReport
from .risk.coverage import CoverageStatement
from .risk.disposition import DispositionPolicy

log = get_logger("provenance_pipeline")

#: Which modules this build implements.  Passed to the coverage statement so
#: that Module 4's classes are declared NOT_ASSESSED with the module named,
#: rather than looking like classes no detector happened to report on.
IMPLEMENTED_MODULES: tuple[int, ...] = (1, 2, 3)

#: Canonicalisation in force, recorded in the report so an old report can be
#: read correctly after this changes.
CANONICALISATION = (
    "RFC 8785-style canonical JSON (sorted keys, no insignificant whitespace, "
    "UTF-8) with floats rejected on the digest surface and carried as "
    "fixed-point integers instead -- see ADR-004"
)


def verify_log(
    entries: Sequence[SignedRecord] | ProvenanceLog,
    config: Config,
    *,
    trust_store: TrustStore | None = None,
    expected: ExpectedBinding | None = None,
    replay_database: ReplayDatabase | None = None,
    anchor: LogAnchor | None = None,
    validity_policy: ValidityPolicy | None = None,
    required_purpose: KeyPurpose = KeyPurpose.INFERENCE_PROVENANCE,
    record_observations: bool = True,
    as_log: bool = True,
    log_locator: str | None = None,
) -> tuple[ProvenanceReport, RunContext, ReplayDatabase | None]:
    """Verify a whole log and build its report.

    Returns the report, the run context, and the replay database as it stands
    after the log was observed — returned rather than mutated in place so a
    caller decides whether to persist it.  A verification that silently wrote to
    the replay database would make a dry run indistinguishable from an
    accepted one.

    ``as_log=False`` verifies the entries as loose records rather than as a
    complete log.  It exists because the two questions are different and
    conflating them produces a false alarm: a record lifted out of the middle of
    a log carries a non-null back-pointer and a non-zero sequence number, which
    is exactly what a *log* missing its beginning looks like.  Verified as a log
    it would be reported as front-truncated and chain-broken; verified as a
    record its position is simply ``NOT_CHECKED``, which is the truth — the
    record is fine, and nothing was presented that could establish where it sat.
    """
    provenance_log = (
        entries if isinstance(entries, ProvenanceLog)
        else ProvenanceLog(log_id=_log_id_of(entries), entries=list(entries))
    )
    policy = validity_policy or ValidityPolicy(
        config.provenance.validity_policy
    )
    locator = log_locator or (
        str(provenance_log.path) if provenance_log.path else None
    )

    run = RunContext.create(
        seed=config.seed,
        config_hash=config.config_hash(),
        extra={
            "module": 3,
            "log_id": provenance_log.log_id,
            "entry_count": len(provenance_log.entries),
            "head_entry_digest": provenance_log.head_digest(),
            "trust_store_digest": trust_store.digest() if trust_store else None,
            "anchor_digest": anchor.digest() if anchor else None,
            "expected": digest_safe(expected.model_dump() if expected else {}),
            "validity_policy": policy.value,
        },
    )
    run.detector_versions[METHOD] = METHOD_VERSION

    # 1. The chain, first: a record's position is a property of the sequence.
    #    Skipped entirely when the caller is verifying loose records, because
    #    "this is not a complete log" is not a finding about a record.
    with run.timer("chain"):
        chain = verify_chain(provenance_log.entries, anchor=anchor) if as_log else None

    # 2. Each record, with the chain result in hand.
    verifications: list[RecordVerification] = []
    database = replay_database
    with run.timer("records"):
        for position, entry in enumerate(provenance_log.entries):
            verification = verify_record(
                entry,
                trust_store=trust_store,
                expected=expected,
                replay_database=database,
                validity_policy=policy,
                required_purpose=required_purpose,
                chain_result=chain,
                position=position if chain is not None else None,
            )
            verifications.append(verification)
            if database is not None and record_observations:
                database = database.record(entry)

    # 3. Findings. Record-level, then chain-level, then unparseable lines.
    findings: list[Finding] = []
    with run.timer("findings"):
        # Which inputs this verification actually had. A failure raised because
        # a check could not run is dispositioned differently from one raised
        # because the check ran and failed.
        available = {
            "trust_store": trust_store is not None,
            "replay_database": replay_database is not None,
            "anchor": anchor is not None,
            "expectations": bool(expected and expected.any_supplied()),
        }
        for verification in verifications:
            findings.extend(
                findings_for_record(
                    verification, config=config, locator=locator,
                    available=available,
                )
            )
        if chain is not None:
            findings.extend(
                findings_for_chain(chain, config=config, log_locator=locator)
            )
        findings.extend(
            malformed_entry_findings(
                provenance_log.malformed, config=config, log_locator=locator
            )
        )

    coverage_entries = provenance_coverage(
        trust_store_supplied=trust_store is not None,
        anchor_supplied=anchor is not None and as_log,
        replay_database_supplied=replay_database is not None,
        expectations_supplied=bool(expected and expected.any_supplied()),
    )
    if not as_log:
        # Nothing about ordering was assessed, so say so rather than letting
        # record_reordering stand at SUPPORTED on the strength of a check that
        # was never run.
        coverage_entries = [
            entry for entry in coverage_entries
            if entry.attack_class not in ("record_reordering", "chain_truncation")
        ]
    coverage = CoverageStatement.build(coverage_entries, IMPLEMENTED_MODULES)

    report = build_provenance_report(
        run=run.finish(),
        log={
            **provenance_log.stats(),
            "path": locator,
            "root": locator,
        },
        cryptographic=_crypto_summary(
            trust_store=trust_store,
            replay_database=replay_database,
            anchor=anchor,
            expected=expected,
            policy=policy,
        ),
        configuration={
            "provenance": config.provenance.model_dump(mode="json"),
            "config_hash": config.config_hash(),
        },
        disposition_policy=DispositionPolicy(config.disposition).describe(),
        chain=_chain_payload(chain),
        verifications=verifications,
        records=[
            _record_summary(entry, verification)
            for entry, verification in zip(provenance_log.entries, verifications)
        ],
        findings=findings,
        detectors=[
            DetectorReport(
                name=METHOD,
                version=METHOD_VERSION,
                findings=len(findings),
                stats={
                    "records_verified": len(verifications),
                    "checks_per_record": (
                        len(verifications[0].checks) if verifications else 0
                    ),
                    "malformed_lines": len(provenance_log.malformed),
                    "confidence_basis": "DETERMINISTIC for every finding; this "
                    "detector has no score and no calibration table, because "
                    "there is nothing to calibrate in an equality test",
                },
            )
        ],
        coverage=coverage,
        malformed_lines=len(provenance_log.malformed),
    )
    return report, run, database


def verify_single_record(
    entry: SignedRecord,
    config: Config,
    *,
    trust_store: TrustStore | None = None,
    expected: ExpectedBinding | None = None,
    replay_database: ReplayDatabase | None = None,
    validity_policy: ValidityPolicy | None = None,
) -> tuple[ProvenanceReport, RunContext, ReplayDatabase | None]:
    """Verify one record outside a log.

    The position checks report ``NOT_CHECKED`` in this mode, which is accurate
    and important: a record that verifies perfectly on its own can still have
    been deleted from, reordered within or spliced into a log, and a report that
    said ``PASS`` here would be claiming a guarantee it had not tested.
    """
    return verify_log(
        [entry],
        config,
        trust_store=trust_store,
        expected=expected,
        replay_database=replay_database,
        anchor=None,
        validity_policy=validity_policy,
        as_log=False,
    )


def load_verification_inputs(
    *,
    log_path: Path | str,
    trust_store_path: Path | str | None = None,
    replay_db_path: Path | str | None = None,
    anchor_path: Path | str | None = None,
) -> tuple[ProvenanceLog, TrustStore | None, ReplayDatabase | None, LogAnchor | None]:
    """Load everything a verification needs, keeping "absent" distinguishable.

    An absent trust store or replay database yields ``None``, never an empty
    one.  The report distinguishes "no trust store was supplied" from "a trust
    store was supplied and it is empty": the first is a missing input, the
    second is an operator who has trusted nothing, and they call for different
    actions.
    """
    import json

    provenance_log = ProvenanceLog.load(log_path)
    store = TrustStore.load(trust_store_path) if trust_store_path else None
    database = (
        ReplayDatabase.load_or_empty(replay_db_path) if replay_db_path else None
    )
    anchor = None
    if anchor_path:
        anchor = LogAnchor.model_validate(
            json.loads(Path(anchor_path).read_text(encoding="utf-8"))
        )
    return provenance_log, store, database, anchor


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _log_id_of(entries: Sequence[SignedRecord]) -> str:
    return entries[0].record.sequence.log_id if entries else "unknown"


def _crypto_summary(
    *,
    trust_store: TrustStore | None,
    replay_database: ReplayDatabase | None,
    anchor: LogAnchor | None,
    expected: ExpectedBinding | None,
    policy: ValidityPolicy,
) -> CryptographicSummary:
    return CryptographicSummary(
        record_schema_version=PROVENANCE_SCHEMA_VERSION,
        hash_algorithm=HASH_ALGORITHM,
        signature_algorithm=SIGNATURE_ALGORITHM,
        canonicalisation=CANONICALISATION,
        quantization_places=CONFIG_QUANT_PLACES,
        validity_policy=policy.value,
        trust_store_supplied=trust_store is not None,
        trust_store_digest=trust_store.digest() if trust_store else None,
        trusted_key_count=(
            len(trust_store.trusted_ids()) if trust_store else 0
        ),
        revoked_key_count=(
            sum(1 for k in trust_store.keys if k.status is KeyStatus.REVOKED)
            if trust_store
            else 0
        ),
        replay_database_supplied=replay_database is not None,
        replay_observations=len(replay_database) if replay_database else 0,
        anchor_supplied=anchor is not None,
        expectations_supplied=bool(expected and expected.any_supplied()),
        expectation_source=expected.source if expected else None,
    )


def _chain_payload(chain: ChainVerification | None) -> dict[str, Any]:
    if chain is None:
        return {
            "status": "NOT_ASSESSED",
            "truncation_status": "NOT_ASSESSED",
            "entry_count": None,
            "head_entry_digest": None,
            "detail": "these records were verified individually, not as a log, "
            "so linkage and ordering were not assessed. A record that verifies "
            "on its own can still have been removed from, reordered within or "
            "spliced into a log",
            "truncation_detail": "not applicable: no log was presented",
            "anchor_supplied": False,
            "links": [],
            "first_break_position": None,
            "guarantees": {
                "ordering": "NOT ASSESSED — no log was presented",
            },
        }
    payload = chain.model_dump(mode="json")
    payload["guarantees"] = chain.guarantees()
    return payload


def _record_summary(
    entry: SignedRecord, verification: RecordVerification
) -> RecordSummary:
    record = entry.record
    return RecordSummary(
        position=verification.position,
        record_id=verification.record_id,
        entry_digest=verification.entry_digest,
        sequence_number=record.sequence.sequence_number,
        timestamp=record.timestamp,
        signing_key_id=verification.signing_key_id,
        key_status=verification.key_status.value,
        failures=tuple(f.value for f in verification.failures),
        replay_verdict=verification.replay_verdict.value,
        input_digest=record.input.raw_input_digest,
        model_id=record.model.model_id,
        model_file_sha256=record.model.file_sha256,
        output_summary=record.output.output.summary(),
        valid=verification.valid,
        cryptographically_intact=verification.cryptographically_intact,
    )


__all__ = [
    "IMPLEMENTED_MODULES", "verify_log", "verify_single_record",
    "load_verification_inputs", "FailureCode",
]
