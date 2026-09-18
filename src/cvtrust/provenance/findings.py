"""Verification facts as Module 1 ``Finding`` objects.

This is the join between Module 3 and the rest of the platform, and it has one
hard rule, which is §27 of the module brief and the reason the file is this
short:

    **A cryptographic verification failure is a deterministic integrity fact.
    An ML detector output is an evidence-based assessment.  They never become
    the same number.**

So every finding produced here carries ``ConfidenceBasis.DETERMINISTIC`` and
confidence exactly ``1.0``, because that is what the basis means: SHA-256
equality and Ed25519 verification are not inferences, there is no threshold, and
there is nothing to calibrate.  There is no score in this module, no calibration
table is produced for it, and a test asserts that no provenance finding ever
arrives with any other basis.

The consequence that matters in the other direction: a model that Module 2
flags as anomalous can have a perfectly valid provenance chain, and a model
Module 2 finds nothing wrong with can have a forged one.  Both facts survive to
the final report because they are carried by separate findings with separate
attack classes, and nothing in this codebase averages them.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..core.config import Config
from ..core.evidence import (
    AssetRef,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Finding,
    Severity,
)
from ..detectors.base import FindingFactory, coverage_entry
from ..risk.calibration import CalibrationSet
from ..risk.coverage import CoverageEntry
from ..risk.disposition import DispositionPolicy
from .chain import ChainStatus, ChainVerification, TruncationStatus
from .verify import CheckOutcome, FailureCode, RecordVerification

METHOD = "provenance_verifier"
METHOD_VERSION = "1.0"

#: Which attack class each failure belongs to, and how consequential it is if
#: true.  A table rather than an if-chain, for the same reason Module 2's
#: identity severities are one: the mapping from an observation to a severity is
#: a policy a reviewer should be able to disagree with, and it is printed.
FAILURE_POLICY: dict[FailureCode, tuple[str, Severity, str]] = {
    FailureCode.INVALID_SIGNATURE: (
        "inference_tampering", Severity.CRITICAL,
        "the signature does not verify over the record's canonical bytes: the "
        "record was altered after it was signed, and nothing it asserts about "
        "the inference can be relied on",
    ),
    FailureCode.MISSING_SIGNATURE: (
        "provenance_key_trust", Severity.HIGH,
        "the record is unsigned, so it attributes itself to no one and its "
        "contents could have been written by anyone with access to the log",
    ),
    FailureCode.MALFORMED_SIGNATURE: (
        "inference_tampering", Severity.HIGH,
        "the signature envelope is structurally broken, so authenticity could "
        "not be assessed at all -- which is not the same as its having failed",
    ),
    FailureCode.UNKNOWN_KEY: (
        "provenance_key_trust", Severity.HIGH,
        "the signing key is not in the trust store. The signature may verify "
        "perfectly; anyone can generate a keypair, so validity without "
        "authority establishes nothing about who produced this record",
    ),
    FailureCode.REVOKED_KEY: (
        "provenance_key_trust", Severity.HIGH,
        "the signing key has been revoked by the operator, so its signatures "
        "are no longer accepted as evidence of authorship",
    ),
    FailureCode.KEY_EXPIRED: (
        "provenance_key_trust", Severity.MEDIUM,
        "the signing key was outside its validity window at the moment the "
        "policy evaluated",
    ),
    FailureCode.KEY_NOT_YET_VALID: (
        "provenance_key_trust", Severity.MEDIUM,
        "the signing key was not yet valid at the moment the policy evaluated",
    ),
    FailureCode.KEY_PURPOSE_MISMATCH: (
        "provenance_key_trust", Severity.MEDIUM,
        "the signing key is authorised for a different purpose than the one it "
        "was used for",
    ),
    FailureCode.INPUT_MISMATCH: (
        "inference_tampering", Severity.CRITICAL,
        "the record binds a different input than the artifact the analyst "
        "holds: the inference described is not the inference over this input",
    ),
    FailureCode.MODEL_MISMATCH: (
        "inference_tampering", Severity.CRITICAL,
        "the record binds a different model than the one assured: every "
        "behavioural conclusion drawn about the assured model is inapplicable "
        "to whatever actually ran",
    ),
    FailureCode.CONFIGURATION_MISMATCH: (
        "inference_tampering", Severity.HIGH,
        "preprocessing or inference configuration does not match: the same "
        "model and the same image under different preprocessing is a different "
        "inference",
    ),
    FailureCode.OUTPUT_MISMATCH: (
        "inference_tampering", Severity.CRITICAL,
        "the bound output does not match the output held: the record describes "
        "a result that was not produced",
    ),
    FailureCode.SELF_INCONSISTENT_RECORD: (
        "inference_tampering", Severity.HIGH,
        "the record's own derived values do not match its content, which a "
        "conforming producer cannot emit",
    ),
    FailureCode.CHAIN_BREAK: (
        "record_reordering", Severity.HIGH,
        "the record's position in the log cannot be verified: an entry was "
        "modified, inserted, deleted or reordered at or before this point",
    ),
    FailureCode.REPLAY: (
        "inference_replay", Severity.HIGH,
        "this record, or its nonce or sequence slot, has been presented before: "
        "a valid signature does not establish that an inference happened once",
    ),
    FailureCode.MALFORMED_RECORD: (
        "inference_tampering", Severity.MEDIUM,
        "the record could not be parsed or evaluated far enough to verify",
    ),
    FailureCode.MISSING_FIELD: (
        "inference_tampering", Severity.MEDIUM,
        "a field whose presence is part of the guarantee is absent, so the "
        "guarantee it supports does not hold",
    ),
    FailureCode.UNSUPPORTED_SCHEMA: (
        "inference_tampering", Severity.MEDIUM,
        "the record uses a schema version this build does not implement; "
        "verifying it would mean guessing what its fields mean",
    ),
}

#: Titles for the finding headline, keyed by failure code.
FAILURE_TITLE: dict[FailureCode, str] = {
    FailureCode.INVALID_SIGNATURE: "Provenance signature does not verify",
    FailureCode.MISSING_SIGNATURE: "Provenance record is unsigned",
    FailureCode.MALFORMED_SIGNATURE: "Provenance signature envelope is malformed",
    FailureCode.UNKNOWN_KEY: "Provenance signed by an unknown key",
    FailureCode.REVOKED_KEY: "Provenance signed by a revoked key",
    FailureCode.KEY_EXPIRED: "Provenance signed by an expired key",
    FailureCode.KEY_NOT_YET_VALID: "Provenance signed by a not-yet-valid key",
    FailureCode.KEY_PURPOSE_MISMATCH: "Signing key used outside its declared purpose",
    FailureCode.INPUT_MISMATCH: "Bound input does not match the artifact held",
    FailureCode.MODEL_MISMATCH: "Bound model does not match the assured model",
    FailureCode.CONFIGURATION_MISMATCH: "Bound configuration does not match",
    FailureCode.OUTPUT_MISMATCH: "Bound output does not match the output held",
    FailureCode.SELF_INCONSISTENT_RECORD: "Provenance record is self-inconsistent",
    FailureCode.CHAIN_BREAK: "Provenance chain is broken at this record",
    FailureCode.REPLAY: "Provenance record has been presented before",
    FailureCode.MALFORMED_RECORD: "Provenance record is malformed",
    FailureCode.MISSING_FIELD: "Provenance record is missing a required field",
    FailureCode.UNSUPPORTED_SCHEMA: "Provenance record uses an unsupported schema",
}

#: Checks that evidence each failure code.  Attaching the *relevant* checks —
#: rather than all of them — is what lets a reviewer recompute the specific
#: claim instead of re-reading the whole verification.
FAILURE_EVIDENCE: dict[FailureCode, tuple[str, ...]] = {
    FailureCode.INVALID_SIGNATURE: ("signature_valid",),
    FailureCode.MISSING_SIGNATURE: ("signature_valid",),
    FailureCode.MALFORMED_SIGNATURE: ("signature_valid",),
    FailureCode.UNKNOWN_KEY: ("signature_valid", "key_known", "key_trusted"),
    FailureCode.REVOKED_KEY: ("key_trusted", "signed_before_revocation"),
    FailureCode.KEY_EXPIRED: ("key_within_validity_window",),
    FailureCode.KEY_NOT_YET_VALID: ("key_within_validity_window",),
    FailureCode.KEY_PURPOSE_MISMATCH: ("key_purpose_permitted",),
    FailureCode.INPUT_MISMATCH: (
        "input_digest_match", "normalized_input_digest_match",
    ),
    FailureCode.MODEL_MISMATCH: (
        "model_digest_match", "model_graph_digest_match",
        "model_parameter_digest_match", "model_id_match",
    ),
    FailureCode.CONFIGURATION_MISMATCH: (
        "preprocessing_digest_match", "inference_config_digest_match",
        "preprocessing_digest_self_consistent",
        "inference_config_digest_self_consistent",
    ),
    FailureCode.OUTPUT_MISMATCH: (
        "output_digest_match", "output_digest_self_consistent",
    ),
    FailureCode.SELF_INCONSISTENT_RECORD: ("record_id_matches_content",),
    FailureCode.CHAIN_BREAK: ("previous_record_valid", "sequence_valid"),
    FailureCode.REPLAY: ("replay_detected",),
    FailureCode.MALFORMED_RECORD: ("schema_supported", "required_fields_present"),
    FailureCode.MISSING_FIELD: ("required_fields_present",),
    FailureCode.UNSUPPORTED_SCHEMA: ("schema_supported",),
}


#: Which supplied input each failure code's assessment depends on.
#:
#: A failure raised because a check could not run is not the same finding as one
#: raised because the check ran and failed, and the disposition policy already
#: knows the difference: rule ``D-000-not-assessed`` downgrades an unassessed
#: class to REVIEW, because an open question must never drive an irreversible
#: action.  Reporting UNKNOWN_KEY at SUPPORTED coverage when no trust store was
#: supplied would quarantine a pipeline for an input the operator simply did not
#: provide, so the dependency is declared here and resolved per verification.
#:
#: Codes absent from this table depend on nothing: they are raised by the
#: record's own content, which is always available.
FAILURE_PRECONDITION: dict[FailureCode, str] = {
    FailureCode.UNKNOWN_KEY: "trust_store",
    FailureCode.REVOKED_KEY: "trust_store",
    FailureCode.KEY_EXPIRED: "trust_store",
    FailureCode.KEY_NOT_YET_VALID: "trust_store",
    FailureCode.KEY_PURPOSE_MISMATCH: "trust_store",
}


class _ProvenanceFactoryContext:
    """The two things :class:`FindingFactory` needs.

    Module 3 findings never resolve confidence through the calibration set —
    every one of them supplies ``DETERMINISTIC`` explicitly — so the set here is
    always empty, and that is a statement rather than an oversight: there is
    nothing to calibrate in an equality test.
    """

    def __init__(self, config: Config) -> None:
        self.calibration = CalibrationSet.empty()
        self.policy = DispositionPolicy(config.disposition)


def record_asset(verification: RecordVerification, locator: str | None = None) -> AssetRef:
    return AssetRef(
        type=AssetType.INFERENCE,
        id=verification.record_id or "unknown-record",
        locator=locator,
        digest=verification.entry_digest,
    )


def findings_for_record(
    verification: RecordVerification,
    *,
    config: Config,
    locator: str | None = None,
    available: Mapping[str, bool] | None = None,
) -> list[Finding]:
    """One finding per distinct failure code on one record.

    Per *code*, not per failed check: three mismatched model digests are one
    substitution, and emitting three findings would triple the apparent evidence
    for a single event.  The individual checks travel inside the finding as
    evidence, so nothing is lost.

    ``available`` names the inputs the verification actually had — currently
    ``trust_store`` — so that a failure raised because a check *could not run*
    carries ``NOT_ASSESSED`` coverage and is dispositioned by rule
    ``D-000-not-assessed`` rather than quarantining a pipeline over a missing
    input.  See :data:`FAILURE_PRECONDITION`.
    """
    factory = FindingFactory(_ProvenanceFactoryContext(config), METHOD, METHOD_VERSION)
    asset = record_asset(verification, locator)
    supplied = dict(available or {})
    findings: list[Finding] = []

    for code in verification.failures:
        if code is FailureCode.VALID:
            continue
        attack_class, severity, rationale = FAILURE_POLICY[code]
        evidence = _evidence_for(verification, code, rationale)
        precondition = FAILURE_PRECONDITION.get(code)
        coverage = (
            Coverage.NOT_ASSESSED
            if precondition is not None and not supplied.get(precondition, True)
            else Coverage.SUPPORTED
        )
        findings.append(
            factory.emit(
                attack_class=attack_class,
                asset=asset,
                category=Category.INFERENCE,
                title=FAILURE_TITLE[code],
                severity=severity,
                evidence=evidence,
                coverage=coverage,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                discriminator=(code.value,),
                assumptions=_assumptions_for(code),
                limitations=_limitations_for(code),
            )
        )
    return findings


def _evidence_for(
    verification: RecordVerification, code: FailureCode, rationale: str
) -> list[EvidenceItem]:
    wanted = FAILURE_EVIDENCE.get(code, ())
    items: list[EvidenceItem] = [
        EvidenceItem(
            kind="provenance_failure",
            statement=rationale,
            observation={
                "failure_code": code.value,
                "record_id": verification.record_id,
                "entry_digest": verification.entry_digest,
                "position": verification.position,
                "all_failures": [f.value for f in verification.failures],
                "signing_key_id": verification.signing_key_id,
                "key_status": verification.key_status.value,
                "validity_policy": verification.validity_policy.value,
                "basis": "deterministic verification, not an inference",
            },
            refs=(verification.record_id or "",),
        )
    ]
    for name in wanted:
        check = verification.check(name)
        if check is None or check.outcome is CheckOutcome.NOT_APPLICABLE:
            continue
        items.append(
            EvidenceItem(
                kind=f"check:{name}",
                statement=check.detail,
                observation={"outcome": check.outcome.value, **dict(check.observation)},
                refs=(verification.record_id or "",),
            )
        )
    return items


def _assumptions_for(code: FailureCode) -> tuple[str, ...]:
    common = (
        "SHA-256 collision resistance and Ed25519 unforgeability hold.",
        "The verifying host, its copy of this software and its trust store are "
        "not under adversary control.",
    )
    if code in (FailureCode.UNKNOWN_KEY, FailureCode.REVOKED_KEY):
        return common + (
            "The trust store was populated from a channel independent of the one "
            "that supplied these records. A trust store filled from the same "
            "source as the records establishes nothing.",
        )
    if code in (
        FailureCode.INPUT_MISMATCH,
        FailureCode.MODEL_MISMATCH,
        FailureCode.OUTPUT_MISMATCH,
        FailureCode.CONFIGURATION_MISMATCH,
    ):
        return common + (
            "The expectation this was compared against is the analyst's own, "
            "obtained independently of the record.",
        )
    if code is FailureCode.REPLAY:
        return common + (
            "The replay database has not been truncated or rolled back, and has "
            "retained observations covering the period in question.",
        )
    return common


def _limitations_for(code: FailureCode) -> tuple[str, ...]:
    base = (
        "This is a statement about the integrity of the record, not about the "
        "quality of the inference. A cryptographically valid record of a "
        "backdoored model is possible, and so is an invalid record of a sound "
        "one.",
    )
    if code is FailureCode.REPLAY:
        return base + (
            "Replay detection is bounded by the local database's retention: a "
            "record older than its earliest observation cannot be shown not to "
            "have been seen before.",
            "A record presented for the first time cannot be distinguished from "
            "the original by a local database; presentation order is not "
            "something it can establish.",
        )
    if code in (FailureCode.KEY_EXPIRED, FailureCode.KEY_NOT_YET_VALID):
        return base + (
            "Under the at_record_timestamp policy the window is evaluated "
            "against the record's own self-asserted clock, which a holder of the "
            "key also controls.",
        )
    return base


# ---------------------------------------------------------------------------
# Chain-level findings
# ---------------------------------------------------------------------------


def findings_for_chain(
    chain: ChainVerification,
    *,
    config: Config,
    log_locator: str | None = None,
) -> list[Finding]:
    """Findings about the log as a whole, distinct from its individual records."""
    factory = FindingFactory(_ProvenanceFactoryContext(config), METHOD, METHOD_VERSION)
    asset = AssetRef(
        type=AssetType.PIPELINE,
        id=chain.log_id or "provenance-log",
        locator=log_locator,
        digest=chain.head_entry_digest,
    )
    findings: list[Finding] = []

    if chain.status is ChainStatus.BROKEN:
        broken = chain.broken_positions()
        findings.append(
            factory.emit(
                attack_class="record_reordering",
                asset=asset,
                category=Category.INFERENCE,
                title="Provenance chain integrity is broken",
                severity=Severity.CRITICAL,
                evidence=[
                    EvidenceItem(
                        kind="chain_linkage",
                        statement=chain.detail,
                        observation={
                            "entry_count": chain.entry_count,
                            "first_break_position": chain.first_break_position,
                            "broken_positions": list(broken),
                            "head_entry_digest": chain.head_entry_digest,
                        },
                        refs=(chain.log_id or "",),
                    ),
                    EvidenceItem(
                        kind="chain_link_detail",
                        statement="Per-entry linkage and sequence results.",
                        observation={
                            "links": [
                                {
                                    "position": link.position,
                                    "record_id": link.record_id,
                                    "link_status": link.link_status.value,
                                    "sequence_number": link.sequence_number,
                                    "sequence_expected": link.sequence_expected,
                                    "sequence_valid": link.sequence_valid,
                                }
                                for link in chain.links
                                if not link.ok
                            ]
                        },
                        refs=(),
                    ),
                    EvidenceItem(
                        kind="chain_guarantees",
                        statement="What this chain check does and does not detect.",
                        observation=chain.guarantees(),
                        refs=(),
                    ),
                ],
                coverage=Coverage.SUPPORTED,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                discriminator=("chain_break",),
                assumptions=(
                    "SHA-256 collision resistance holds.",
                    "The entries were presented in the order they appear in the log.",
                ),
                limitations=(
                    "A hash chain detects restructuring of the entries it "
                    "contains. It cannot detect entries removed from the end -- "
                    "see the truncation status, which is reported separately.",
                ),
            )
        )

    # Deliberately NOT firing on ANCHOR_STALE: a log that has grown past its
    # anchor is what appending to a log looks like, and raising a HIGH-severity
    # finding for it would make operators stop taking anchors. The status is
    # still reported, so the reader can see that the newer entries are
    # unattested.
    if chain.truncation_status in (
        TruncationStatus.TRUNCATION_DETECTED,
        TruncationStatus.ANCHOR_MISMATCH,
        TruncationStatus.FRONT_TRUNCATION_DETECTED,
    ):
        findings.append(
            factory.emit(
                attack_class="chain_truncation",
                asset=asset,
                category=Category.INFERENCE,
                title="Provenance log does not match its anchor",
                severity=Severity.HIGH,
                evidence=[
                    EvidenceItem(
                        kind="log_truncation",
                        statement=chain.truncation_detail,
                        observation={
                            "truncation_status": chain.truncation_status.value,
                            "entry_count": chain.entry_count,
                            "head_entry_digest": chain.head_entry_digest,
                            "anchor_supplied": chain.anchor_supplied,
                        },
                        refs=(chain.log_id or "",),
                    )
                ],
                coverage=Coverage.SUPPORTED,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                discriminator=("truncation",),
                assumptions=(
                    "The anchor was recorded out of band and is not writable by "
                    "whoever writes the log.",
                ),
                limitations=(
                    "An anchor stored alongside the log it anchors protects "
                    "against nothing.",
                ),
            )
        )

    if chain.mixed_log_ids:
        findings.append(
            factory.emit(
                attack_class="record_reordering",
                asset=asset,
                category=Category.INFERENCE,
                title="Records from multiple logs are interleaved",
                severity=Severity.MEDIUM,
                evidence=[
                    EvidenceItem(
                        kind="mixed_log_ids",
                        statement=(
                            "This sequence contains records claiming membership "
                            "of more than one log, so no single chain can be "
                            "verified over it."
                        ),
                        observation={"log_ids": list(chain.mixed_log_ids)},
                        refs=(),
                    )
                ],
                coverage=Coverage.SUPPORTED,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                discriminator=("mixed_logs",),
                limitations=(
                    "Interleaving is a structural observation; it does not by "
                    "itself establish that either log was tampered with.",
                ),
            )
        )
    return findings


def malformed_entry_findings(
    malformed: Sequence[Any], *, config: Config, log_locator: str | None = None
) -> list[Finding]:
    """A finding per line that could not be parsed into a record."""
    factory = FindingFactory(_ProvenanceFactoryContext(config), METHOD, METHOD_VERSION)
    findings: list[Finding] = []
    for entry in malformed:
        asset = AssetRef(
            type=AssetType.INFERENCE,
            id=f"line-{entry.line_number}",
            locator=log_locator,
        )
        findings.append(
            factory.emit(
                attack_class="inference_tampering",
                asset=asset,
                category=Category.INFERENCE,
                title="Provenance log line is not a valid record",
                severity=Severity.HIGH,
                evidence=[
                    EvidenceItem(
                        kind="malformed_log_line",
                        statement=(
                            f"Line {entry.line_number} of the log could not be "
                            f"parsed into a provenance record: {entry.error}"
                        ),
                        observation={
                            "line_number": entry.line_number,
                            "error": entry.error,
                            "raw_prefix": entry.raw[:200],
                        },
                        refs=(log_locator or "",),
                    )
                ],
                coverage=Coverage.SUPPORTED,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                discriminator=(str(entry.line_number),),
                limitations=(
                    "A malformed line is excluded from chain verification, so "
                    "the chain result covers the parseable entries only.",
                ),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def provenance_coverage(
    *,
    trust_store_supplied: bool,
    anchor_supplied: bool,
    replay_database_supplied: bool,
    expectations_supplied: bool,
) -> list[CoverageEntry]:
    """Coverage for Module 3's attack classes, conditioned on what was supplied.

    Every one of these degrades to ``PARTIAL`` or ``NOT_ASSESSED`` when its
    precondition is absent, because the alternative is a report that reads as
    clean on the strength of a check that never ran.
    """
    entries: list[CoverageEntry] = []

    entries.append(
        coverage_entry(
            "inference_tampering",
            Coverage.SUPPORTED if expectations_supplied else Coverage.PARTIAL,
            detector=METHOD,
            detector_version=METHOD_VERSION,
            reason=(
                None
                if expectations_supplied
                else "no independent expectation (input artifact, model manifest, "
                "configuration or output) was supplied, so only the record's "
                "internal consistency and its signature were checked. A forger "
                "holding a signing key can emit a perfectly consistent record "
                "about the wrong artifacts, and nothing here would contradict it"
            ),
            assumptions=(
                "SHA-256 collision resistance and Ed25519 unforgeability hold.",
                "The verifying host is not under adversary control.",
            ),
            limitations=(
                "Binding proves that the record describes these artifacts. It "
                "does not prove the inference was actually executed -- a "
                "producer able to sign can sign a record for an inference it "
                "never ran.",
            ),
        )
    )

    entries.append(
        coverage_entry(
            "inference_replay",
            Coverage.PARTIAL if replay_database_supplied else Coverage.NOT_ASSESSED,
            detector=METHOD,
            detector_version=METHOD_VERSION,
            reason=(
                "detection is bounded by the local replay database's retention "
                "and by the integrity of that database, which an adversary with "
                "write access to the verifying host could roll back"
                if replay_database_supplied
                else "no replay database was supplied. A valid signature does "
                "not establish that an inference happened once; detecting a "
                "second presentation requires a record of what has been seen"
            ),
            assumptions=(
                "The replay database has not been rolled back or pruned across "
                "the period in question.",
            ),
            limitations=(
                "Exact re-presentation, nonce reuse and sequence collision are "
                "detected. The same input legitimately processed twice is NOT "
                "replay and is reported as an observation.",
                "A verifier that sees the replayed copy first records it as the "
                "original; presentation order is not locally establishable.",
            ),
        )
    )

    entries.append(
        coverage_entry(
            "record_reordering",
            Coverage.SUPPORTED,
            detector=METHOD,
            detector_version=METHOD_VERSION,
            assumptions=("SHA-256 collision resistance holds.",),
            limitations=(
                "Covers modification, insertion, deletion, reordering and "
                "duplication within the log presented. Tail truncation is a "
                "separate attack class because it is not detectable by linkage.",
            ),
        )
    )

    entries.append(
        coverage_entry(
            "provenance_key_trust",
            Coverage.PARTIAL if trust_store_supplied else Coverage.NOT_ASSESSED,
            detector=METHOD,
            detector_version=METHOD_VERSION,
            reason=(
                "key authority is an administrative fact recorded locally; the "
                "guarantee is only as strong as the channel the operator used to "
                "obtain each key"
                if trust_store_supplied
                else "no trust store was supplied, so every key is UNKNOWN and "
                "authenticity was not assessed. A cryptographically valid "
                "signature from an unauthorised key is indistinguishable from an "
                "authorised one without one"
            ),
            assumptions=(
                "Each trusted key was obtained through a channel independent of "
                "the one that supplied the records.",
            ),
            limitations=(
                "There is no revocation service. Revocation is effective only "
                "once an operator records it in this store.",
                "This software cannot protect a private key from a compromised "
                "signing host.",
            ),
        )
    )

    entries.append(
        coverage_entry(
            "chain_truncation",
            Coverage.PARTIAL if anchor_supplied else Coverage.NOT_ASSESSED,
            detector=METHOD,
            detector_version=METHOD_VERSION,
            reason=(
                "assessed against the supplied anchor; the guarantee holds only "
                "for entries written before the anchor was taken"
                if anchor_supplied
                else "no log anchor was supplied. A chain truncated at the end "
                "is internally perfect and cannot be distinguished from a "
                "shorter honest log. Front truncation IS detected, by the "
                "genesis rule"
            ),
            assumptions=(
                "The anchor is held somewhere the log's producer cannot write.",
            ),
            limitations=(
                "Entries written after the anchor was taken are outside its "
                "scope and their removal is undetectable.",
            ),
        )
    )
    return entries


__all__ = [
    "METHOD", "METHOD_VERSION", "FAILURE_POLICY", "FAILURE_TITLE",
    "FAILURE_PRECONDITION",
    "findings_for_record", "findings_for_chain", "malformed_entry_findings",
    "provenance_coverage", "record_asset",
]
