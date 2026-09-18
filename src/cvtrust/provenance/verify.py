"""Record verification: structured evidence, never a boolean.

``PASS`` / ``FAIL`` is the wrong shape for this answer.  "The signature is valid,
the key is unknown, the output digest matches the artifact on disk and the model
digest does not" is four separate facts, and an analyst acts on *which* of them
failed.  Collapsing them loses the only information that determines what to do
next — exactly the argument ADR-012 made for Module 2's assessment matrix, one
layer down.

So verification produces a list of :class:`VerificationCheck` values, each with
its own outcome and its own observation, and a set of
:class:`FailureCode` values summarising them.  **Every check runs.**  Nothing
short-circuits on the first failure: an adversary who could make verification
stop early could hide every later fact, and an analyst looking at a
single-failure report cannot tell whether the rest was clean or simply never
examined.

Three independent sources of truth
----------------------------------
1. **The record itself** — self-consistency. Does the stored configuration hash
   to the stored configuration digest? Does the output hash to the output
   digest? Does the record id match the record's content? These need nothing
   external and catch a forger who edited a field and re-signed with their own
   key but did not recompute the derived values.
2. **The signature and the trust store** — authenticity. Did someone with a
   private key produce these bytes, and is that key one the operator trusts?
   Two separate questions, two separate checks, and the second is never implied
   by the first.
3. **The expectation** — correspondence with reality. Does the record's input
   digest match the image the analyst actually holds? Its model digest, the
   model they actually assured? Absent expectations are reported
   ``NOT_CHECKED``, never as passes.

That third source is what makes model and input substitution detectable even
when the cryptography is flawless, because an attacker who controls the signing
key produces perfectly valid records about the wrong artifacts.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import utc_now_iso
from .binding import ConfigBinding
from .record import (
    SUPPORTED_SCHEMA_VERSIONS,
    ProvenanceRecord,
    SignedRecord,
)
from .replay import ReplayDatabase, ReplayResult, ReplayVerdict, detect_replay
from .signing import SignatureOutcome, verify_signature
from .trust import KeyPurpose, KeyStatus, TrustStore, ValidityPolicy

VERIFICATION_SCHEMA_VERSION = "1.0"


class FailureCode(str, Enum):
    """The closed failure taxonomy.

    A record may carry several of these at once, and the report lists all of
    them.  ``VALID`` is the absence of the others, and is never mixed with one.
    """

    VALID = "VALID"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    MISSING_SIGNATURE = "MISSING_SIGNATURE"
    MALFORMED_SIGNATURE = "MALFORMED_SIGNATURE"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    REVOKED_KEY = "REVOKED_KEY"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_NOT_YET_VALID = "KEY_NOT_YET_VALID"
    KEY_PURPOSE_MISMATCH = "KEY_PURPOSE_MISMATCH"
    INPUT_MISMATCH = "INPUT_MISMATCH"
    MODEL_MISMATCH = "MODEL_MISMATCH"
    CONFIGURATION_MISMATCH = "CONFIGURATION_MISMATCH"
    OUTPUT_MISMATCH = "OUTPUT_MISMATCH"
    SELF_INCONSISTENT_RECORD = "SELF_INCONSISTENT_RECORD"
    CHAIN_BREAK = "CHAIN_BREAK"
    REPLAY = "REPLAY"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    MISSING_FIELD = "MISSING_FIELD"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"


#: Failure codes that concern **authenticity**: the record is intact, but the
#: operator has not authorised whoever signed it.  Separated because the remedy
#: differs -- an integrity failure means the artifact changed, a trust failure
#: means a key needs provisioning, revoking or rotating.
TRUST_FAILURES: frozenset[FailureCode] = frozenset({
    FailureCode.UNKNOWN_KEY,
    FailureCode.REVOKED_KEY,
    FailureCode.KEY_EXPIRED,
    FailureCode.KEY_NOT_YET_VALID,
    FailureCode.KEY_PURPOSE_MISMATCH,
})

#: Failure codes that concern **context**: the record is intact and properly
#: signed, and the objection is to something outside it.  A replayed record has
#: a perfect signature over unaltered bytes; what is wrong is that it has been
#: presented before, which is a fact about the verifier's memory rather than
#: about the record.  Folding it in with integrity would tell an analyst to go
#: looking for an edit that never happened.
CONTEXT_FAILURES: frozenset[FailureCode] = frozenset({
    FailureCode.REPLAY,
})


class CheckOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    #: The check does not apply to this record (e.g. genesis has no predecessor).
    NOT_APPLICABLE = "NOT_APPLICABLE"
    #: The check could have applied but the input it needs was not supplied.
    #: Never to be read as a pass.
    NOT_CHECKED = "NOT_CHECKED"
    #: Observed and reported, but not a pass/fail judgement.
    OBSERVED = "OBSERVED"


class VerificationCheck(BaseModel):
    """One named check with its outcome and the values behind it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    outcome: CheckOutcome
    detail: str
    observation: Mapping[str, Any] = Field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.outcome is CheckOutcome.FAIL


class ExpectedBinding(BaseModel):
    """What the analyst independently holds to be true.

    Every field is optional, and every absent field produces a ``NOT_CHECKED``
    result rather than silence.  This is the object that turns "the record is
    internally consistent and properly signed" into "the record describes the
    artifacts I actually have".
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    raw_input_digest: str | None = None
    normalized_input_digest: str | None = None
    model_file_sha256: str | None = None
    model_graph_digest: str | None = None
    model_parameter_digest: str | None = None
    model_id: str | None = None
    preprocessing_digest: str | None = None
    inference_digest: str | None = None
    output_digest: str | None = None
    log_id: str | None = None
    source: str | None = Field(
        default=None,
        description="Where these expectations came from: a Module 2 manifest, a "
        "file on disk, an operator declaration. Recorded because an expectation "
        "taken from the same source as the record proves nothing.",
    )

    def any_supplied(self) -> bool:
        return any(
            value is not None
            for field_name, value in self.model_dump().items()
            if field_name != "source"
        )

    @classmethod
    def from_model_manifest(cls, manifest: Any, **overrides: Any) -> "ExpectedBinding":
        """Build expectations from a Module 2 model manifest.

        Module 3 does not recompute model identity; it compares against Module
        2's, so a mismatch reported here and one reported by ``cvtrust model
        verify`` are statements about the same three digests.
        """
        return cls(
            model_id=manifest.model_id,
            model_file_sha256=manifest.file_sha256,
            model_graph_digest=manifest.graph_digest,
            model_parameter_digest=manifest.parameter_digest,
            source=f"model manifest {manifest.manifest_id}",
            **overrides,
        )


class RecordVerification(BaseModel):
    """The full, structured result for one record."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = VERIFICATION_SCHEMA_VERSION
    record_id: str | None
    entry_digest: str | None
    position: int | None = None
    verified_at: str = Field(default_factory=utc_now_iso)

    checks: tuple[VerificationCheck, ...]
    failures: tuple[FailureCode, ...]

    signing_key_id: str | None = None
    key_status: KeyStatus = KeyStatus.UNKNOWN
    key_label: str | None = None
    replay_verdict: ReplayVerdict = ReplayVerdict.NOT_CHECKED
    validity_policy: ValidityPolicy = ValidityPolicy.AT_RECORD_TIMESTAMP

    @property
    def valid(self) -> bool:
        """No failure of any kind.

        Note what this does *not* mean: a valid record is a record whose
        bindings hold and whose signer the operator trusts. It is not a
        statement that the inference was correct, that the model is sound, or
        that the input was what it should have been — only that nobody altered
        the account of it.
        """
        return self.failures == (FailureCode.VALID,)

    @property
    def cryptographically_intact(self) -> bool:
        """The record's own integrity holds: signature, digests and bindings.

        Deliberately blind to trust and to replay, because those are objections
        to the *signer* and to the *context*, not to the record.  "Correctly
        signed by a key we have never authorised" and "a genuine record we have
        already seen" are both specific, common and actionable states, and a
        single boolean that lumped them in with "the bytes were edited" would
        send an analyst looking for an edit that never happened.

        :attr:`valid` is the conjunction of all three.
        """
        integrity = (
            set(self.failures)
            - TRUST_FAILURES
            - CONTEXT_FAILURES
            - {FailureCode.VALID}
        )
        return not integrity

    def failed_checks(self) -> tuple[VerificationCheck, ...]:
        return tuple(c for c in self.checks if c.failed)

    def check(self, name: str) -> VerificationCheck | None:
        for item in self.checks:
            if item.name == name:
                return item
        return None

    def evidence_map(self) -> dict[str, str]:
        """``{check name: outcome}`` — the compact form the report prints."""
        return {c.name: c.outcome.value for c in self.checks}


def verify_record(
    signed: SignedRecord,
    *,
    trust_store: TrustStore | None = None,
    expected: ExpectedBinding | None = None,
    replay_database: ReplayDatabase | None = None,
    validity_policy: ValidityPolicy = ValidityPolicy.AT_RECORD_TIMESTAMP,
    required_purpose: KeyPurpose = KeyPurpose.INFERENCE_PROVENANCE,
    chain_result: Any | None = None,
    position: int | None = None,
) -> RecordVerification:
    """Run every check against one record and return all of the evidence."""
    record = signed.record
    checks: list[VerificationCheck] = []
    failures: set[FailureCode] = set()

    _check_schema(record, checks, failures)
    _check_record_identity(record, checks, failures)
    _check_self_consistency(record, checks, failures)
    _check_required_fields(record, checks, failures)

    key_status, key_label = _check_signature_and_trust(
        signed, trust_store, validity_policy, required_purpose, checks, failures
    )

    _check_expectations(record, expected, checks, failures)
    replay = _check_replay(signed, replay_database, checks, failures)
    _check_chain_membership(chain_result, position, checks, failures)

    if not failures:
        failures.add(FailureCode.VALID)

    return RecordVerification(
        record_id=record.record_id,
        entry_digest=signed.entry_digest(),
        position=position,
        checks=tuple(checks),
        failures=tuple(sorted(failures, key=lambda f: f.value)),
        signing_key_id=signed.signature.key_id if signed.signature else None,
        key_status=key_status,
        key_label=key_label,
        replay_verdict=replay.verdict,
        validity_policy=validity_policy,
    )


# ---------------------------------------------------------------------------
# 1. The record on its own terms
# ---------------------------------------------------------------------------


def _check_schema(
    record: ProvenanceRecord,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    supported = record.schema_supported()
    checks.append(
        VerificationCheck(
            name="schema_supported",
            outcome=CheckOutcome.PASS if supported else CheckOutcome.FAIL,
            detail=(
                f"record schema {record.schema_version} is implemented by this build"
                if supported
                else f"record schema {record.schema_version} is not implemented by "
                "this build; verifying it would mean guessing what its fields "
                "mean, and a guess that happens to pass is worse than a refusal"
            ),
            observation={
                "record_schema_version": record.schema_version,
                "supported_versions": sorted(SUPPORTED_SCHEMA_VERSIONS),
            },
        )
    )
    if not supported:
        failures.add(FailureCode.UNSUPPORTED_SCHEMA)


def _check_record_identity(
    record: ProvenanceRecord,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    expected_id = record.expected_record_id()
    consistent = record.record_id == expected_id
    checks.append(
        VerificationCheck(
            name="record_id_matches_content",
            outcome=CheckOutcome.PASS if consistent else CheckOutcome.FAIL,
            detail=(
                "the record id is the content digest of the record"
                if consistent
                else f"the record calls itself {record.record_id} but its content "
                f"digests to {expected_id}; the record has been altered or "
                "relabelled"
            ),
            observation={
                "declared_record_id": record.record_id,
                "derived_record_id": expected_id,
                "record_digest": record.record_digest(),
            },
        )
    )
    if not consistent:
        failures.add(FailureCode.SELF_INCONSISTENT_RECORD)


def _check_self_consistency(
    record: ProvenanceRecord,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    """Do the record's own digests hash its own inline content?

    This is what catches a forger who re-signed with their own key: the
    signature verifies, but a digest field they edited without recomputing, or
    an inline payload they edited without updating its digest, still gives them
    away.
    """
    for name, binding, code in (
        ("preprocessing_digest_self_consistent", record.preprocessing,
         FailureCode.CONFIGURATION_MISMATCH),
        ("inference_config_digest_self_consistent", record.inference,
         FailureCode.CONFIGURATION_MISMATCH),
    ):
        _self_consistency_check(name, binding, code, checks, failures)

    output_ok = record.output.self_consistent()
    checks.append(
        VerificationCheck(
            name="output_digest_self_consistent",
            outcome=CheckOutcome.PASS if output_ok else CheckOutcome.FAIL,
            detail=(
                "the recorded output digest is the digest of the recorded output"
                if output_ok
                else "the recorded output digest does not hash the output carried "
                "in the same record: one of the two was altered"
            ),
            observation={
                "declared_digest": record.output.digest,
                "recomputed_digest": record.output.recompute_digest(),
                "task": record.output.output.task.value,
                "ordering_policy": record.output.output.ordering_policy,
                "quantization_places": record.output.output.quantization_places,
            },
        )
    )
    if not output_ok:
        failures.add(FailureCode.OUTPUT_MISMATCH)


def _self_consistency_check(
    name: str,
    binding: ConfigBinding,
    code: FailureCode,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    ok = binding.self_consistent()
    checks.append(
        VerificationCheck(
            name=name,
            outcome=CheckOutcome.PASS if ok else CheckOutcome.FAIL,
            detail=(
                "the recorded digest is the digest of the recorded configuration"
                if ok
                else "the recorded digest does not hash the configuration carried "
                "in the same record: one of the two was altered"
            ),
            observation={
                "declared_digest": binding.digest,
                "recomputed_digest": binding.recompute_digest(),
                "quantization_places": binding.quantization_places,
            },
        )
    )
    if not ok:
        failures.add(code)


def _check_required_fields(
    record: ProvenanceRecord,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    """Are the fields whose *presence* is itself a claim actually present?

    Pydantic already enforces the schema, so these are the fields a
    schema-valid record can still leave empty — and each absence weakens a
    specific guarantee, so each is reported rather than defaulted.
    """
    missing: list[str] = []
    if not record.nonce.strip():
        missing.append("nonce")
    if not record.timestamp.strip():
        missing.append("timestamp")
    if not record.sequence.log_id.strip():
        missing.append("sequence.log_id")

    checks.append(
        VerificationCheck(
            name="required_fields_present",
            outcome=CheckOutcome.PASS if not missing else CheckOutcome.FAIL,
            detail=(
                "nonce, timestamp and log id are all present"
                if not missing
                else f"missing or empty: {', '.join(missing)}"
            ),
            observation={"missing": missing},
        )
    )
    if missing:
        failures.add(FailureCode.MISSING_FIELD)

    # Presence, not truth. A timestamp establishes only that the producer
    # asserted it, so it is reported as an observation and never as a pass.
    checks.append(
        VerificationCheck(
            name="timestamp_present",
            outcome=CheckOutcome.OBSERVED,
            detail=(
                f"the record asserts {record.timestamp}. This is the producer's "
                "own clock, signed: it establishes that this time was included "
                "in the signed record, not when the inference happened. There is "
                "no timestamp authority in an offline deployment"
            ),
            observation={
                "timestamp": record.timestamp,
                "establishes": "inclusion in the signed record",
                "does_not_establish": "wall-clock truth",
            },
        )
    )
    checks.append(
        VerificationCheck(
            name="nonce_present",
            outcome=CheckOutcome.OBSERVED,
            detail=(
                f"the record carries a {len(record.nonce) * 4}-bit nonce. A nonce "
                "makes two legitimately distinct inferences over the same input "
                "distinguishable; on its own it does not prevent replay"
            ),
            observation={"nonce_bits": len(record.nonce) * 4, "nonce": record.nonce},
        )
    )


# ---------------------------------------------------------------------------
# 2. Authenticity: signature, then trust, never one implying the other
# ---------------------------------------------------------------------------


def _check_signature_and_trust(
    signed: SignedRecord,
    trust_store: TrustStore | None,
    validity_policy: ValidityPolicy,
    required_purpose: KeyPurpose,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> tuple[KeyStatus, str | None]:
    signature_check = verify_signature(signed)
    outcome_map = {
        SignatureOutcome.VALID: (CheckOutcome.PASS, None),
        SignatureOutcome.INVALID: (CheckOutcome.FAIL, FailureCode.INVALID_SIGNATURE),
        SignatureOutcome.MALFORMED: (CheckOutcome.FAIL, FailureCode.MALFORMED_SIGNATURE),
        SignatureOutcome.MISSING: (CheckOutcome.FAIL, FailureCode.MISSING_SIGNATURE),
        SignatureOutcome.UNSUPPORTED_ALGORITHM: (
            CheckOutcome.FAIL, FailureCode.MALFORMED_SIGNATURE
        ),
    }
    outcome, code = outcome_map[signature_check.outcome]
    checks.append(
        VerificationCheck(
            name="signature_valid",
            outcome=outcome,
            detail=signature_check.detail,
            observation={
                "signature_outcome": signature_check.outcome.value,
                "key_id": signature_check.key_id,
                "algorithm": signature_check.algorithm,
                "key_id_fingerprints_public_key": signature_check.key_id_consistent,
                "establishes": (
                    "the holder of the matching private key produced these bytes"
                    if signature_check.valid
                    else "nothing"
                ),
            },
        )
    )
    if code is not None:
        failures.add(code)

    key_id = signature_check.key_id
    if key_id is None:
        checks.append(
            VerificationCheck(
                name="key_known",
                outcome=CheckOutcome.NOT_APPLICABLE,
                detail="the record names no key, so there is nothing to look up",
                observation={"key_id": None},
            )
        )
        checks.append(
            VerificationCheck(
                name="key_trusted",
                outcome=CheckOutcome.NOT_APPLICABLE,
                detail="no key to trust",
                observation={"key_id": None},
            )
        )
        return KeyStatus.UNKNOWN, None

    if trust_store is None:
        for name in ("key_known", "key_trusted"):
            checks.append(
                VerificationCheck(
                    name=name,
                    outcome=CheckOutcome.NOT_CHECKED,
                    detail=(
                        "no trust store was supplied, so key authority was not "
                        "assessed. A cryptographically valid signature from an "
                        "unauthorised key is indistinguishable from an "
                        "authorised one without a trust store"
                    ),
                    observation={"key_id": key_id, "trust_store_supplied": False},
                )
            )
        failures.add(FailureCode.UNKNOWN_KEY)
        return KeyStatus.UNKNOWN, None

    if signature_check.key_id_consistent is False:
        # The envelope names one key and carries another. Looking the *named*
        # key up would report "key trusted" for a record that key did not sign,
        # which is precisely the confusion the forgery is trying to create.
        # There is no established signer here, so there is no key to trust.
        for name in ("key_known", "key_trusted"):
            checks.append(
                VerificationCheck(
                    name=name,
                    outcome=CheckOutcome.NOT_APPLICABLE,
                    detail=(
                        "the envelope names a key that did not sign this record, "
                        "so no signer is established and there is nothing to look "
                        "up. Resolving the declared key_id against the trust store "
                        "would report the named key's status for a record it did "
                        "not sign"
                    ),
                    observation={
                        "declared_key_id": key_id,
                        "key_id_fingerprints_public_key": False,
                    },
                )
            )
        failures.add(FailureCode.UNKNOWN_KEY)
        return KeyStatus.UNKNOWN, None

    entry = trust_store.get(key_id)
    known = entry is not None
    checks.append(
        VerificationCheck(
            name="key_known",
            outcome=CheckOutcome.PASS if known else CheckOutcome.FAIL,
            detail=(
                f"key {key_id[:16]}… is present in the trust store"
                if known
                else f"key {key_id[:16]}… is not in the trust store. The signature "
                "may still be cryptographically valid: anyone can generate a "
                "keypair, so validity without authority establishes nothing"
            ),
            observation={
                "key_id": key_id,
                "present_in_store": known,
                "store_key_count": len(trust_store.keys),
                "trusted_key_count": len(trust_store.trusted_ids()),
            },
        )
    )
    if not known:
        failures.add(FailureCode.UNKNOWN_KEY)
        checks.append(
            VerificationCheck(
                name="key_trusted",
                outcome=CheckOutcome.FAIL,
                detail="an unknown key is not a trusted key",
                observation={"key_id": key_id, "status": KeyStatus.UNKNOWN.value},
            )
        )
        return KeyStatus.UNKNOWN, None

    assert entry is not None
    status = entry.status
    trusted = status is KeyStatus.TRUSTED
    checks.append(
        VerificationCheck(
            name="key_trusted",
            outcome=CheckOutcome.PASS if trusted else CheckOutcome.FAIL,
            detail=(
                f"key {entry.short_id()} ({entry.label or 'unlabelled'}) is TRUSTED "
                "in this store"
                if trusted
                else f"key {entry.short_id()} is recorded as {status.value}"
                + (
                    f" since {entry.revoked_at}: {entry.revocation_reason}"
                    if entry.revoked_at
                    else ""
                )
            ),
            observation={
                "key_id": key_id,
                "status": status.value,
                "label": entry.label,
                "revoked_at": entry.revoked_at,
                "revocation_reason": entry.revocation_reason,
                "key_provenance": entry.provenance,
            },
        )
    )
    if status is KeyStatus.REVOKED:
        failures.add(FailureCode.REVOKED_KEY)
        # Revocation is absolute, but whether the record *claims* to predate it
        # is a distinct fact an analyst needs, so it is reported rather than
        # folded into the verdict.
        claims_before = (
            entry.revoked_at is not None
            and signed.record.timestamp < entry.revoked_at
        )
        checks.append(
            VerificationCheck(
                name="signed_before_revocation",
                outcome=CheckOutcome.OBSERVED,
                detail=(
                    "the record's self-asserted timestamp precedes the recorded "
                    "revocation. That is a claim by the record, not a fact: a "
                    "holder of a revoked key can choose the timestamp too"
                    if claims_before
                    else "the record's self-asserted timestamp does not precede "
                    "the recorded revocation"
                ),
                observation={
                    "record_timestamp": signed.record.timestamp,
                    "revoked_at": entry.revoked_at,
                    "claims_to_predate_revocation": claims_before,
                    "timestamp_is_self_asserted": True,
                },
            )
        )
    elif status is KeyStatus.UNKNOWN:
        failures.add(FailureCode.UNKNOWN_KEY)

    _check_key_window(
        entry, signed.record, validity_policy, checks, failures
    )
    _check_key_purpose(entry, required_purpose, checks, failures)
    return status, entry.label


def _check_key_window(
    entry: Any,
    record: ProvenanceRecord,
    policy: ValidityPolicy,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    moment = (
        record.timestamp
        if policy is ValidityPolicy.AT_RECORD_TIMESTAMP
        else utc_now_iso()
    )
    inside = entry.window_contains(moment)
    if entry.valid_from is None and entry.valid_until is None:
        checks.append(
            VerificationCheck(
                name="key_within_validity_window",
                outcome=CheckOutcome.NOT_APPLICABLE,
                detail="this key has no validity window recorded",
                observation={"key_id": entry.key_id, "policy": policy.value},
            )
        )
        return

    if inside is None:
        checks.append(
            VerificationCheck(
                name="key_within_validity_window",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"the moment to evaluate ({moment!r}) could not be parsed as "
                    "an instant, so the key's validity window could not be "
                    "applied. An unparseable timestamp does not satisfy a window"
                ),
                observation={
                    "key_id": entry.key_id,
                    "policy": policy.value,
                    "moment": moment,
                    "valid_from": entry.valid_from,
                    "valid_until": entry.valid_until,
                },
            )
        )
        failures.add(FailureCode.MALFORMED_RECORD)
        return

    detail_common = {
        "key_id": entry.key_id,
        "policy": policy.value,
        "evaluated_at": moment,
        "valid_from": entry.valid_from,
        "valid_until": entry.valid_until,
        "timestamp_is_self_asserted": policy is ValidityPolicy.AT_RECORD_TIMESTAMP,
    }
    if inside:
        checks.append(
            VerificationCheck(
                name="key_within_validity_window",
                outcome=CheckOutcome.PASS,
                detail=(
                    f"the key was valid under the {policy.value} policy"
                    + (
                        ". Note that this moment is the record's own claim, so a "
                        "holder of an expired key could backdate into the window"
                        if policy is ValidityPolicy.AT_RECORD_TIMESTAMP
                        else ""
                    )
                ),
                observation=detail_common,
            )
        )
        return

    before = entry.valid_from is not None and moment < entry.valid_from
    checks.append(
        VerificationCheck(
            name="key_within_validity_window",
            outcome=CheckOutcome.FAIL,
            detail=(
                # The moment itself is in the observation: under the
                # at_verification_time policy it is the verifier's clock, and
                # quoting it here would make two identical reports differ.
                "the key was not yet valid at the moment the policy evaluated"
                if before
                else "the key's validity had ended by the moment the policy "
                "evaluated"
            ),
            observation=detail_common,
        )
    )
    failures.add(
        FailureCode.KEY_NOT_YET_VALID if before else FailureCode.KEY_EXPIRED
    )


def _check_key_purpose(
    entry: Any,
    required: KeyPurpose,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    ok = entry.purpose in (required, KeyPurpose.ANY) or required is KeyPurpose.ANY
    checks.append(
        VerificationCheck(
            name="key_purpose_permitted",
            outcome=CheckOutcome.PASS if ok else CheckOutcome.FAIL,
            detail=(
                f"the key is authorised for {entry.purpose.value}"
                if ok
                else f"the key is authorised for {entry.purpose.value}, not "
                f"{required.value}. A key trusted to sign inference records is "
                "not thereby trusted to attest that a log is complete"
            ),
            observation={
                "key_id": entry.key_id,
                "key_purpose": entry.purpose.value,
                "required_purpose": required.value,
            },
        )
    )
    if not ok:
        failures.add(FailureCode.KEY_PURPOSE_MISMATCH)


# ---------------------------------------------------------------------------
# 3. Correspondence with what the analyst independently holds
# ---------------------------------------------------------------------------

#: ``(check name, record accessor, expectation field, failure code, subject)``.
#: A table rather than an if-chain, so that adding a bound field cannot
#: accidentally skip its failure code.
_EXPECTATION_FIELDS: tuple[tuple[str, str, str, FailureCode, str], ...] = (
    ("input_digest_match", "input.raw_input_digest", "raw_input_digest",
     FailureCode.INPUT_MISMATCH, "the raw bytes of the input artifact"),
    ("normalized_input_digest_match", "input.normalized_input_digest",
     "normalized_input_digest", FailureCode.INPUT_MISMATCH,
     "the preprocessed input tensor"),
    ("model_digest_match", "model.file_sha256", "model_file_sha256",
     FailureCode.MODEL_MISMATCH, "the model artifact's bytes"),
    ("model_graph_digest_match", "model.graph_digest", "model_graph_digest",
     FailureCode.MODEL_MISMATCH, "the model's graph"),
    ("model_parameter_digest_match", "model.parameter_digest",
     "model_parameter_digest", FailureCode.MODEL_MISMATCH, "the model's weights"),
    ("model_id_match", "model.model_id", "model_id",
     FailureCode.MODEL_MISMATCH, "the model's content-addressed id"),
    ("preprocessing_digest_match", "preprocessing.digest", "preprocessing_digest",
     FailureCode.CONFIGURATION_MISMATCH, "the preprocessing configuration"),
    ("inference_config_digest_match", "inference.digest", "inference_digest",
     FailureCode.CONFIGURATION_MISMATCH, "the inference configuration"),
    ("output_digest_match", "output.digest", "output_digest",
     FailureCode.OUTPUT_MISMATCH, "the inference output"),
    ("log_id_match", "sequence.log_id", "log_id",
     FailureCode.MALFORMED_RECORD, "the log this record belongs to"),
)


def _resolve(record: ProvenanceRecord, dotted: str) -> Any:
    value: Any = record
    for part in dotted.split("."):
        value = getattr(value, part)
    return value


def _check_expectations(
    record: ProvenanceRecord,
    expected: ExpectedBinding | None,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    for name, accessor, field_name, code, subject in _EXPECTATION_FIELDS:
        recorded = _resolve(record, accessor)
        wanted = getattr(expected, field_name) if expected else None

        if wanted is None:
            checks.append(
                VerificationCheck(
                    name=name,
                    outcome=CheckOutcome.NOT_CHECKED,
                    detail=(
                        f"no independent expectation for {subject} was supplied, "
                        "so the record's claim about it was not corroborated. "
                        "The record's internal consistency does not establish "
                        "that it describes the artifact you hold"
                    ),
                    observation={"recorded": recorded, "expected": None},
                )
            )
            continue

        if recorded is None:
            checks.append(
                VerificationCheck(
                    name=name,
                    outcome=CheckOutcome.FAIL,
                    detail=(
                        f"an expectation for {subject} was supplied but the "
                        "record binds no value for it, so the expectation cannot "
                        "be satisfied"
                    ),
                    observation={"recorded": None, "expected": wanted},
                )
            )
            failures.add(FailureCode.MISSING_FIELD)
            continue

        match = recorded == wanted
        checks.append(
            VerificationCheck(
                name=name,
                outcome=CheckOutcome.PASS if match else CheckOutcome.FAIL,
                detail=(
                    f"the record's binding for {subject} matches the independently "
                    "held value"
                    if match
                    else f"the record binds {str(recorded)[:24]}… for {subject}, "
                    f"but the independently held value is {str(wanted)[:24]}…"
                ),
                observation={
                    "recorded": recorded,
                    "expected": wanted,
                    "match": match,
                    "expectation_source": expected.source if expected else None,
                },
            )
        )
        if not match:
            failures.add(code)


# ---------------------------------------------------------------------------
# 4. Replay and chain membership
# ---------------------------------------------------------------------------


def _check_replay(
    signed: SignedRecord,
    database: ReplayDatabase | None,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> ReplayResult:
    result = detect_replay(signed, database)
    if result.verdict is ReplayVerdict.NOT_CHECKED:
        outcome = CheckOutcome.NOT_CHECKED
    elif result.is_replay:
        outcome = CheckOutcome.FAIL
    elif result.verdict is ReplayVerdict.DUPLICATE_SUBJECT:
        # Explicitly an observation, not a failure. The same image processed
        # twice is normal and must never be reported as an attack.
        outcome = CheckOutcome.OBSERVED
    else:
        outcome = CheckOutcome.PASS

    checks.append(
        VerificationCheck(
            name="replay_detected",
            outcome=outcome,
            detail=result.detail,
            observation={
                "verdict": result.verdict.value,
                "is_replay": result.is_replay,
                **result.observation,
            },
        )
    )
    if result.is_replay:
        failures.add(FailureCode.REPLAY)
    return result


def _check_chain_membership(
    chain_result: Any | None,
    position: int | None,
    checks: list[VerificationCheck],
    failures: set[FailureCode],
) -> None:
    if chain_result is None or position is None:
        checks.append(
            VerificationCheck(
                name="previous_record_valid",
                outcome=CheckOutcome.NOT_CHECKED,
                detail=(
                    "this record was verified on its own, not as part of a log, "
                    "so its position in a chain was not assessed. A record that "
                    "verifies in isolation can still have been removed from, "
                    "reordered within, or spliced into a log"
                ),
                observation={"chain_supplied": False},
            )
        )
        checks.append(
            VerificationCheck(
                name="sequence_valid",
                outcome=CheckOutcome.NOT_CHECKED,
                detail="no chain context; sequence position was not assessed",
                observation={"chain_supplied": False},
            )
        )
        return

    link = next(
        (item for item in chain_result.links if item.position == position), None
    )
    if link is None:  # pragma: no cover - defensive
        return

    linked = link.link_status.value in ("GENESIS", "LINKED")
    checks.append(
        VerificationCheck(
            name="previous_record_valid",
            outcome=CheckOutcome.PASS if linked else CheckOutcome.FAIL,
            detail=link.detail,
            observation={
                "position": link.position,
                "link_status": link.link_status.value,
                "declared_previous_digest": link.declared_previous_digest,
                "expected_previous_digest": link.expected_previous_digest,
                "entry_digest": link.entry_digest,
            },
        )
    )
    checks.append(
        VerificationCheck(
            name="sequence_valid",
            outcome=CheckOutcome.PASS if link.sequence_valid else CheckOutcome.FAIL,
            detail=(
                f"sequence number {link.sequence_number} is the expected "
                f"{link.sequence_expected} for this position"
                if link.sequence_valid
                else f"sequence number is {link.sequence_number} where "
                f"{link.sequence_expected} was expected for this position"
            ),
            observation={
                "sequence_number": link.sequence_number,
                "sequence_expected": link.sequence_expected,
            },
        )
    )
    if not (linked and link.sequence_valid):
        failures.add(FailureCode.CHAIN_BREAK)


__all__ = [
    "VERIFICATION_SCHEMA_VERSION", "FailureCode", "TRUST_FAILURES",
    "CONTEXT_FAILURES", "CheckOutcome",
    "VerificationCheck", "ExpectedBinding", "RecordVerification", "verify_record",
]
