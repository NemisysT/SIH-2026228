"""The canonical inference-provenance record, schema 1.0.

One record answers a single question:

    *Did this exact model, under this exact configuration, produce this exact
    output from this exact input — and who says so?*

It does not answer whether the model is trustworthy, whether the input was
in-distribution, or whether the output is correct.  Those are Module 1, 2 and 4
questions and mixing them in here would produce a number that means nothing
(§27 of the module brief, and ADR-012's argument one level up).

Layout
------

The record is split into two objects and that split is load-bearing:

``ProvenanceRecord``
    The signed payload.  Deterministic, float-free, self-contained.

``SignedRecord``
    The payload plus a detached signature envelope.  Kept separate so that the
    bytes that were signed are exactly the payload's canonical bytes, with no
    chicken-and-egg problem and no field that has to be blanked before hashing.

Two digests, for two different jobs
-----------------------------------

``record_digest``
    SHA-256 over the payload's canonical bytes with ``record_id`` removed.  This
    is the record's content identity, and ``record_id`` is derived from it, so a
    record cannot claim an id that does not match its own content.

``entry_digest``
    SHA-256 over the canonical bytes of ``{"record": payload, "signature": sig}``
    — payload *and* signature together.  This is what the hash chain links, so
    replacing a signature on an already-chained record breaks the chain rather
    than only failing that record's own signature check.  See
    :mod:`cvtrust.provenance.chain`.

Everything on the digest surface is float-free (ADR-004): confidences and
configuration values arrive already quantised onto a fixed decimal grid by
:mod:`cvtrust.provenance.output` and :mod:`cvtrust.provenance.binding`.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import canonical_json
from ..core.evidence import utc_now_iso
from ..core.hashing import HASH_ALGORITHM, short
from .binding import (
    ConfigBinding,
    ExecutionMetadata,
    InputBinding,
    ModelBinding,
    OutputBinding,
)

#: Version of the record schema.  A verifier refuses a major version it does not
#: implement rather than guessing, and reports UNSUPPORTED_SCHEMA.
PROVENANCE_SCHEMA_VERSION: Final[str] = "1.0"

#: Schema versions this build can verify.  Deliberately an explicit set, not a
#: comparison: "anything <= ours" assumes forward knowledge of what a future
#: minor version will mean, which is exactly the assumption that turns a schema
#: change into a silent verification bypass.
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({"1.0"})

#: Nonce width in bytes.  128 bits from the OS CSPRNG via :mod:`secrets`
#: (``getrandom(2)`` / ``/dev/urandom``), which needs no network and no seeding.
#: At 2^64 records the birthday bound gives a ~50% chance of one collision; a
#: deployment producing a million records a day would need roughly fifty million
#: years to get there, so the width is not the limiting factor — the replay
#: database's retention window is (see :mod:`cvtrust.provenance.replay`).
NONCE_BYTES: Final[int] = 16

#: Sequence number of the first record in a log.
GENESIS_SEQUENCE: Final[int] = 0


def new_nonce() -> str:
    """A fresh 128-bit nonce, hex-encoded.

    Uniqueness rests on the OS CSPRNG, not on this code.  A nonce alone does not
    prevent replay — it only makes two legitimately distinct inferences over the
    same input distinguishable.  Detecting an actual replay needs a record of
    what has been seen, which is the replay database's job, and that limitation
    is stated in ``docs/provenance.md`` §7 rather than papered over.
    """
    return secrets.token_hex(NONCE_BYTES)


class SequenceBinding(BaseModel):
    """Where this record sits in its log, and what it links back to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    log_id: str = Field(min_length=1, description="Identifier of the append-only log.")
    sequence_number: int = Field(ge=0)
    previous_record_digest: str | None = Field(
        default=None,
        description="entry_digest of the preceding entry; None only at genesis.",
    )


class ProvenanceRecord(BaseModel):
    """The signed payload.  Everything here is inside the signature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PROVENANCE_SCHEMA_VERSION
    record_id: str = Field(pattern=r"^PR-[0-9a-f]{16}$")
    hash_algorithm: str = HASH_ALGORITHM

    input: InputBinding
    model: ModelBinding
    preprocessing: ConfigBinding
    inference: ConfigBinding
    output: OutputBinding
    execution: ExecutionMetadata = ExecutionMetadata()
    sequence: SequenceBinding

    #: Producer's own clock, ISO-8601 UTC.  Signing this binds *that the
    #: producer asserted this time*, and nothing else.  There is no external
    #: timestamp authority in an air-gapped deployment, so the record carries a
    #: claim, and the verifier reports it as a claim.  See ``docs/provenance.md``
    #: §6 for exactly what the sequence number adds that the clock does not.
    timestamp: str = Field(min_length=1)
    nonce: str = Field(min_length=8)

    producer: str | None = Field(
        default=None,
        description="Operator-supplied producer label. UNTRUSTED; the signing "
        "key is the only thing that attributes a record.",
    )
    labels: dict[str, str] = Field(
        default_factory=dict,
        description="Free-form operator annotations. UNTRUSTED, but signed, so "
        "they cannot be altered after the fact without detection.",
    )

    # -- identity ----------------------------------------------------------

    def digest_payload(self) -> dict[str, Any]:
        """The structure ``record_digest`` is taken over: everything but the id."""
        payload = self.model_dump(mode="json")
        payload.pop("record_id", None)
        return payload

    def record_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.digest_payload())).hexdigest()

    def canonical_bytes(self) -> bytes:
        """The exact bytes a signature is computed over.

        Includes ``record_id``: the id is derived from the rest of the payload,
        so signing it costs nothing and closes the hole where a record could be
        re-labelled with a different id under the same signature.
        """
        return canonical_json(self.model_dump(mode="json"))

    def expected_record_id(self) -> str:
        return derive_record_id(self.record_digest())

    def record_id_consistent(self) -> bool:
        return self.record_id == self.expected_record_id()

    def schema_supported(self) -> bool:
        return self.schema_version in SUPPORTED_SCHEMA_VERSIONS

    def subject_key(self) -> str:
        """What this record is *about*: input, model and configuration.

        Two records with the same subject key describe the same inference
        subject.  That is emphatically **not** the same as a replay — the same
        image legitimately processed twice has one subject key and two records —
        and the two are kept apart by name for that reason.
        """
        return hashlib.sha256(
            canonical_json(
                {
                    "input": self.input.raw_input_digest,
                    "model": self.model.file_sha256,
                    "preprocessing": self.preprocessing.digest,
                    "inference": self.inference.digest,
                }
            )
        ).hexdigest()


def derive_record_id(record_digest: str) -> str:
    """``PR-`` plus the first 16 hex characters of the record digest.

    Truncated, and therefore a *label*: every integrity comparison in this
    module uses the full 64-character digest.  Same rule as Module 1's finding
    ids (``core/hashing.short``).
    """
    return f"PR-{short(record_digest, 16)}"


class SignatureEnvelope(BaseModel):
    """A detached Ed25519 signature over a record's canonical bytes.

    The public key travels with the signature, and that is a deliberate,
    documented trade:

    * it lets a verifier distinguish **invalid signature** from **valid
      signature by an unknown key**, which the failure taxonomy requires and
      which is impossible if the key is only discoverable through the trust
      store;
    * it means a cryptographically valid signature, on its own, proves nothing
      at all — anyone can mint a key.  Trust comes from the trust store and
      nowhere else.

    ``key_id`` is SHA-256 over the raw 32-byte public key, so the envelope's own
    key id can be checked against the key it carries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = "ed25519"
    key_id: str = Field(min_length=64, max_length=64)
    public_key: str = Field(
        min_length=64, max_length=64,
        description="Raw 32-byte Ed25519 public key, hex. See the class note on "
        "why carrying it is safe and what it does not establish.",
    )
    signature: str = Field(min_length=128, max_length=128, description="Hex Ed25519 signature.")
    signed_at: str | None = Field(
        default=None,
        description="Signer's own clock. UNTRUSTED, and -- unlike the record's "
        "own timestamp -- OUTSIDE this signature: it is in the envelope, not "
        "the payload. Omitted by default so that nothing weaker than "
        "record.timestamp sits beside it inviting misreading; the chain's "
        "entry_digest covers it when a caller does supply one.",
    )


class SignedRecord(BaseModel):
    """A provenance record with its signature envelope, as stored on disk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    record: ProvenanceRecord
    signature: SignatureEnvelope | None = None

    def entry_payload(self) -> dict[str, Any]:
        return {
            "record": self.record.model_dump(mode="json"),
            "signature": (
                self.signature.model_dump(mode="json") if self.signature else None
            ),
        }

    def entry_digest(self) -> str:
        """Digest over payload **and** signature — what the hash chain links.

        Chaining the payload alone would let an adversary swap a signature on an
        already-linked record without breaking the chain; the swap would still
        fail that record's own signature check, but the chain would report
        itself intact, and a chain that reports itself intact over a tampered
        entry is worse than no chain.
        """
        return hashlib.sha256(canonical_json(self.entry_payload())).hexdigest()

    def is_signed(self) -> bool:
        return self.signature is not None


def create_provenance_record(
    *,
    input_binding: InputBinding,
    model_binding: ModelBinding,
    preprocessing: ConfigBinding,
    inference: ConfigBinding,
    output: OutputBinding,
    log_id: str,
    sequence_number: int = GENESIS_SEQUENCE,
    previous_record_digest: str | None = None,
    execution: ExecutionMetadata | None = None,
    timestamp: str | None = None,
    nonce: str | None = None,
    producer: str | None = None,
    labels: dict[str, str] | None = None,
) -> ProvenanceRecord:
    """Assemble a record and derive its content-addressed id.

    The id cannot be supplied by the caller: it is a function of the content, so
    that a record whose id does not match its content is detectable as such
    rather than merely mislabelled.
    """
    draft = ProvenanceRecord(
        record_id="PR-0000000000000000",
        input=input_binding,
        model=model_binding,
        preprocessing=preprocessing,
        inference=inference,
        output=output,
        execution=execution or ExecutionMetadata(),
        sequence=SequenceBinding(
            log_id=log_id,
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        # `is None`, not `or`: an explicitly empty timestamp or nonce is a
        # caller's bug, and substituting a default for it would hide that bug
        # inside a signed record, where it becomes indistinguishable from a
        # real claim. Only an omitted value gets a default.
        timestamp=utc_now_iso() if timestamp is None else timestamp,
        nonce=new_nonce() if nonce is None else nonce,
        producer=producer,
        labels=dict(labels or {}),
    )
    return draft.model_copy(update={"record_id": draft.expected_record_id()})
