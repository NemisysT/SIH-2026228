"""Signing and signature verification.

Thin by design.  All this module does is put a record's canonical bytes through
``cryptography``'s Ed25519 and report, in a structured way, which of the three
distinct failures occurred:

``MISSING``
    No signature envelope at all.  An unsigned record is not an invalid record;
    it is a record making no claim of authenticity, and the two must be
    reported differently or an operator will read "no signature" as "signature
    failed" and look for an attacker who is not there.

``MALFORMED``
    An envelope exists but its key or signature cannot be decoded, or its
    ``key_id`` does not fingerprint the public key it carries.  This is a
    structural defect, not a cryptographic one, and it is reached before any
    verification is attempted.

``INVALID``
    Well-formed, decodable, and the bytes do not verify.  The record was
    altered after signing, or signed by a different key than the one it names.

What a valid signature establishes
----------------------------------
Only that the holder of the private key matching the *embedded* public key
produced these exact bytes.  Because the public key travels inside the envelope,
anyone can produce a record whose signature verifies.  Authenticity requires
that key to be in the trust store, which is :mod:`cvtrust.provenance.trust`'s
job and is never decided here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import (
    SIGNATURE_ALGORITHM,
    SIGNATURE_BYTES,
    export_public_key,
    public_key_fingerprint,
    public_key_from_hex,
)
from .record import ProvenanceRecord, SignatureEnvelope, SignedRecord


class SignatureOutcome(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    MALFORMED = "MALFORMED"
    MISSING = "MISSING"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"


@dataclass(frozen=True)
class SignatureCheck:
    """The result of checking one signature, with the evidence behind it."""

    outcome: SignatureOutcome
    key_id: str | None
    algorithm: str | None
    detail: str
    #: Does the envelope's ``key_id`` fingerprint the key material it carries?
    #: ``None`` when the material could not be decoded at all.
    key_id_consistent: bool | None = None

    @property
    def valid(self) -> bool:
        return self.outcome is SignatureOutcome.VALID


def sign_record(
    record: ProvenanceRecord,
    private_key: Ed25519PrivateKey,
    *,
    signed_at: str | None = None,
) -> SignedRecord:
    """Sign a record's canonical bytes and return the signed envelope.

    Ed25519 signatures are deterministic (RFC 8032): signing the same record
    twice with the same key yields identical bytes.  That is what lets the
    determinism test compare two independently produced logs byte for byte, and
    it removes the per-signature nonce that has cost real ECDSA deployments
    their private keys.

    ``signed_at`` is **omitted by default**, and deliberately.  It sits in the
    envelope rather than the payload, so it is *outside* the record's own
    signature: a second, weaker timestamp beside the signed one in
    ``record.timestamp`` invites a reader to treat it as authoritative when it is
    strictly less trustworthy.  A caller who genuinely needs to record a signing
    time distinct from the inference time passes one explicitly, and it is then
    covered by the chain's ``entry_digest`` but not by this signature.

    Leaving it out also means signing is a pure function of ``(record, key)``,
    so two independently produced logs over the same inputs are byte-identical.
    """
    key_id, public_hex = export_public_key(private_key)
    signature = private_key.sign(record.canonical_bytes())
    return SignedRecord(
        record=record,
        signature=SignatureEnvelope(
            algorithm=SIGNATURE_ALGORITHM,
            key_id=key_id,
            public_key=public_hex,
            signature=signature.hex(),
            signed_at=signed_at,
        ),
    )


def verify_signature(signed: SignedRecord) -> SignatureCheck:
    """Check the signature over a record's canonical bytes.

    Never raises for a bad signature: an unverifiable record is the normal case
    this system exists to report, and an exception would abort the twelve other
    checks the caller still has to run.
    """
    envelope = signed.signature
    if envelope is None:
        return SignatureCheck(
            outcome=SignatureOutcome.MISSING,
            key_id=None,
            algorithm=None,
            detail=(
                "the record carries no signature envelope; it asserts no "
                "authenticity and attributes itself to no key"
            ),
        )

    if envelope.algorithm != SIGNATURE_ALGORITHM:
        return SignatureCheck(
            outcome=SignatureOutcome.UNSUPPORTED_ALGORITHM,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            detail=(
                f"signature algorithm {envelope.algorithm!r} is not supported by "
                f"this build, which verifies {SIGNATURE_ALGORITHM} only"
            ),
        )

    try:
        raw_public = bytes.fromhex(envelope.public_key)
        signature_bytes = bytes.fromhex(envelope.signature)
    except ValueError as exc:
        return SignatureCheck(
            outcome=SignatureOutcome.MALFORMED,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            detail=f"signature envelope is not valid hex: {exc}",
        )

    if len(signature_bytes) != SIGNATURE_BYTES:
        return SignatureCheck(
            outcome=SignatureOutcome.MALFORMED,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            detail=(
                f"an Ed25519 signature is {SIGNATURE_BYTES} bytes; this envelope "
                f"carries {len(signature_bytes)}"
            ),
        )

    try:
        fingerprint = public_key_fingerprint(raw_public)
    except Exception as exc:
        return SignatureCheck(
            outcome=SignatureOutcome.MALFORMED,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            detail=f"public key in the envelope cannot be decoded: {exc}",
        )

    key_id_consistent = fingerprint == envelope.key_id
    if not key_id_consistent:
        # The envelope names one key and carries another.  Verifying against the
        # carried key and reporting the named one would let a record be
        # attributed to a key that did not sign it.
        return SignatureCheck(
            outcome=SignatureOutcome.MALFORMED,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            key_id_consistent=False,
            detail=(
                f"the envelope declares key_id {envelope.key_id[:16]}… but the "
                f"public key it carries fingerprints to {fingerprint[:16]}…; the "
                "record names a key that did not sign it"
            ),
        )

    try:
        public_key = public_key_from_hex(envelope.public_key)
    except Exception as exc:
        return SignatureCheck(
            outcome=SignatureOutcome.MALFORMED,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            key_id_consistent=key_id_consistent,
            detail=f"public key in the envelope cannot be loaded: {exc}",
        )

    try:
        public_key.verify(signature_bytes, signed.record.canonical_bytes())
    except InvalidSignature:
        return SignatureCheck(
            outcome=SignatureOutcome.INVALID,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            key_id_consistent=key_id_consistent,
            detail=(
                "the signature does not verify over this record's canonical "
                "bytes: the record was altered after signing, or it was signed "
                "by a different key than the one it carries"
            ),
        )

    return SignatureCheck(
        outcome=SignatureOutcome.VALID,
        key_id=envelope.key_id,
        algorithm=envelope.algorithm,
        key_id_consistent=True,
        detail=(
            "the signature verifies over this record's canonical bytes. This "
            "establishes that the holder of the matching private key produced "
            "these bytes -- not that the key is authorised."
        ),
    )


__all__ = [
    "SignatureOutcome", "SignatureCheck", "sign_record", "verify_signature",
    "InvalidSignature",
]
