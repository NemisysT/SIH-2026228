"""The local, offline trust store.

**Cryptographic validity and trust are different claims.**  A signature that
verifies establishes that *whoever holds this private key* produced these bytes.
It says nothing about whether that holder was authorised, because anyone can
generate a keypair.  Conflating the two is the single most common way a signing
system ends up proving nothing, so this module exists to keep them apart: the
signature check lives in :mod:`cvtrust.provenance.signing`, and the question
"should I believe this key" is answered only here.

Administrative model
--------------------
There is no CA, no PKI, no OCSP responder and no network. Trust is an
**administrative fact recorded locally by the analyst**:

* the operator obtains a public key through a channel independent of the one
  that supplied the records — a courier, a printed fingerprint read aloud, a
  key handed over at enrolment — and adds it with ``trust_key``;
* the operator removes trust with ``revoke_key``, which records *when* and
  *why*;
* everything else is ``UNKNOWN``.

The independence of that channel is the assumption the whole module rests on,
and it is stated in the coverage entry rather than buried: a trust store
populated from the same source as the records proves nothing.

Rotation and validity windows
-----------------------------
A store holds many keys at once, each with an optional ``valid_from`` /
``valid_until`` window, so rotation is an ordinary state rather than an outage:
the old key stays TRUSTED for the period it signed, the new key is added, and
both verify.

Deciding *when* to evaluate a window is a genuine problem in an offline system,
because the only time a record carries is its own self-asserted timestamp.  Both
answers are wrong in different ways, so both are implemented and the choice is
recorded in every verification:

``AT_RECORD_TIMESTAMP`` (default)
    Honours rotation — a record signed last year by a key retired since still
    verifies.  Its weakness is exact: a forger with a retired key can also
    choose the timestamp, so an expired key can be "revived" by backdating.
    That is why an expired-key result is reported as its own outcome rather
    than folded into "valid", and why a chained record is stronger than a
    loose one (its position bounds when it can have been written).

``AT_VERIFICATION_TIME``
    Immune to backdating, and it invalidates the entire history of every key
    that has ever expired. Available for deployments that would rather re-sign
    than carry that risk.

Revocation is absolute under both policies — a revoked key's signatures are
never TRUSTED — but the store records ``revoked_at`` so the verifier can also
report whether the record *claims* to predate the revocation.  Those are two
separate facts and the report carries both rather than averaging them into one.
"""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..core.errors import ProvenanceError
from ..core.evidence import utc_now_iso
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger
from .keys import SIGNATURE_ALGORITHM, public_key_fingerprint

log = get_logger("provenance.trust")

TRUST_STORE_SCHEMA_VERSION = "1.0"


class KeyStatus(str, Enum):
    """Status of a key in the operator's store.

    ``UNKNOWN`` is both a storable status and the result of a lookup miss.  The
    storable form means "this key has been seen and deliberately not trusted",
    which an analyst may want to record; the lookup form means "never seen".
    The verification result distinguishes them by ``present_in_store``.
    """

    TRUSTED = "TRUSTED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class KeyPurpose(str, Enum):
    """What a key is authorised to sign.

    A key trusted to sign inference records is not thereby trusted to sign a log
    anchor: the anchor is the analyst's own out-of-band attestation about a log,
    and letting the log's producer mint one would remove the only thing that
    makes truncation detectable.
    """

    INFERENCE_PROVENANCE = "inference_provenance"
    LOG_ANCHOR = "log_anchor"
    ANY = "any"


class ValidityPolicy(str, Enum):
    AT_RECORD_TIMESTAMP = "at_record_timestamp"
    AT_VERIFICATION_TIME = "at_verification_time"


class TrustedKey(BaseModel):
    """One key as the operator recorded it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str = Field(min_length=64, max_length=64)
    algorithm: str = SIGNATURE_ALGORITHM
    public_key: str = Field(min_length=64, max_length=64)
    status: KeyStatus = KeyStatus.TRUSTED
    valid_from: str | None = None
    valid_until: str | None = None
    purpose: KeyPurpose = KeyPurpose.INFERENCE_PROVENANCE
    label: str | None = Field(
        default=None, description="Operator's own name for the key. A label."
    )
    added_at: str = Field(default_factory=utc_now_iso)
    revoked_at: str | None = None
    revocation_reason: str | None = None
    provenance: str | None = Field(
        default=None,
        description="How the operator obtained this key. Free text, and the "
        "most important field in the record for a reviewer: a key obtained "
        "through the same channel as the records it verifies establishes "
        "nothing.",
    )
    metadata: dict[str, str] = Field(default_factory=dict)

    def fingerprint_consistent(self) -> bool:
        """Does the stored key id match the stored key material?"""
        try:
            return public_key_fingerprint(bytes.fromhex(self.public_key)) == self.key_id
        except Exception:
            return False

    def window_contains(self, moment: str | None) -> bool | None:
        """Is ``moment`` inside this key's validity window?

        ``None`` means the question could not be answered — no moment supplied,
        or a timestamp this build cannot parse.  Returning ``None`` rather than
        ``True`` matters: an unparseable timestamp must not silently satisfy a
        validity check.
        """
        if self.valid_from is None and self.valid_until is None:
            return True
        if moment is None:
            return None
        point = _parse_iso(moment)
        if point is None:
            return None
        if self.valid_from is not None:
            start = _parse_iso(self.valid_from)
            if start is None or point < start:
                return False
        if self.valid_until is not None:
            end = _parse_iso(self.valid_until)
            if end is None or point > end:
                return False
        return True

    def short_id(self) -> str:
        return self.key_id[:16]


class TrustStore(BaseModel):
    """A set of keys the operator has made an explicit decision about."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = TRUST_STORE_SCHEMA_VERSION
    store_id: str = ""
    updated_at: str = Field(default_factory=utc_now_iso)
    administrative_model: str = (
        "Local, offline, operator-administered. No CA, no PKI, no network "
        "revocation service. A key is trusted because an analyst added it, "
        "having obtained it through a channel independent of the one that "
        "supplied the records."
    )
    keys: tuple[TrustedKey, ...] = ()

    # -- lookup ------------------------------------------------------------

    def get(self, key_id: str) -> TrustedKey | None:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        return None

    def status_of(self, key_id: str) -> KeyStatus:
        key = self.get(key_id)
        return key.status if key else KeyStatus.UNKNOWN

    def trusted_ids(self) -> tuple[str, ...]:
        return tuple(k.key_id for k in self.keys if k.status is KeyStatus.TRUSTED)

    def digest(self) -> str:
        """Digest over the store's content, excluding its own volatile fields."""
        payload = self.model_dump(mode="json")
        payload.pop("updated_at", None)
        payload.pop("store_id", None)
        return sha256_canonical(payload)

    # -- mutation ----------------------------------------------------------

    def with_key(self, key: TrustedKey) -> "TrustStore":
        others = tuple(k for k in self.keys if k.key_id != key.key_id)
        return self.model_copy(
            update={
                "keys": tuple(sorted(others + (key,), key=lambda k: k.key_id)),
                "updated_at": utc_now_iso(),
            }
        )

    # -- persistence -------------------------------------------------------

    @classmethod
    def empty(cls) -> "TrustStore":
        return cls()

    @classmethod
    def load(cls, path: Path | str) -> "TrustStore":
        file_path = Path(path)
        if not file_path.is_file():
            raise ProvenanceError(f"trust store not found: {file_path}")
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProvenanceError(f"trust store {file_path} is not JSON: {exc}") from exc
        try:
            store = cls.model_validate(payload)
        except Exception as exc:
            raise ProvenanceError(f"trust store {file_path} is malformed: {exc}") from exc
        inconsistent = [k.short_id() for k in store.keys if not k.fingerprint_consistent()]
        if inconsistent:
            raise ProvenanceError(
                "trust store contains key(s) whose recorded key_id does not "
                f"match their key material: {', '.join(inconsistent)}. The store "
                "itself has been altered."
            )
        return store

    @classmethod
    def load_or_empty(cls, path: Path | str | None) -> "TrustStore":
        """Load a store, or return an empty one when no path was supplied.

        An absent store is a legitimate state — every key is then UNKNOWN — and
        it is *not* the same as an empty one that was deliberately created. Both
        verify nothing; the report says which it had.
        """
        if path is None:
            return cls.empty()
        file_path = Path(path)
        return cls.load(file_path) if file_path.is_file() else cls.empty()

    def save(self, path: Path | str) -> Path:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(
            self.model_dump_json(indent=2), encoding="utf-8"
        )
        return file_path


def trust_key(
    store: TrustStore,
    *,
    public_key: str,
    key_id: str | None = None,
    label: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
    purpose: KeyPurpose = KeyPurpose.INFERENCE_PROVENANCE,
    provenance: str | None = None,
    metadata: dict[str, str] | None = None,
) -> TrustStore:
    """Record an operator decision to trust a key.

    The key id is always recomputed from the key material.  A caller-supplied id
    that disagrees is an error rather than a preference: a trust store whose ids
    do not fingerprint its keys would authorise the wrong signatures.
    """
    raw = bytes.fromhex(public_key.strip())
    fingerprint = public_key_fingerprint(raw)
    if key_id is not None and key_id != fingerprint:
        raise ProvenanceError(
            f"supplied key_id {key_id[:16]}… does not fingerprint the supplied key "
            f"material ({fingerprint[:16]}…)"
        )
    entry = TrustedKey(
        key_id=fingerprint,
        public_key=raw.hex(),
        status=KeyStatus.TRUSTED,
        valid_from=valid_from,
        valid_until=valid_until,
        purpose=purpose,
        label=label,
        provenance=provenance,
        metadata=dict(metadata or {}),
    )
    log.info("trusting key %s (%s)", fingerprint[:16], label or "unlabelled")
    return store.with_key(entry)


def revoke_key(
    store: TrustStore,
    key_id: str,
    *,
    reason: str,
    revoked_at: str | None = None,
) -> TrustStore:
    """Revoke a key already in the store.

    Revocation preserves the original entry's window and label, so the record of
    *what the key was* survives the decision to stop trusting it.  Revoking a key
    that is not in the store is an error: silently inserting a REVOKED entry for
    an unknown key would let a typo look like a completed action.
    """
    existing = store.get(key_id)
    if existing is None:
        raise ProvenanceError(
            f"cannot revoke {key_id[:16]}…: it is not in this trust store. An "
            "unknown key is already untrusted; revoking it would only record a "
            "decision that was never made."
        )
    if not reason.strip():
        raise ProvenanceError("revocation requires a reason; it is an audit record")
    log.info("revoking key %s: %s", key_id[:16], reason)
    return store.with_key(
        existing.model_copy(
            update={
                "status": KeyStatus.REVOKED,
                "revoked_at": revoked_at or utc_now_iso(),
                "revocation_reason": reason,
            }
        )
    )


def untrust_key(store: TrustStore, key_id: str, *, reason: str | None = None) -> TrustStore:
    """Mark a known key explicitly UNKNOWN without asserting revocation.

    Distinct from revocation on purpose: revocation says "this key was ours and
    is now compromised or retired", which is a claim about history. This says
    only "we have no basis to trust this".
    """
    existing = store.get(key_id)
    if existing is None:
        raise ProvenanceError(f"key {key_id[:16]}… is not in this trust store")
    return store.with_key(
        existing.model_copy(
            update={"status": KeyStatus.UNKNOWN, "revocation_reason": reason}
        )
    )


def build_store(keys: Iterable[TrustedKey]) -> TrustStore:
    return TrustStore(keys=tuple(sorted(keys, key=lambda k: k.key_id)))


def _parse_iso(value: str) -> Any:
    """Parse an ISO-8601 instant, or return ``None``.

    Returning ``None`` rather than raising is deliberate: a malformed timestamp
    inside an untrusted record is a *finding*, and the caller turns it into one.
    A parse failure here must never become an exception that aborts the
    verification of the other twelve checks.
    """
    import datetime as _dt

    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = _dt.datetime.fromisoformat(text)
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


__all__ = [
    "TRUST_STORE_SCHEMA_VERSION", "KeyStatus", "KeyPurpose", "ValidityPolicy",
    "TrustedKey", "TrustStore", "trust_key", "revoke_key", "untrust_key",
    "build_store",
]
