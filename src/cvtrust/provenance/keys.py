"""Offline Ed25519 key material: generation, storage, loading, fingerprints.

No cryptography is invented here.  Key generation, signing and verification are
``cryptography``'s Ed25519 implementation (RFC 8032), and private keys are
serialised as PKCS#8 PEM with the library's own encryption.  This module's job
is the *lifecycle* around those primitives, offline: no key server, no
certificate download, no hosted KMS, no escrow.

Why Ed25519
-----------
Deterministic signatures (no per-signature nonce to leak a key through, unlike
ECDSA), a fixed 64-byte signature, a 32-byte public key that fits in a record
without ceremony, no parameter choices to get wrong, and a constant-time
reference implementation in the library we already depend on.  RSA would work
and produce records an order of magnitude larger for no gain; ECDSA would
reintroduce the nonce-reuse failure mode that has taken real keys.

Key identity
------------
``key_id`` is the full SHA-256 of the raw 32-byte public key.  It is not derived
from a filename, an operator label, or anything else the operator can restate —
consistent with the rule Modules 1 and 2 already enforce, that identity is
content and nothing else.  The 16-character prefix is used for display only.

Private-key handling, stated plainly
------------------------------------
This software cannot protect a private key from a compromised host.  It is a
Python process reading a file; an adversary with code execution as the signing
user can read that file, or simply ask this module to sign.  What it does
provide:

* PKCS#8 PEM with a passphrase (``BestAvailableEncryption``) as the default
  path;
* an *explicit* opt-in for unencrypted keys — :func:`generate_keypair` refuses
  to write one unless ``allow_unencrypted=True`` is passed, mirroring Module 2's
  ``allow_unsafe_deserialisation`` flag — and files written with mode ``0600``;
* a recorded ``encrypted`` flag on the public half, so a reviewer can see which
  kind of key signed a log without hunting for the private file.

Unencrypted keys are for tests and demos.  The operational model, and its
limits, are in ``docs/cryptographic-model.md`` §5.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..core.errors import KeyMaterialError
from ..core.evidence import utc_now_iso
from ..core.logging import get_logger

log = get_logger("provenance.keys")

SIGNATURE_ALGORITHM = "ed25519"
KEY_FILE_SCHEMA_VERSION = "1.0"

#: Length of a raw Ed25519 public key, in bytes.  RFC 8032 fixes this; it is
#: asserted rather than assumed so a malformed key file fails at load.
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64

#: Owner read/write only.  A private key readable by the group is a private key
#: with a larger trusted set than the operator thinks.
_PRIVATE_KEY_MODE = stat.S_IRUSR | stat.S_IWUSR


def public_key_fingerprint(public_key: Ed25519PublicKey | bytes) -> str:
    """SHA-256 over the raw 32-byte public key.  The key's identity."""
    raw = (
        public_key
        if isinstance(public_key, (bytes, bytearray))
        else public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    if len(raw) != PUBLIC_KEY_BYTES:
        raise KeyMaterialError(
            f"an Ed25519 public key is {PUBLIC_KEY_BYTES} bytes; got {len(raw)}"
        )
    return hashlib.sha256(bytes(raw)).hexdigest()


@dataclass(frozen=True)
class KeyPair:
    """A generated keypair and where its halves were written."""

    key_id: str
    public_key_hex: str
    private_key_path: Path | None
    public_key_path: Path | None
    encrypted: bool
    label: str | None = None
    created_at: str = ""

    def short_id(self) -> str:
        return self.key_id[:16]


def generate_keypair(
    *,
    private_path: Path | str | None = None,
    public_path: Path | str | None = None,
    passphrase: bytes | str | None = None,
    allow_unencrypted: bool = False,
    label: str | None = None,
) -> tuple[Ed25519PrivateKey, KeyPair]:
    """Generate an Ed25519 keypair locally and, optionally, write it out.

    Randomness comes from the library's CSPRNG, which is the OS CSPRNG.  Nothing
    is contacted, nothing is registered, and no authority is consulted: the
    keypair exists the moment it is generated, and it becomes *meaningful* only
    when an operator adds its public half to a trust store.

    Args:
        private_path: where to write the PKCS#8 PEM. ``None`` returns the key
            in memory only, which is what the test suite uses.
        public_path: where to write the public half as JSON. Defaults to
            ``<private_path>.pub.json``.
        passphrase: encrypts the private key at rest.
        allow_unencrypted: required to write an unencrypted private key. The
            refusal is the point: an unencrypted operational key should be a
            decision someone made, not a default they inherited.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    key_id = public_key_fingerprint(raw_public)
    created_at = utc_now_iso()

    if private_path is None:
        return private_key, KeyPair(
            key_id=key_id,
            public_key_hex=raw_public.hex(),
            private_key_path=None,
            public_key_path=None,
            encrypted=False,
            label=label,
            created_at=created_at,
        )

    target = Path(private_path)
    if passphrase is None and not allow_unencrypted:
        raise KeyMaterialError(
            "refusing to write an unencrypted private key: supply a passphrase, "
            "or pass allow_unencrypted=True to state explicitly that this is a "
            "test or demonstration key. This software cannot protect a private "
            "key from a compromised host either way -- see "
            "docs/cryptographic-model.md."
        )

    encryption: serialization.KeySerializationEncryption
    if passphrase is None:
        encryption = serialization.NoEncryption()
    else:
        secret = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        encryption = serialization.BestAvailableEncryption(secret)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    # Create with restrictive permissions from the outset rather than chmod-ing
    # afterwards: between write and chmod there is a window in which the key is
    # world-readable, and that window is enough.
    descriptor = os.open(
        target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _PRIVATE_KEY_MODE
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)
    os.chmod(target, _PRIVATE_KEY_MODE)

    pub_target = Path(public_path) if public_path else target.with_suffix(".pub.json")
    pub_target.parent.mkdir(parents=True, exist_ok=True)
    pub_target.write_text(
        json.dumps(
            {
                "schema_version": KEY_FILE_SCHEMA_VERSION,
                "algorithm": SIGNATURE_ALGORITHM,
                "key_id": key_id,
                "public_key": raw_public.hex(),
                "created_at": created_at,
                "label": label,
                "private_key_encrypted": passphrase is not None,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    log.info("generated ed25519 keypair %s -> %s", key_id[:16], target)
    return private_key, KeyPair(
        key_id=key_id,
        public_key_hex=raw_public.hex(),
        private_key_path=target,
        public_key_path=pub_target,
        encrypted=passphrase is not None,
        label=label,
        created_at=created_at,
    )


def load_private_key(
    path: Path | str, passphrase: bytes | str | None = None
) -> Ed25519PrivateKey:
    """Load a PKCS#8 PEM private key from disk."""
    file_path = Path(path)
    if not file_path.is_file():
        raise KeyMaterialError(f"private key not found: {file_path}")
    secret = (
        passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    )
    try:
        key = serialization.load_pem_private_key(
            file_path.read_bytes(), password=secret
        )
    except TypeError as exc:
        raise KeyMaterialError(
            f"private key {file_path} is encrypted and no passphrase was supplied"
            if secret is None
            else f"private key {file_path} is not encrypted but a passphrase was supplied"
        ) from exc
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError(f"cannot load private key {file_path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyMaterialError(
            f"private key {file_path} is {type(key).__name__}, not Ed25519; this "
            "build signs with Ed25519 only"
        )
    mode = stat.S_IMODE(file_path.stat().st_mode)
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        log.warning(
            "private key %s is readable beyond its owner (mode %o)", file_path, mode
        )
    return key


def load_public_key(value: str | bytes | Path) -> Ed25519PublicKey:
    """Load a public key from raw bytes, a hex string, or a ``.pub.json`` file."""
    if isinstance(value, Path):
        return public_key_from_hex(read_public_key_file(value)["public_key"])
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        text = str(value)
        candidate = Path(text)
        if len(text) != PUBLIC_KEY_BYTES * 2 and candidate.is_file():
            return public_key_from_hex(read_public_key_file(candidate)["public_key"])
        return public_key_from_hex(text)
    return _public_key_from_raw(raw)


def public_key_from_hex(value: str) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(value.strip())
    except ValueError as exc:
        raise KeyMaterialError(f"public key is not valid hex: {exc}") from exc
    return _public_key_from_raw(raw)


def _public_key_from_raw(raw: bytes) -> Ed25519PublicKey:
    if len(raw) != PUBLIC_KEY_BYTES:
        raise KeyMaterialError(
            f"an Ed25519 public key is {PUBLIC_KEY_BYTES} bytes; got {len(raw)}"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:  # pragma: no cover - library-level rejection
        raise KeyMaterialError(f"cannot decode public key: {exc}") from exc


def read_public_key_file(path: Path | str) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise KeyMaterialError(f"public key file not found: {file_path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KeyMaterialError(f"public key file {file_path} is not JSON: {exc}") from exc
    if not isinstance(payload, dict) or "public_key" not in payload:
        raise KeyMaterialError(
            f"public key file {file_path} has no 'public_key' field"
        )
    declared = str(payload.get("key_id", ""))
    actual = public_key_fingerprint(bytes.fromhex(str(payload["public_key"])))
    if declared and declared != actual:
        # The file names a key id that its own key material does not produce.
        # A filename or a label may be wrong harmlessly; a key id may not.
        raise KeyMaterialError(
            f"public key file {file_path} declares key_id {declared[:16]}… but its "
            f"key material fingerprints to {actual[:16]}…"
        )
    payload["key_id"] = actual
    return payload


def export_public_key(private_key: Ed25519PrivateKey) -> tuple[str, str]:
    """Return ``(key_id, public_key_hex)`` for a loaded private key."""
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return public_key_fingerprint(raw), raw.hex()


__all__ = [
    "SIGNATURE_ALGORITHM", "PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "KeyPair",
    "generate_keypair", "load_private_key", "load_public_key",
    "public_key_from_hex", "public_key_fingerprint", "read_public_key_file",
    "export_public_key", "InvalidSignature",
]
