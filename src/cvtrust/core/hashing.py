"""Cryptographic hashing helpers.

Policy (see ``docs/security.md``): SHA-256 is the only digest used for identity
or integrity decisions.  MD5 and SHA-1 are not used anywhere in this codebase,
including for "non-security" convenience keys, because a convenience key has a
habit of becoming an identity later.

Two distinct digests are computed for every image, and they answer different
questions:

``file_sha256``
    Digest of the bytes on disk.  Identity of the *artifact*.

``pixel_sha256``
    Digest of the decoded, normalised pixel buffer plus its shape and mode.
    Identity of the *content*.  Two files with different container bytes
    (re-encoded, re-stripped EXIF, different JPEG quantisation that happens to
    decode identically) but the same pixels share this digest.  That difference
    is exactly what an exact-duplicate-flooding adversary hides behind.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from .canonical import FloatMode, canonical_json

#: Read granularity for file hashing: large enough to amortise syscalls, small
#: enough that a multi-GB dataset never materialises in memory.
_CHUNK = 1024 * 1024

HASH_ALGORITHM = "sha256"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path | str) -> str:
    """Streaming SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_canonical(value: Any, *, float_mode: FloatMode = "reject") -> str:
    """SHA-256 over the canonical JSON encoding of a structure."""
    return hashlib.sha256(canonical_json(value, float_mode=float_mode)).hexdigest()


def pixel_sha256(array: np.ndarray, mode: str) -> str:
    """Content digest of a decoded image.

    The shape, dtype and colour mode are bound into the digest so that buffers
    that happen to share bytes under a different interpretation cannot collide.
    """
    if not array.flags["C_CONTIGUOUS"]:
        array = np.ascontiguousarray(array)
    digest = hashlib.sha256()
    header = f"{mode}|{array.dtype.str}|{'x'.join(str(d) for d in array.shape)}|"
    digest.update(header.encode("utf-8"))
    digest.update(array.tobytes())
    return digest.hexdigest()


def short(digest: str, length: int = 12) -> str:
    """Truncated digest for human-readable identifiers.

    Only ever used for display and for finding ids, never for an integrity
    decision — a truncated digest is a label, not a proof.
    """
    return digest[:length]
