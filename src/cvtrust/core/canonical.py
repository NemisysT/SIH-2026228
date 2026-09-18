"""Canonical serialisation for digest-bearing structures.

Why this module exists
----------------------
Anything we hash and (from Module 3 onward) sign must have exactly one byte
representation, on every machine, for every Python version.  Ordinary
``json.dumps`` does not give that: key order, whitespace, unicode escaping and
— above all — floating-point formatting are all free parameters.

Design decision (ADR-004): the digest surface is **float-free by default**.
``canonical_json`` raises on ``float`` unless the caller explicitly opts into a
non-digest mode.  RFC 8785 (JSON Canonicalization Scheme) number formatting is
implementable but subtle, and every subtlety becomes a signature-verification
bug later.  Scores that genuinely must be hashed are carried as integers in
fixed units via :func:`quantize`.  Human-facing reports, which are not signed in
Module 1, may serialise floats with ``float_mode="repr"``.

Guarantees
----------
* UTF-8 bytes, no BOM.
* Object keys sorted by Unicode code point; duplicate keys impossible (dict).
* No insignificant whitespace (``,`` / ``:`` separators).
* ``NaN``/``Infinity`` always rejected — they have no JSON representation.
* Only ``dict`` / ``list`` / ``tuple`` / ``str`` / ``int`` / ``bool`` / ``None``
  (plus ``float`` in ``repr`` mode) are accepted; anything else is an error
  rather than a silent ``str()``.
"""

from __future__ import annotations

import json
import math
from typing import Any, Final, Literal

from .errors import CanonicalizationError

FloatMode = Literal["reject", "repr"]

#: Integers outside IEEE-754 double exact range cannot survive a JSON
#: round-trip through consumers that parse numbers as doubles.  We keep our
#: digest surface inside the safe range and reject anything larger.
MAX_SAFE_INT: Final[int] = 2**53 - 1


def _normalise(value: Any, float_mode: FloatMode, path: str) -> Any:
    if value is None or isinstance(value, bool):
        return value

    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalizationError(
                f"integer at {path} exceeds the IEEE-754 safe range: {value}"
            )
        return value

    if isinstance(value, float):
        if float_mode == "reject":
            raise CanonicalizationError(
                f"float at {path} ({value!r}) is not allowed in a digest-bearing "
                "structure; carry it as an integer in fixed units (see quantize()) "
                'or serialise with float_mode="repr" for non-signed output'
            )
        if not math.isfinite(value):
            raise CanonicalizationError(f"non-finite float at {path}: {value!r}")
        return value

    if isinstance(value, str):
        return value

    if isinstance(value, (list, tuple)):
        return [_normalise(v, float_mode, f"{path}[{i}]") for i, v in enumerate(value)]

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, val in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"non-string object key at {path}: {key!r} ({type(key).__name__})"
                )
            out[key] = _normalise(val, float_mode, f"{path}.{key}")
        return out

    raise CanonicalizationError(
        f"unsupported type at {path}: {type(value).__name__}; convert it "
        "explicitly before canonicalisation"
    )


def canonical_json(value: Any, *, float_mode: FloatMode = "reject") -> bytes:
    """Return the canonical UTF-8 JSON encoding of ``value``.

    Args:
        value: a JSON-compatible structure.
        float_mode: ``"reject"`` (default, digest-safe) or ``"repr"`` for
            non-signed human/report output.

    Raises:
        CanonicalizationError: on unsupported types, non-finite numbers,
            non-string keys, unsafe integers, or floats in ``"reject"`` mode.
    """
    normalised = _normalise(value, float_mode, "$")
    text = json.dumps(
        normalised,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("utf-8")


def quantize(value: float, places: int = 6) -> int:
    """Convert a float into an integer in fixed units, for digest inclusion.

    ``quantize(0.9134, 3) -> 913``.  Round-half-even is used so that the result
    does not depend on the platform's rounding mode.
    """
    if not math.isfinite(value):
        raise CanonicalizationError(f"cannot quantize non-finite value {value!r}")
    scaled = round(value * (10**places))
    if abs(scaled) > MAX_SAFE_INT:
        raise CanonicalizationError(f"quantized value out of safe range: {value!r}")
    return int(scaled)


#: Marker key used by :func:`digest_safe` to represent a quantized float.
QUANT_KEY: Final[str] = "$q"


def digest_safe(value: Any, places: int = 6) -> Any:
    """Rewrite a structure so that it can be canonicalised in ``reject`` mode.

    Floats are replaced by ``{"$q": <int>, "p": <places>}``.  This keeps the
    digest surface float-free (ADR-004) while still letting configuration
    objects, which legitimately contain thresholds like ``0.90``, participate in
    a stable configuration hash.  The transform is lossy at the chosen
    precision and is used only for hashing, never for reconstructing values.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        return {QUANT_KEY: quantize(value, places), "p": places}
    if isinstance(value, (list, tuple)):
        return [digest_safe(v, places) for v in value]
    if isinstance(value, dict):
        return {k: digest_safe(v, places) for k, v in value.items()}
    return value


def undigest_safe(value: Any) -> Any:
    """Invert :func:`digest_safe` for *display only*.

    Module 3 stores preprocessing and inference configuration inside the signed
    provenance record in digest-safe form, so that the record's canonical bytes
    are float-free end to end (ADR-004) and the record is self-verifying: a
    verifier can recompute the configuration digest from the record alone.

    The cost is that ``{"threshold": 0.9}`` is stored as
    ``{"threshold": {"$q": 900000, "p": 6}}``, which no analyst should be asked
    to read.  This function rebuilds the float for a report or a console view.

    It is **lossy at the quantisation grid** and is therefore never used on an
    integrity path: nothing in this codebase re-derives a digest from the output
    of this function.
    """
    if isinstance(value, dict):
        if set(value) == {QUANT_KEY, "p"} and isinstance(value.get(QUANT_KEY), int):
            places = value["p"]
            if isinstance(places, int) and 0 <= places <= 18:
                return value[QUANT_KEY] / (10**places)
        return {k: undigest_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [undigest_safe(v) for v in value]
    return value
