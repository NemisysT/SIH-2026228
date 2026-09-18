"""What a provenance record binds, and how each binding is computed.

Five things are bound, and the reason they are separate fields rather than one
"context hash" is that an analyst reading a failed verification needs to know
*which* of them moved.  A single digest over everything answers "something
changed"; these answer "the model is not the one you assured", which is a
different conversation.

``InputBinding``
    Identity of what was fed in.  ``raw_input_digest`` is SHA-256 over the bytes
    on disk; ``normalized_input_digest``, when present, is SHA-256 over the
    decoded, preprocessed tensor.  They are **never** interchangeable and one is
    never silently substituted for the other: the raw digest changes when a JPEG
    is re-encoded and the pixels do not, and the normalised digest changes when
    the preprocessing changes and the file does not.

``ModelBinding``
    Module 2's identity, consumed rather than recomputed.  Module 3 owns no
    model forensics: it copies ``model_id``, ``file_sha256``, ``graph_digest``
    and ``parameter_digest`` out of a :class:`~cvtrust.models.manifest.ModelManifest`
    and binds them.  The declared name travels alongside, flagged untrusted, so
    that a record claiming ``detector_v3`` can be shown *not* to establish that
    the model was ``detector_v3``.

``PreprocessingBinding`` / ``InferenceBinding``
    Configuration, canonicalised and hashed.  Both carry the configuration
    inline in digest-safe form as well as its digest, which makes a record
    self-verifying: a verifier can recompute the digest from the record alone
    and catch a forger who edited the configuration and forgot the digest.

``OutputBinding``
    The canonical output (see :mod:`cvtrust.provenance.output`) and its digest,
    carried inline for the same reason.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import canonical_json, digest_safe, undigest_safe
from ..core.errors import ProvenanceError
from ..core.hashing import HASH_ALGORITHM, sha256_canonical, sha256_file
from .output import OUTPUT_QUANT_PLACES, CanonicalOutput

#: Decimal places used when folding a configuration float onto the digest grid.
#: Shared with the output grid so that one record has one quantisation story.
CONFIG_QUANT_PLACES = OUTPUT_QUANT_PLACES


class InputBinding(BaseModel):
    """Identity of the inference input.  Content, never filename."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    raw_input_digest: str = Field(min_length=64, max_length=64)
    raw_input_size_bytes: int = Field(ge=0)
    normalized_input_digest: str | None = Field(
        default=None,
        description="SHA-256 over the preprocessed tensor, when the caller "
        "computed one. Distinct from raw_input_digest and never a substitute.",
    )
    normalized_input_shape: tuple[int, ...] | None = None
    normalized_input_dtype: str | None = None
    media_type: str | None = Field(
        default=None, description="Declared media type. UNTRUSTED: a label."
    )
    locator: str | None = Field(
        default=None,
        description="Where the input came from. UNTRUSTED: recorded for the "
        "analyst, excluded from every identity decision.",
    )


class ModelBinding(BaseModel):
    """Module 2's model identity, consumed by Module 3 and bound here."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model_id: str = Field(min_length=1)
    file_sha256: str = Field(min_length=64, max_length=64)
    graph_digest: str | None = None
    parameter_digest: str | None = None
    parameter_count: int | None = None
    model_format: str = Field(min_length=1)
    declared_name: str | None = Field(
        default=None,
        description="Human-readable model name. UNTRUSTED: a record claiming "
        "'detector_v3' does not establish that the model was detector_v3. The "
        "digests above do.",
    )
    declared_version: str | None = Field(
        default=None, description="UNTRUSTED, for the same reason."
    )
    manifest_digest: str | None = Field(
        default=None,
        description="Digest of the Module 2 manifest this binding was taken "
        "from, so the two artifacts can be joined later.",
    )


class ConfigBinding(BaseModel):
    """A canonicalised configuration and its digest.

    ``config`` is stored in digest-safe form (floats as ``{"$q": int, "p": n}``)
    so that the whole record canonicalises in strict float-free mode.  Use
    :meth:`readable` for display; nothing re-derives a digest from that.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest: str = Field(min_length=64, max_length=64)
    quantization_places: int = CONFIG_QUANT_PLACES
    config: Mapping[str, Any] = Field(default_factory=dict)

    def recompute_digest(self) -> str:
        return sha256_canonical(dict(self.config))

    def self_consistent(self) -> bool:
        """Does the stored digest match the stored configuration?

        A forger who edits the configuration inside a record and re-signs with
        their own key produces a record whose signature verifies.  This check is
        what still catches them if they did not also recompute the digest, and
        it costs nothing.
        """
        return self.recompute_digest() == self.digest

    def readable(self) -> dict[str, Any]:
        """Display form, with fixed-point values rebuilt as floats."""
        return undigest_safe(dict(self.config))


class OutputBinding(BaseModel):
    """The canonical output and its digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    digest: str = Field(min_length=64, max_length=64)
    output: CanonicalOutput

    def recompute_digest(self) -> str:
        return self.output.digest()

    def self_consistent(self) -> bool:
        return self.recompute_digest() == self.digest


class ExecutionMetadata(BaseModel):
    """Where and with what the inference ran.

    Every field here is asserted by the producer and none of it is verifiable by
    the verifier, which is exactly why it is segregated into its own object
    instead of sitting beside the digests.  It is signed — so it cannot be
    altered after the fact without detection — but a signature over a claim
    makes the claim attributable, not true.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime: str | None = None
    runtime_version: str | None = None
    adapter: str | None = None
    adapter_version: str | None = None
    software_version: str | None = None
    access_mode: str | None = None
    host_label: str | None = Field(
        default=None, description="Operator-supplied host name. UNTRUSTED."
    )
    device: str | None = None
    notes: tuple[str, ...] = ()


def bind_input(
    path: Path | str,
    *,
    locator: str | None = None,
    normalized_digest: str | None = None,
    normalized_shape: tuple[int, ...] | None = None,
    normalized_dtype: str | None = None,
    media_type: str | None = None,
) -> InputBinding:
    """Bind an input file by the SHA-256 of its bytes.

    The path is recorded as an untrusted locator and plays no part in identity:
    two copies of the same bytes under different names bind identically, and a
    verification never consults it.

    ``locator`` overrides what is recorded.  It exists because the locator *is*
    inside the signature -- so it cannot be altered after the fact -- which also
    means an absolute path makes an otherwise identical record differ between
    two hosts.  A deployment that wants records comparable across machines
    records a dataset-relative path here; one that wants to know exactly which
    file on which host was read leaves the default.  Either way the digest above
    is the identity.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ProvenanceError(f"input artifact not found: {file_path}")
    return InputBinding(
        raw_input_digest=sha256_file(file_path),
        raw_input_size_bytes=file_path.stat().st_size,
        normalized_input_digest=normalized_digest,
        normalized_input_shape=normalized_shape,
        normalized_input_dtype=normalized_dtype,
        media_type=media_type,
        locator=str(file_path) if locator is None else locator,
    )


def bind_input_bytes(
    data: bytes,
    *,
    locator: str | None = None,
    media_type: str | None = None,
    normalized_digest: str | None = None,
) -> InputBinding:
    """Bind an in-memory input by the SHA-256 of its bytes."""
    import hashlib

    return InputBinding(
        raw_input_digest=hashlib.sha256(data).hexdigest(),
        raw_input_size_bytes=len(data),
        normalized_input_digest=normalized_digest,
        media_type=media_type,
        locator=locator,
    )


def normalized_tensor_digest(array: Any) -> str:
    """SHA-256 over a preprocessed tensor: quantised values and shape only.

    Quantised for the same reason model parameters are (ADR-010): a tensor
    materialised as float32 and as float64 is the *same* preprocessed input, and
    a digest that disagreed would report a preprocessing change where there was
    only a storage change.

    The storage dtype is deliberately **not** bound here, and that is a design
    decision rather than an omission.  The dtype the pipeline preprocesses *to*
    is part of its preprocessing configuration, which is canonicalised and bound
    in its own right by :func:`bind_config`; binding it a second time inside the
    tensor digest would make the two disagree about what a dtype change means,
    and would undo the dtype-independence this function exists to provide.  The
    shape *is* bound, because a reshaped buffer is a different input.
    """
    import numpy as np

    data = np.asarray(array)
    if np.issubdtype(data.dtype, np.floating):
        if not np.all(np.isfinite(data)):
            raise ProvenanceError(
                "preprocessed input contains non-finite values; that is itself a "
                "finding and must not be folded silently into a digest"
            )
        values = np.rint(
            np.asarray(data, dtype=np.float64) * (10**CONFIG_QUANT_PLACES)
        ).astype(np.int64)
    else:
        values = data.astype(np.int64)
    return sha256_canonical(
        {
            "kind": "normalized_input",
            "places": CONFIG_QUANT_PLACES,
            "numeric_kind": (
                "float" if np.issubdtype(data.dtype, np.floating) else "integer"
            ),
            "shape": [int(d) for d in data.shape],
            "values": [int(v) for v in values.ravel()],
        }
    )


def bind_config(
    config: Mapping[str, Any], *, places: int = CONFIG_QUANT_PLACES
) -> ConfigBinding:
    """Canonicalise a configuration mapping and take its digest.

    Any structure that survives :func:`digest_safe` is accepted: this has to
    work for pipelines whose preprocessing we have never seen.  What it will not
    do is accept a value it cannot canonicalise — an unrepresentable type raises
    rather than being coerced to ``str()``, because a configuration digest that
    silently ignores a field is worse than none.
    """
    safe = digest_safe(dict(config), places)
    try:
        canonical_json(safe)
    except Exception as exc:  # CanonicalizationError, with a useful message
        raise ProvenanceError(
            f"configuration cannot be canonicalised, so it cannot be bound: {exc}"
        ) from exc
    return ConfigBinding(
        digest=sha256_canonical(safe), quantization_places=places, config=safe
    )


def bind_output(output: CanonicalOutput) -> OutputBinding:
    return OutputBinding(digest=output.digest(), output=output)


def bind_model_manifest(manifest: Any) -> ModelBinding:
    """Bind a Module 2 :class:`ModelManifest` without recomputing any of it.

    Module 3 is not allowed to have its own opinion about model identity.  It
    reads Module 2's and binds it, so that a mismatch found here and a mismatch
    found by ``cvtrust model verify`` are statements about the same digests.
    """
    return ModelBinding(
        model_id=manifest.model_id,
        file_sha256=manifest.file_sha256,
        graph_digest=manifest.graph_digest,
        parameter_digest=manifest.parameter_digest,
        parameter_count=manifest.parameter_count,
        model_format=manifest.model_format,
        declared_name=getattr(manifest, "architecture", None),
        declared_version=str(
            (manifest.declared_metadata or {}).get("version")
        ) if getattr(manifest, "declared_metadata", None) else None,
        manifest_digest=manifest.digest,
    )


#: The hash algorithm every binding in this module uses.  Recorded in the record
#: itself rather than assumed, so a future migration is visible in old records.
BINDING_HASH_ALGORITHM = HASH_ALGORITHM
