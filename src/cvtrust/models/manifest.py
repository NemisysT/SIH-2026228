"""Model manifest — the cryptographic identity of a model artifact.

Module 1 established that one digest is not enough to describe an image: the
file bytes and the decoded pixels answer different questions, and an adversary
hides in the gap between them.  The same argument applies, with more force, to a
model, so this manifest carries **three** digests:

``file_sha256``
    Digest of the bytes on disk.  Identity of the *artifact*.

``graph_digest``
    Digest over topology, operator sequence, tensor names, shapes and dtypes —
    and deliberately **not** over weight values.  Identity of the
    *architecture*.

``parameter_digest``
    Digest over the weight tensor values, canonically ordered and
    container-independent.  Identity of the *weights*.

Those three, compared against a reference, separate cases an analyst must never
see collapsed into one "model changed" flag:

============  ============  ================  ==========================================
``file``      ``graph``     ``parameter``     interpretation
============  ============  ================  ==========================================
=             =             =                 same artifact
≠             =             =                 re-serialised: new bytes, identical behaviour
≠             =             ≠                 same architecture, different weights:
                                              fine-tune, retrain — or a backdoor
≠             ≠             ≠                 a different model: substitution
============  ============  ================  ==========================================

Identity is never derived from a filename, a path, a display name or a declared
version string.  All three digests are SHA-256 via :mod:`cvtrust.core.hashing`;
no cryptography is implemented here.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import digest_safe
from ..core.errors import VerificationError
from ..core.evidence import utc_now_iso
from ..core.hashing import HASH_ALGORITHM, sha256_canonical, sha256_file, short
from ..core.logging import get_logger
from .base import AccessMode, Capability, LayerInfo, ModelAdapter, ModelHandle, TensorSpec

log = get_logger("models.manifest")

MODEL_MANIFEST_SCHEMA_VERSION = "1.0"

#: Decimal places used when folding a float tensor into ``parameter_digest``.
#:
#: Raw IEEE-754 bytes would be the obvious choice, but they make the digest
#: depend on storage dtype: the *same* weights exported once as float32 and once
#: as float16 would get different digests, and the manifest would report
#: "different weights" for what is a container change.  Quantising to a fixed
#: decimal grid before hashing makes the digest a statement about the weight
#: *values*, which is the question the field is supposed to answer.  Six places
#: is far finer than any meaningful weight perturbation and far coarser than
#: float32 epsilon, so it is stable across platforms without being blind.
PARAMETER_DIGEST_PLACES = 6


class ParameterRecord(BaseModel):
    """Per-tensor record: shape, dtype, count and content digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    dtype: str
    shape: tuple[int, ...]
    count: int
    owner: str | None = None
    op_type: str | None = None
    digest: str


class LayerRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    op_type: str
    input_names: tuple[str, ...] = ()
    output_names: tuple[str, ...] = ()
    output_shape: tuple[int | None, ...] | None = None
    parameter_count: int = 0
    parameter_dtypes: tuple[str, ...] = ()


class TensorSpecRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    dtype: str
    shape: tuple[int | None, ...]


class ModelManifest(BaseModel):
    """Canonical, reproducible description of one model artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = MODEL_MANIFEST_SCHEMA_VERSION
    manifest_id: str
    created_at: str
    hash_algorithm: str = HASH_ALGORITHM

    #: Content-addressed model id.  Derived from ``file_sha256``, never from the
    #: filename or a declared version.
    model_id: str
    model_format: str
    architecture: str | None = Field(
        default=None,
        description="Architecture identifier where the format declares one. "
        "UNTRUSTED: it is a label inside the artifact, not a measurement.",
    )

    file_sha256: str
    file_size_bytes: int
    graph_digest: str | None
    parameter_digest: str | None
    parameter_count: int | None

    inputs: tuple[TensorSpecRecord, ...]
    outputs: tuple[TensorSpecRecord, ...]
    operators: dict[str, int] = Field(
        default_factory=dict, description="Operator/module type histogram."
    )
    layers: tuple[LayerRecord, ...] = ()
    parameters: tuple[ParameterRecord, ...] = ()

    declared_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata the artifact declares about itself. UNTRUSTED.",
    )

    adapter: str
    adapter_version: str
    runtime: dict[str, str] = Field(default_factory=dict)
    access_mode: AccessMode
    capabilities: tuple[str, ...]

    reference_designation: str | None = Field(
        default=None,
        description="Operator-supplied role, e.g. 'trusted reference' or "
        "'supplied artifact under assessment'. A label, never an identity.",
    )
    unavailable_fields: tuple[str, ...] = Field(
        default=(),
        description="Fields this format could not supply. Recorded explicitly "
        "so that 'unavailable' is never read as 'absent'.",
    )
    notes: tuple[str, ...] = ()

    digest: str

    def digest_payload(self) -> dict[str, Any]:
        """The exact structure ``digest`` is taken over.

        ``manifest_id``, ``created_at``, ``digest`` and ``reference_designation``
        are excluded: the first three are derived or volatile, and the fourth is
        an operator label that must not change the identity of what was
        measured.
        """
        payload = self.model_dump(mode="json")
        for volatile in ("manifest_id", "created_at", "digest", "reference_designation"):
            payload.pop(volatile, None)
        return payload

    def recompute_digest(self) -> str:
        return sha256_canonical(digest_safe(self.digest_payload()))

    def identity_summary(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "file_sha256": self.file_sha256,
            "graph_digest": self.graph_digest,
            "parameter_digest": self.parameter_digest,
            "parameter_count": self.parameter_count,
            "model_format": self.model_format,
        }

    def parameter(self, name: str) -> ParameterRecord | None:
        return self._parameter_index().get(name)

    def _parameter_index(self) -> dict[str, ParameterRecord]:
        cached = getattr(self, "__parameter_index", None)
        if cached is None:
            cached = {p.name: p for p in self.parameters}
            object.__setattr__(self, "__parameter_index", cached)
        return cached


def tensor_digest(values: np.ndarray, dtype: str, shape: Sequence[int]) -> str:
    """Content digest of one weight tensor.

    Float tensors are quantised onto a fixed decimal grid first (see
    :data:`PARAMETER_DIGEST_PLACES`) so that the digest describes the *values*
    rather than their storage format.  Integer tensors are hashed exactly.
    The declared shape is bound into the digest so that two tensors sharing a
    flattened buffer under different shapes cannot collide.
    """
    digest = hashlib.sha256()
    digest.update(f"{dtype}|{'x'.join(str(int(d)) for d in shape)}|".encode("utf-8"))
    array = np.asarray(values)
    if np.issubdtype(array.dtype, np.floating):
        scaled = np.rint(
            np.asarray(array, dtype=np.float64) * (10**PARAMETER_DIGEST_PLACES)
        )
        # Non-finite weights are themselves a finding; they are encoded by a
        # distinct sentinel rather than being allowed to poison the digest.
        finite = np.isfinite(np.asarray(array, dtype=np.float64))
        scaled = np.where(finite, scaled, np.float64(np.iinfo(np.int64).min))
        buffer = np.ascontiguousarray(scaled.astype(np.int64))
    else:
        buffer = np.ascontiguousarray(array)
    digest.update(buffer.tobytes())
    return digest.hexdigest()


def _graph_payload(
    inputs: Iterable[TensorSpec],
    outputs: Iterable[TensorSpec],
    layers: Iterable[LayerInfo],
    parameters: Iterable[ParameterRecord],
) -> dict[str, Any]:
    """Structure-only view: shapes, dtypes, topology.  No weight values."""
    return {
        "inputs": [spec.as_dict() for spec in inputs],
        "outputs": [spec.as_dict() for spec in outputs],
        "layers": [
            {
                "name": layer.name,
                "op_type": layer.op_type,
                "input_names": list(layer.input_names),
                "output_names": list(layer.output_names),
                "output_shape": (
                    None
                    if layer.output_shape is None
                    else [None if d is None else int(d) for d in layer.output_shape]
                ),
                "parameter_count": int(layer.parameter_count),
                "parameter_dtypes": list(layer.parameter_dtypes),
            }
            for layer in layers
        ],
        # Parameter *shapes* are structure; parameter *values* are not, and are
        # excluded here on purpose.  This is what makes graph_digest survive a
        # weight change and makes the two-digest comparison informative.
        "parameter_shapes": [
            {"name": p.name, "dtype": p.dtype, "shape": list(p.shape)}
            for p in parameters
        ],
    }


def build_model_manifest(
    handle: ModelHandle,
    adapter: ModelAdapter,
    *,
    reference_designation: str | None = None,
) -> ModelManifest:
    """Measure an artifact and produce its manifest.

    Every field that the format cannot supply is recorded in
    ``unavailable_fields`` rather than silently defaulting, so a reader can tell
    "this model has no operator histogram" from "this format does not expose
    one".
    """
    path = Path(handle.path)
    file_digest = sha256_file(path)
    unavailable: list[str] = list(handle.unavailable)

    parameter_records: list[ParameterRecord] = []
    parameter_digest: str | None = None
    parameter_count: int | None = None
    if handle.has(Capability.PARAMETERS):
        tensors = adapter.parameters(handle)
        for tensor in tensors:
            parameter_records.append(
                ParameterRecord(
                    name=tensor.name,
                    dtype=tensor.dtype,
                    shape=tuple(int(d) for d in tensor.shape),
                    count=tensor.count,
                    owner=tensor.owner,
                    op_type=tensor.op_type,
                    digest=tensor_digest(tensor.values, tensor.dtype, tensor.shape),
                )
            )
        # Sorted by name so the digest cannot depend on graph traversal order,
        # which differs between exporters for the same model.
        parameter_records.sort(key=lambda p: p.name)
        parameter_count = sum(p.count for p in parameter_records)
        parameter_digest = sha256_canonical(
            {
                "algorithm": HASH_ALGORITHM,
                "places": PARAMETER_DIGEST_PLACES,
                "tensors": [
                    {"name": p.name, "dtype": p.dtype, "shape": list(p.shape),
                     "digest": p.digest}
                    for p in parameter_records
                ],
            }
        )
    else:
        unavailable += ["parameter_digest", "parameter_count", "parameters"]

    layer_records: list[LayerRecord] = []
    operators: dict[str, int] = {}
    graph_digest: str | None = None
    if handle.has(Capability.GRAPH):
        layers = adapter.layers(handle)
        for layer in layers:
            layer_records.append(
                LayerRecord(
                    name=layer.name,
                    op_type=layer.op_type,
                    input_names=tuple(layer.input_names),
                    output_names=tuple(layer.output_names),
                    output_shape=layer.output_shape,
                    parameter_count=int(layer.parameter_count),
                    parameter_dtypes=tuple(layer.parameter_dtypes),
                )
            )
            operators[layer.op_type] = operators.get(layer.op_type, 0) + 1
        graph_digest = sha256_canonical(
            digest_safe(
                _graph_payload(handle.inputs, handle.outputs, layers, parameter_records)
            )
        )
    else:
        unavailable += ["graph_digest", "layers", "operators"]

    architecture = handle.declared_metadata.get("architecture")

    manifest = ModelManifest(
        manifest_id="",
        created_at=utc_now_iso(),
        model_id=f"M-{short(file_digest, 16)}",
        model_format=handle.model_format,
        architecture=str(architecture) if architecture is not None else None,
        file_sha256=file_digest,
        file_size_bytes=path.stat().st_size,
        graph_digest=graph_digest,
        parameter_digest=parameter_digest,
        parameter_count=parameter_count,
        inputs=tuple(
            TensorSpecRecord(name=s.name, dtype=s.dtype, shape=s.shape)
            for s in handle.inputs
        ),
        outputs=tuple(
            TensorSpecRecord(name=s.name, dtype=s.dtype, shape=s.shape)
            for s in handle.outputs
        ),
        operators=dict(sorted(operators.items())),
        layers=tuple(layer_records),
        parameters=tuple(parameter_records),
        declared_metadata=dict(sorted(handle.declared_metadata.items())),
        adapter=handle.adapter,
        adapter_version=handle.adapter_version,
        runtime=dict(sorted(handle.runtime.items())),
        access_mode=handle.access_mode,
        capabilities=tuple(sorted(c.value for c in handle.capabilities)),
        reference_designation=reference_designation,
        unavailable_fields=tuple(sorted(set(unavailable))),
        notes=tuple(handle.notes),
        digest="",
    )
    digest = manifest.recompute_digest()
    object.__setattr__(manifest, "digest", digest)
    object.__setattr__(manifest, "manifest_id", f"MM-{short(digest, 16)}")
    log.info(
        "model manifest %s: format=%s params=%s access=%s",
        manifest.manifest_id, manifest.model_format,
        manifest.parameter_count, manifest.access_mode.value,
    )
    return manifest


class ModelVerificationResult(BaseModel):
    """Outcome of re-verifying an artifact against a stored manifest."""

    model_config = ConfigDict(extra="forbid")

    manifest_self_consistent: bool
    manifest_digest: str
    digest_recomputed: str
    artifact_present: bool
    file_match: bool
    expected_file_sha256: str
    actual_file_sha256: str | None
    expected_size: int
    actual_size: int | None
    graph_match: bool | None = None
    parameter_match: bool | None = None
    expected_graph_digest: str | None = None
    actual_graph_digest: str | None = None
    expected_parameter_digest: str | None = None
    actual_parameter_digest: str | None = None
    changed_parameters: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.manifest_self_consistent
            and self.artifact_present
            and self.file_match
        )


def verify_model_manifest(
    manifest: ModelManifest, path: Path, *, adapter: ModelAdapter | None = None
) -> ModelVerificationResult:
    """Re-verify an artifact against a manifest recorded earlier.

    Two independent checks, kept separate because they fail for different
    reasons:

    1. *Manifest self-consistency* — has the manifest file itself been edited?
       Recomputing its digest answers that without touching the artifact.
    2. *Artifact correspondence* — is the artifact still the one described?

    Where the artifact can be re-loaded, the graph and parameter digests are
    also recomputed and the specific changed tensors are listed.  That is the
    difference between "the model changed" and "layer4.weight changed and
    nothing else did", and it is the evidence a reviewer needs.
    """
    path = Path(path)
    recomputed = manifest.recompute_digest()
    result = ModelVerificationResult(
        manifest_self_consistent=(recomputed == manifest.digest),
        manifest_digest=manifest.digest,
        digest_recomputed=recomputed,
        artifact_present=path.is_file(),
        file_match=False,
        expected_file_sha256=manifest.file_sha256,
        actual_file_sha256=None,
        expected_size=manifest.file_size_bytes,
        actual_size=None,
        expected_graph_digest=manifest.graph_digest,
        expected_parameter_digest=manifest.parameter_digest,
    )
    if not result.artifact_present:
        result.notes.append(f"artifact not found at {path}")
        return result

    result.actual_file_sha256 = sha256_file(path)
    result.actual_size = path.stat().st_size
    result.file_match = result.actual_file_sha256 == manifest.file_sha256

    if adapter is None:
        from .base import detect_model_adapter

        try:
            adapter = detect_model_adapter(path)
        except Exception as exc:  # noqa: BLE001 - reported, never raised through
            result.notes.append(
                f"structural re-verification unavailable: {exc}"
            )
            return result

    try:
        handle = adapter.load(path)
        rebuilt = build_model_manifest(handle, adapter)
    except Exception as exc:  # noqa: BLE001 - reported, never raised through
        result.notes.append(f"artifact could not be re-loaded for comparison: {exc}")
        return result

    result.actual_graph_digest = rebuilt.graph_digest
    result.actual_parameter_digest = rebuilt.parameter_digest
    if manifest.graph_digest is not None and rebuilt.graph_digest is not None:
        result.graph_match = manifest.graph_digest == rebuilt.graph_digest
    if manifest.parameter_digest is not None and rebuilt.parameter_digest is not None:
        result.parameter_match = manifest.parameter_digest == rebuilt.parameter_digest
        if not result.parameter_match:
            result.changed_parameters = diff_parameter_records(
                manifest.parameters, rebuilt.parameters
            )
    return result


def diff_parameter_records(
    expected: Sequence[ParameterRecord], actual: Sequence[ParameterRecord]
) -> list[dict[str, Any]]:
    """Per-tensor difference between two parameter record sets.

    Reports added, removed, reshaped and content-changed tensors separately: a
    reshaped tensor is a structural change, a content-changed tensor is a weight
    change, and conflating them would lose the distinction the manifest exists
    to preserve.
    """
    left = {p.name: p for p in expected}
    right = {p.name: p for p in actual}
    out: list[dict[str, Any]] = []
    for name in sorted(set(left) | set(right)):
        a, b = left.get(name), right.get(name)
        if a is None:
            out.append({"name": name, "change": "added", "shape": list(b.shape),
                        "count": b.count})
        elif b is None:
            out.append({"name": name, "change": "removed", "shape": list(a.shape),
                        "count": a.count})
        elif tuple(a.shape) != tuple(b.shape) or a.dtype != b.dtype:
            out.append({
                "name": name, "change": "respecified",
                "expected_shape": list(a.shape), "actual_shape": list(b.shape),
                "expected_dtype": a.dtype, "actual_dtype": b.dtype,
            })
        elif a.digest != b.digest:
            out.append({
                "name": name, "change": "content_changed",
                "expected_digest": a.digest, "actual_digest": b.digest,
                "count": a.count, "shape": list(a.shape),
            })
    return out


def load_model_manifest(path: Path | str) -> ModelManifest:
    path = Path(path)
    try:
        manifest = ModelManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VerificationError(f"cannot read model manifest {path}: {exc}") from exc
    if manifest.recompute_digest() != manifest.digest:
        raise VerificationError(
            f"model manifest {path} is not self-consistent: its recorded digest "
            f"{manifest.digest[:16]}… does not match the recomputed "
            f"{manifest.recompute_digest()[:16]}…. The manifest file has been altered."
        )
    return manifest


def compare_identity(
    supplied: ModelManifest, reference: ModelManifest
) -> dict[str, Any]:
    """The three-way identity comparison, as a structure an analyst can read.

    ``interpretation`` is derived from the three booleans by an explicit table,
    not by a heuristic, so the mapping is arguable rather than hidden.
    """
    file_match = supplied.file_sha256 == reference.file_sha256
    graph_match: bool | None = None
    parameter_match: bool | None = None
    if supplied.graph_digest is not None and reference.graph_digest is not None:
        graph_match = supplied.graph_digest == reference.graph_digest
    if supplied.parameter_digest is not None and reference.parameter_digest is not None:
        parameter_match = supplied.parameter_digest == reference.parameter_digest

    interpretation, code = _interpret(file_match, graph_match, parameter_match)
    return {
        "reference_model_id": reference.model_id,
        "supplied_model_id": supplied.model_id,
        "reference_sha256": reference.file_sha256,
        "supplied_sha256": supplied.file_sha256,
        "identity_match": file_match,
        "reference_graph_digest": reference.graph_digest,
        "supplied_graph_digest": supplied.graph_digest,
        "graph_match": graph_match,
        "reference_parameter_digest": reference.parameter_digest,
        "supplied_parameter_digest": supplied.parameter_digest,
        "parameter_match": parameter_match,
        "reference_parameter_count": reference.parameter_count,
        "supplied_parameter_count": supplied.parameter_count,
        "reference_format": reference.model_format,
        "supplied_format": supplied.model_format,
        "interpretation": interpretation,
        "interpretation_code": code,
    }


def _interpret(
    file_match: bool, graph_match: bool | None, parameter_match: bool | None
) -> tuple[str, str]:
    if file_match:
        return (
            "The supplied artifact is byte-identical to the trusted reference.",
            "IDENTICAL",
        )
    if graph_match is None or parameter_match is None:
        return (
            "The supplied artifact differs from the trusted reference in its bytes. "
            "Structure and weight comparison are unavailable for this format, so "
            "whether the difference is a re-serialisation or a different model "
            "cannot be determined from identity alone.",
            "DIFFERENT_BYTES_STRUCTURE_UNAVAILABLE",
        )
    if graph_match and parameter_match:
        return (
            "The supplied artifact has different bytes but an identical graph and "
            "identical weights: it is a re-serialisation of the reference, not a "
            "different model. Behaviour is expected to be unchanged.",
            "RESERIALISED",
        )
    if graph_match and not parameter_match:
        return (
            "The supplied artifact shares the reference architecture but carries "
            "different weights. This is consistent with fine-tuning, retraining or "
            "a weight-level backdoor; identity alone cannot distinguish them, and "
            "the parameter, behavioural and backdoor assessments below are what "
            "separate these cases.",
            "SAME_ARCHITECTURE_DIFFERENT_WEIGHTS",
        )
    return (
        "The supplied artifact differs from the trusted reference in architecture "
        "as well as in weights: a different model is being served.",
        "DIFFERENT_MODEL",
    )
