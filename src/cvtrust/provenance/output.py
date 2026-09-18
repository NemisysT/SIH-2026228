"""Canonical inference-output representation.

Signing ``prediction = "wheel_defect"`` binds a string, not an inference.  It
does not say which of several boxes carried that label, what the confidence was,
which label vocabulary the index referred to, or whether a second detection was
dropped afterwards.  An output binding is only worth having if the thing bound
is the *whole* output, in exactly one byte representation.

So Module 3 defines a closed output schema and a canonicalisation for it, and
``output_digest`` is SHA-256 over those canonical bytes.

Two rules do the work:

**Floating point.**  Every real-valued quantity — confidence, box coordinate,
keypoint position — is quantised onto a fixed decimal grid and carried as an
integer, exactly as Module 1 does for configuration (ADR-004).  The number of
places is recorded in the output itself, so the grid is part of what was signed
rather than a convention two implementations might disagree about.  An IEEE-754
double has no canonical textual form that is both round-trippable and
cross-platform-stable, and every subtlety in RFC 8785 number formatting becomes
a signature-verification bug.

**Ordering.**  Detections and classification scores are *sets*: an inference
engine that emits the same three boxes in a different order produced the same
output, and the canonical bytes must agree.  They are therefore sorted into a
total, documented order — descending quantised score first (so a human reading
the record sees the ranking), then the item's own canonical bytes as a
tiebreaker, which is total because two items with identical canonical bytes are
the same item.  Keypoints are **not** sorted by score: their index is semantic
(index 0 is not interchangeable with index 3), so they are ordered by index.

**Masks.**  A segmentation mask is bound by digest, not embedded.  The digest
covers the mask buffer together with its shape and dtype, using the same header
construction as :func:`cvtrust.core.hashing.pixel_sha256`, so two buffers that
share bytes under different interpretations cannot collide.  The consequence is
stated rather than hidden: the record establishes *which* mask was produced, and
a verifier needs the mask artifact itself to re-derive that digest.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Mapping, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import canonical_json, digest_safe, quantize
from ..core.errors import ProvenanceError
from ..core.hashing import sha256_canonical

OUTPUT_SCHEMA_VERSION = "1.0"

#: Decimal places used to put every real-valued output quantity on a fixed grid.
#:
#: Six places is far finer than any meaningful difference in a confidence score
#: or a pixel coordinate, and far coarser than float32 epsilon, so the digest is
#: stable across runtimes without being blind to a genuine change.  The value is
#: recorded in every output record, so a future change to this constant produces
#: a visibly different output rather than a silently incompatible one.
OUTPUT_QUANT_PLACES = 6

#: The ordering rule applied before digesting.  Recorded in the output so that a
#: verifier knows which rule produced the bytes it is checking.
ORDERING_POLICY = "canonical_sorted_v1"


class OutputTask(str, Enum):
    """The output shapes this schema can represent.

    A closed vocabulary on purpose.  ``RAW`` exists so that a pipeline whose
    output does not fit the CV shapes can still be bound — it carries an opaque
    digest-safe structure — but it is named ``RAW`` rather than allowed to
    masquerade as a typed output, because a verifier reading ``RAW`` knows the
    schema imposed no structure on what it is checking.
    """

    CLASSIFICATION = "classification"
    DETECTION = "detection"
    SEGMENTATION = "segmentation"
    KEYPOINTS = "keypoints"
    EMBEDDING = "embedding"
    RAW = "raw"


class ClassScore(BaseModel):
    """One (label, confidence) pair."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(min_length=1)
    #: Confidence on the fixed decimal grid. An integer, never a float.
    score_q: int


class Detection(BaseModel):
    """One detected instance.

    ``box`` is ``(x_min, y_min, x_max, y_max)`` on the fixed grid, in the
    coordinate space named by :attr:`CanonicalOutput.coordinate_space`.  The
    space is bound rather than assumed: the same four numbers mean different
    things in pixel coordinates of the original image, pixel coordinates of the
    letterboxed input, and normalised ``[0, 1]`` coordinates, and an analyst
    comparing two records must not have to guess which.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str = Field(min_length=1)
    score_q: int
    box: tuple[int, int, int, int]
    instance_id: str | None = None
    mask_digest: str | None = Field(
        default=None,
        description="SHA-256 of this instance's mask buffer, when one exists.",
    )


class Keypoint(BaseModel):
    """One keypoint.  ``index`` is semantic and fixes the ordering."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(ge=0)
    name: str | None = None
    x_q: int
    y_q: int
    score_q: int | None = None
    visible: bool | None = None


class MaskRecord(BaseModel):
    """A segmentation mask, bound by digest rather than embedded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    shape: tuple[int, ...]
    dtype: str
    digest: str = Field(min_length=64, max_length=64)
    label_map: tuple[str, ...] = Field(
        default=(),
        description="Class index -> label, when the mask is a label map. "
        "Bound because the same mask buffer means something different under a "
        "different label vocabulary.",
    )


class CanonicalOutput(BaseModel):
    """The canonical representation of one inference output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    output_schema_version: str = OUTPUT_SCHEMA_VERSION
    task: OutputTask
    quantization_places: int = OUTPUT_QUANT_PLACES
    ordering_policy: str = ORDERING_POLICY

    #: The label vocabulary the model emits, in the model's own index order.
    #: Bound because "class 3" is meaningless without it, and because swapping
    #: two entries in the vocabulary changes every prediction the model makes
    #: while leaving the weights untouched.
    labels: tuple[str, ...] = ()
    coordinate_space: str | None = Field(
        default=None,
        description="Named coordinate space for boxes and keypoints, e.g. "
        "'input_pixels', 'original_pixels', 'normalised_01'.",
    )

    classification: tuple[ClassScore, ...] = ()
    detections: tuple[Detection, ...] = ()
    keypoints: tuple[Keypoint, ...] = ()
    masks: tuple[MaskRecord, ...] = ()
    embedding_digest: str | None = Field(
        default=None,
        description="SHA-256 over a quantised embedding vector, when the output "
        "is an embedding. The vector itself is not embedded in the record.",
    )
    embedding_dim: int | None = None

    #: Anything the closed shapes above cannot express, in digest-safe form.
    extra: Mapping[str, Any] = Field(default_factory=dict)

    def canonical_payload(self) -> dict[str, Any]:
        """The exact structure ``output_digest`` is taken over.

        Everything is already float-free by construction, so this is passed to
        :func:`canonical_json` in its strict ``reject`` mode: a float reaching
        this point is a bug in a caller, and it fails loudly rather than being
        silently formatted.
        """
        payload = self.model_dump(mode="json")
        payload["classification"] = _sorted_items(payload["classification"])
        payload["detections"] = _sorted_items(payload["detections"])
        payload["keypoints"] = sorted(
            payload["keypoints"], key=lambda item: (item["index"], canonical_json(item))
        )
        payload["masks"] = sorted(payload["masks"], key=lambda item: item["name"])
        return payload

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.canonical_payload())

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def summary(self) -> str:
        """One line for an analyst.  Never used on an integrity path."""
        places = self.quantization_places
        if self.task is OutputTask.CLASSIFICATION and self.classification:
            top = max(self.classification, key=lambda c: c.score_q)
            return f"{top.label} ({top.score_q / (10**places):.3f})"
        if self.task is OutputTask.DETECTION:
            return f"{len(self.detections)} detection(s)"
        if self.task is OutputTask.SEGMENTATION:
            return f"{len(self.masks)} mask(s)"
        if self.task is OutputTask.KEYPOINTS:
            return f"{len(self.keypoints)} keypoint(s)"
        if self.task is OutputTask.EMBEDDING:
            return f"embedding, dim {self.embedding_dim}"
        return "raw output"


def _sorted_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Total, deterministic order: score descending, then canonical bytes.

    The second key is what makes the order *total*.  Sorting by score alone
    leaves ties in whatever order the engine happened to emit, which would let
    two byte-identical inferences produce two different digests.
    """
    return sorted(
        items,
        key=lambda item: (-int(item.get("score_q") or 0), canonical_json(item)),
    )


def mask_digest(array: np.ndarray, *, label_map: Sequence[str] = ()) -> str:
    """Content digest of a mask buffer.

    Shape, dtype and the label vocabulary are bound into the digest for the same
    reason :func:`cvtrust.core.hashing.pixel_sha256` binds shape and mode: a
    buffer reinterpreted under a different shape or a different class vocabulary
    is a different output, and must not share a digest with the original.
    """
    data = np.ascontiguousarray(array)
    digest = hashlib.sha256()
    header = f"mask|{data.dtype.str}|{'x'.join(str(d) for d in data.shape)}|"
    digest.update(header.encode("utf-8"))
    digest.update(canonical_json(list(label_map)))
    digest.update(b"|")
    digest.update(data.tobytes())
    return digest.hexdigest()


def embedding_digest(vector: np.ndarray, places: int = OUTPUT_QUANT_PLACES) -> str:
    """Digest of an embedding, quantised so it is independent of storage dtype."""
    flat = np.asarray(vector, dtype=np.float64).ravel()
    if not np.all(np.isfinite(flat)):
        raise ProvenanceError(
            "embedding contains non-finite values; a non-finite activation is "
            "itself a finding and must not be folded silently into a digest"
        )
    scaled = np.rint(flat * (10**places)).astype(np.int64)
    return sha256_canonical(
        {"kind": "embedding", "places": places, "dim": int(flat.size),
         "values": [int(v) for v in scaled]}
    )


# ---------------------------------------------------------------------------
# Builders.  These are the supported way to get float model output into the
# canonical form, so that quantisation happens in exactly one place.
# ---------------------------------------------------------------------------


def classification_output(
    scores: Mapping[str, float] | Sequence[float],
    *,
    labels: Sequence[str] | None = None,
    places: int = OUTPUT_QUANT_PLACES,
    extra: Mapping[str, Any] | None = None,
) -> CanonicalOutput:
    """Build a classification output from raw float scores."""
    if isinstance(scores, Mapping):
        vocabulary = tuple(labels) if labels is not None else tuple(sorted(scores))
        pairs = [(str(label), float(scores[label])) for label in vocabulary if label in scores]
    else:
        values = [float(v) for v in scores]
        if labels is None:
            vocabulary = tuple(f"class_{i}" for i in range(len(values)))
        else:
            vocabulary = tuple(str(label) for label in labels)
        if len(vocabulary) != len(values):
            raise ProvenanceError(
                f"label vocabulary has {len(vocabulary)} entries but {len(values)} "
                "scores were supplied; a mismatched vocabulary silently relabels "
                "every prediction"
            )
        pairs = list(zip(vocabulary, values))

    return CanonicalOutput(
        task=OutputTask.CLASSIFICATION,
        quantization_places=places,
        labels=vocabulary,
        classification=tuple(
            ClassScore(label=label, score_q=quantize(value, places))
            for label, value in pairs
        ),
        extra=digest_safe(dict(extra or {}), places),
    )


def detection_output(
    detections: Sequence[Mapping[str, Any]],
    *,
    labels: Sequence[str] = (),
    coordinate_space: str = "input_pixels",
    places: int = OUTPUT_QUANT_PLACES,
    extra: Mapping[str, Any] | None = None,
) -> CanonicalOutput:
    """Build a detection output.

    Each entry supplies ``label``, ``score`` and ``box`` as
    ``(x_min, y_min, x_max, y_max)`` floats, and optionally ``instance_id`` and
    ``mask_digest``.
    """
    items: list[Detection] = []
    for index, raw in enumerate(detections):
        try:
            box = tuple(float(v) for v in raw["box"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProvenanceError(f"detection {index} has no usable box: {exc}") from exc
        if len(box) != 4:
            raise ProvenanceError(
                f"detection {index} has {len(box)} box coordinates; four are required"
            )
        items.append(
            Detection(
                label=str(raw["label"]),
                score_q=quantize(float(raw["score"]), places),
                box=tuple(quantize(v, places) for v in box),  # type: ignore[arg-type]
                instance_id=(str(raw["instance_id"]) if raw.get("instance_id") else None),
                mask_digest=(str(raw["mask_digest"]) if raw.get("mask_digest") else None),
            )
        )
    return CanonicalOutput(
        task=OutputTask.DETECTION,
        quantization_places=places,
        labels=tuple(str(label) for label in labels),
        coordinate_space=coordinate_space,
        detections=tuple(items),
        extra=digest_safe(dict(extra or {}), places),
    )


def segmentation_output(
    masks: Sequence[Mapping[str, Any]],
    *,
    labels: Sequence[str] = (),
    places: int = OUTPUT_QUANT_PLACES,
    extra: Mapping[str, Any] | None = None,
) -> CanonicalOutput:
    """Build a segmentation output from mask arrays or pre-computed digests."""
    records: list[MaskRecord] = []
    for index, raw in enumerate(masks):
        label_map = tuple(str(v) for v in raw.get("label_map", ()))
        array = raw.get("array")
        if array is not None:
            data = np.asarray(array)
            records.append(
                MaskRecord(
                    name=str(raw.get("name", f"mask_{index}")),
                    shape=tuple(int(d) for d in data.shape),
                    dtype=str(data.dtype.str),
                    digest=mask_digest(data, label_map=label_map),
                    label_map=label_map,
                )
            )
            continue
        records.append(
            MaskRecord(
                name=str(raw.get("name", f"mask_{index}")),
                shape=tuple(int(d) for d in raw["shape"]),
                dtype=str(raw["dtype"]),
                digest=str(raw["digest"]),
                label_map=label_map,
            )
        )
    return CanonicalOutput(
        task=OutputTask.SEGMENTATION,
        quantization_places=places,
        labels=tuple(str(label) for label in labels),
        masks=tuple(records),
        extra=digest_safe(dict(extra or {}), places),
    )


def keypoint_output(
    keypoints: Sequence[Mapping[str, Any]],
    *,
    coordinate_space: str = "input_pixels",
    places: int = OUTPUT_QUANT_PLACES,
    extra: Mapping[str, Any] | None = None,
) -> CanonicalOutput:
    """Build a keypoint output.  Index is semantic and fixes the ordering."""
    items = [
        Keypoint(
            index=int(raw.get("index", position)),
            name=(str(raw["name"]) if raw.get("name") else None),
            x_q=quantize(float(raw["x"]), places),
            y_q=quantize(float(raw["y"]), places),
            score_q=(quantize(float(raw["score"]), places) if "score" in raw else None),
            visible=(bool(raw["visible"]) if "visible" in raw else None),
        )
        for position, raw in enumerate(keypoints)
    ]
    indices = [item.index for item in items]
    if len(set(indices)) != len(indices):
        raise ProvenanceError(
            "duplicate keypoint indices; the index is the semantic identity of a "
            "keypoint and cannot be repeated"
        )
    return CanonicalOutput(
        task=OutputTask.KEYPOINTS,
        quantization_places=places,
        coordinate_space=coordinate_space,
        keypoints=tuple(items),
        extra=digest_safe(dict(extra or {}), places),
    )


def embedding_output(
    vector: np.ndarray,
    *,
    places: int = OUTPUT_QUANT_PLACES,
    extra: Mapping[str, Any] | None = None,
) -> CanonicalOutput:
    flat = np.asarray(vector).ravel()
    return CanonicalOutput(
        task=OutputTask.EMBEDDING,
        quantization_places=places,
        embedding_digest=embedding_digest(flat, places),
        embedding_dim=int(flat.size),
        extra=digest_safe(dict(extra or {}), places),
    )


def raw_output(
    payload: Mapping[str, Any], *, places: int = OUTPUT_QUANT_PLACES
) -> CanonicalOutput:
    """Bind an output this schema has no shape for.

    Named ``raw`` so that a verifier reading the record knows the schema imposed
    no structure on what it checked.
    """
    return CanonicalOutput(
        task=OutputTask.RAW,
        quantization_places=places,
        extra=digest_safe(dict(payload), places),
    )
