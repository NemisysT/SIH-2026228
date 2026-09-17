"""Dataset adapter interface and the format-neutral in-memory representation.

Adapters answer exactly one question: *what does this dataset claim about
itself?*  They parse, they normalise, and they record structural problems as
:class:`IngestIssue` values — but they never decide whether anything is
suspicious.  That separation matters: an adapter that silently repaired a
malformed annotation would erase the evidence that it was malformed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from ..core.registry import Registry


class Task(str, Enum):
    CLASSIFICATION = "classification"
    DETECTION = "detection"


class IssueCode(str, Enum):
    """Structural problems an adapter can observe while parsing.

    Every code maps to a deterministic finding in the ``integrity`` detector.
    """

    MISSING_IMAGE_FILE = "missing_image_file"
    UNREADABLE_IMAGE = "unreadable_image"
    EMPTY_FILE = "empty_file"
    DIMENSION_MISMATCH = "dimension_mismatch"
    ORPHAN_ANNOTATION = "orphan_annotation"
    UNLABELLED_SAMPLE = "unlabelled_sample"
    UNKNOWN_CATEGORY = "unknown_category"
    INVALID_BBOX = "invalid_bbox"
    BBOX_OUT_OF_BOUNDS = "bbox_out_of_bounds"
    DUPLICATE_ID = "duplicate_id"
    MALFORMED_RECORD = "malformed_record"
    UNSUPPORTED_EXTENSION = "unsupported_extension"


@dataclass(frozen=True, slots=True)
class IngestIssue:
    """One observed structural defect.  Facts only, no interpretation."""

    code: IssueCode
    locator: str
    message: str
    observation: Mapping[str, Any] = field(default_factory=dict)
    sample_id: str | None = None


@dataclass(frozen=True, slots=True)
class ObjectAnnotation:
    """One annotated object.  ``bbox`` is absolute pixels, ``(x1, y1, x2, y2)``."""

    annotation_id: str
    category: str
    bbox: tuple[float, float, float, float] | None = None
    native: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawSample:
    """One dataset sample as the dataset *claims* it to be."""

    sample_id: str
    relpath: str
    abspath: Path
    labels: tuple[str, ...] = ()
    annotations: tuple[ObjectAnnotation, ...] = ()
    declared_width: int | None = None
    declared_height: int | None = None
    native: Mapping[str, Any] = field(default_factory=dict)

    @property
    def primary_label(self) -> str | None:
        """The single label used by label-consistency analysis.

        For classification this is the image label.  For detection, a sample
        carries many object labels and image-level label analysis is not
        meaningful, so this is ``None`` and the label detectors operate on
        object crops instead (see ``detectors/label_consistency.py``).
        """
        return self.labels[0] if len(self.labels) == 1 else None


@dataclass
class RawDataset:
    """Format-neutral dataset view produced by an adapter."""

    name: str
    root: Path
    adapter: str
    adapter_version: str
    task: Task
    classes: tuple[str, ...]
    samples: list[RawSample]
    issues: list[IngestIssue] = field(default_factory=list)
    native: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Deterministic sample ordering is a prerequisite for a deterministic
        # manifest digest, so it is enforced here rather than trusted to
        # filesystem iteration order, which differs between platforms.
        self.samples.sort(key=lambda s: s.sample_id)
        self.issues.sort(key=lambda i: (i.code.value, i.locator, i.message))


@runtime_checkable
class DatasetAdapter(Protocol):
    """Contract every dataset format implementation satisfies."""

    name: str
    version: str

    @staticmethod
    def detect(root: Path) -> bool:
        """Cheap structural test: could this root plausibly be this format?"""

    def load(self, root: Path) -> RawDataset:
        """Parse the dataset.  Must not raise on malformed *content* — record
        an :class:`IngestIssue` instead.  May raise :class:`AdapterError` if the
        root is not this format at all."""


ADAPTERS: Registry[DatasetAdapter] = Registry("dataset adapter")

IMAGE_EXTENSIONS = frozenset(
    {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}
)


def detect_adapter(root: Path) -> DatasetAdapter:
    """Pick an adapter for ``root``.

    Detection order is alphabetical and therefore deterministic; ambiguity is an
    error the operator resolves with ``--adapter`` rather than something the
    tool guesses at, because guessing the format wrong silently changes what
    "the dataset" means.
    """
    from ..core.errors import AdapterError

    matches = [adapter for _, adapter in ADAPTERS if adapter.detect(root)]
    if not matches:
        raise AdapterError(
            f"no registered adapter recognises {root}; "
            f"tried: {', '.join(ADAPTERS.names())}"
        )
    if len(matches) > 1:
        names = ", ".join(a.name for a in matches)
        raise AdapterError(
            f"ambiguous dataset format at {root}: {names}. "
            "Select one explicitly with --adapter."
        )
    return matches[0]
