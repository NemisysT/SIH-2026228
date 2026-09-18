"""Dataset ingestion: adapters, contributor attribution, manifests."""

from . import coco, folder, yolo  # noqa: F401  (registration side effects)
from .base import (
    ADAPTERS,
    DatasetAdapter,
    IngestIssue,
    IssueCode,
    ObjectAnnotation,
    RawDataset,
    RawSample,
    Task,
    detect_adapter,
)
from .contributors import Attribution, AttributionSource, ContributorResolver
from .manifest import (
    DatasetManifest,
    ImageFacts,
    SampleRecord,
    VerificationResult,
    build_manifest,
    measure_image,
    resolve_bbox,
    verify_manifest,
)

__all__ = [
    "ADAPTERS", "DatasetAdapter", "IngestIssue", "IssueCode", "ObjectAnnotation",
    "RawDataset", "RawSample", "Task", "detect_adapter",
    "Attribution", "AttributionSource", "ContributorResolver",
    "DatasetManifest", "ImageFacts", "SampleRecord", "VerificationResult",
    "build_manifest", "measure_image", "resolve_bbox", "verify_manifest",
]
