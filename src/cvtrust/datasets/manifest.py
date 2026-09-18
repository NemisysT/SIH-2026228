"""Dataset manifest — the cryptographic identity of a dataset.

The manifest is the hinge between Module 1 and everything that follows.  Its
``digest`` is the dataset's identity: Module 3 binds inference records to it,
Module 4 references it when declaring a reference distribution, and
``cvtrust dataset verify`` re-derives it to prove the dataset on disk is still
the dataset that was assessed.

Design notes
------------
* Two digests per sample (``file_sha256`` over container bytes, ``pixel_sha256``
  over decoded content) — see :mod:`cvtrust.core.hashing` for why.
* The manifest is **float-free on the digest path**: floating-point values are
  passed through ``digest_safe`` before hashing (ADR-004), so the digest cannot
  drift with a platform's float formatting.
* ``manifest_id`` and ``digest`` are derived from content, and ``created_at`` is
  excluded from the digest.  Building the same dataset twice yields the same
  digest; only the recorded creation time differs.
* The format is signature-ready: Module 3 attaches a detached Ed25519 signature
  over ``digest`` without changing this schema.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

import numpy as np
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import digest_safe
from ..core.evidence import utc_now_iso
from ..core.hashing import HASH_ALGORITHM, pixel_sha256, sha256_canonical, sha256_file, short
from ..core.logging import get_logger
from .base import IngestIssue, IssueCode, RawDataset, RawSample
from .contributors import Attribution, ContributorResolver

log = get_logger("datasets.manifest")

MANIFEST_SCHEMA_VERSION = "1.0"

# Pillow refuses very large images by default as a decompression-bomb guard.
# We keep the guard (an oversized image is itself a finding) but raise the limit
# so that legitimate high-resolution imagery is not rejected outright.
Image.MAX_IMAGE_PIXELS = 512_000_000


class AnnotationRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    annotation_id: str
    category: str
    bbox_xyxy: tuple[float, float, float, float] | None = None


class SampleRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_id: str
    relpath: str
    size_bytes: int
    file_sha256: str | None
    pixel_sha256: str | None
    width: int | None
    height: int | None
    mode: str | None
    image_format: str | None
    labels: tuple[str, ...]
    annotations: tuple[AnnotationRecord, ...]
    contributor: str
    batch: str | None
    source: str | None
    attribution_source: str
    readable: bool


class DatasetManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = MANIFEST_SCHEMA_VERSION
    manifest_id: str
    created_at: str
    hash_algorithm: str = HASH_ALGORITHM
    dataset: dict[str, Any]
    counts: dict[str, int]
    classes: tuple[str, ...]
    contributors: dict[str, dict[str, Any]]
    attribution: dict[str, Any]
    samples: tuple[SampleRecord, ...]
    digest: str

    def digest_payload(self) -> dict[str, Any]:
        """The exact structure the digest is taken over.

        ``manifest_id``, ``created_at`` and ``digest`` itself are excluded: they
        are either derived from the digest or genuinely volatile.
        """
        payload = self.model_dump(mode="json")
        for volatile in ("manifest_id", "created_at", "digest"):
            payload.pop(volatile, None)
        return payload

    def recompute_digest(self) -> str:
        return sha256_canonical(digest_safe(self.digest_payload()))

    def sample(self, sample_id: str) -> SampleRecord | None:
        return self._index().get(sample_id)

    def _index(self) -> dict[str, SampleRecord]:
        cached = getattr(self, "__index_cache", None)
        if cached is None:
            cached = {s.sample_id: s for s in self.samples}
            object.__setattr__(self, "__index_cache", cached)
        return cached


class ImageFacts(BaseModel):
    """Measured facts about one image file, independent of what it claims."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_id: str
    exists: bool
    readable: bool
    size_bytes: int
    file_sha256: str | None
    pixel_sha256: str | None
    width: int | None
    height: int | None
    mode: str | None
    image_format: str | None
    error: str | None = None


def measure_image(sample: RawSample) -> tuple[ImageFacts, IngestIssue | None]:
    """Hash and decode one sample, recording failures as issues rather than raising."""
    path = sample.abspath
    if not path.is_file():
        return (
            ImageFacts(
                sample_id=sample.sample_id, exists=False, readable=False, size_bytes=0,
                file_sha256=None, pixel_sha256=None, width=None, height=None,
                mode=None, image_format=None, error="file not found",
            ),
            IngestIssue(
                code=IssueCode.MISSING_IMAGE_FILE,
                locator=sample.relpath,
                message="the dataset declares this image but the file does not exist",
                observation={"relpath": sample.relpath},
                sample_id=sample.sample_id,
            ),
        )

    size = path.stat().st_size
    file_digest = sha256_file(path)

    if size == 0:
        return (
            ImageFacts(
                sample_id=sample.sample_id, exists=True, readable=False, size_bytes=0,
                file_sha256=file_digest, pixel_sha256=None, width=None, height=None,
                mode=None, image_format=None, error="empty file",
            ),
            IngestIssue(
                code=IssueCode.EMPTY_FILE,
                locator=sample.relpath,
                message="image file is zero bytes",
                observation={"relpath": sample.relpath, "file_sha256": file_digest},
                sample_id=sample.sample_id,
            ),
        )

    try:
        with Image.open(path) as img:
            image_format = img.format
            mode = img.mode
            # Full decode: Image.open is lazy and a truncated file only fails here.
            rgb = img.convert("RGB")
            array = np.asarray(rgb, dtype=np.uint8)
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        return (
            ImageFacts(
                sample_id=sample.sample_id, exists=True, readable=False, size_bytes=size,
                file_sha256=file_digest, pixel_sha256=None, width=None, height=None,
                mode=None, image_format=None, error=f"{type(exc).__name__}: {exc}",
            ),
            IngestIssue(
                code=IssueCode.UNREADABLE_IMAGE,
                locator=sample.relpath,
                message=f"image cannot be decoded: {type(exc).__name__}",
                observation={
                    "relpath": sample.relpath,
                    "size_bytes": size,
                    "file_sha256": file_digest,
                    "error": str(exc)[:300],
                },
                sample_id=sample.sample_id,
            ),
        )

    height, width = array.shape[0], array.shape[1]
    return (
        ImageFacts(
            sample_id=sample.sample_id, exists=True, readable=True, size_bytes=size,
            file_sha256=file_digest, pixel_sha256=pixel_sha256(array, "RGB"),
            width=width, height=height, mode=mode, image_format=image_format,
        ),
        None,
    )


def resolve_bbox(
    annotation_native: Mapping[str, Any],
    bbox: tuple[float, float, float, float] | None,
    width: int | None,
    height: int | None,
) -> tuple[float, float, float, float] | None:
    """Return an absolute ``(x1, y1, x2, y2)`` box.

    YOLO boxes are normalised and can only be converted once the true image
    dimensions are known, which is the manifest stage.
    """
    if bbox is not None:
        return bbox
    norm = annotation_native.get("norm_bbox")
    if not norm or width is None or height is None:
        return None
    cx, cy, bw, bh = (float(v) for v in norm)
    return (
        (cx - bw / 2) * width,
        (cy - bh / 2) * height,
        (cx + bw / 2) * width,
        (cy + bh / 2) * height,
    )


def build_manifest(
    dataset: RawDataset,
    resolver: ContributorResolver,
    *,
    facts: Mapping[str, ImageFacts] | None = None,
) -> tuple[DatasetManifest, dict[str, ImageFacts], dict[str, Attribution], list[IngestIssue]]:
    """Measure every sample and produce the dataset manifest.

    Returns the manifest, the measured facts, the resolved attributions, and any
    additional issues discovered while measuring (missing/corrupt files,
    declared-vs-actual dimension mismatches).
    """
    measured: dict[str, ImageFacts] = dict(facts or {})
    attributions: dict[str, Attribution] = {}
    issues: list[IngestIssue] = []
    records: list[SampleRecord] = []

    for sample in dataset.samples:
        if sample.sample_id in measured:
            fact = measured[sample.sample_id]
        else:
            fact, issue = measure_image(sample)
            measured[sample.sample_id] = fact
            if issue is not None:
                issues.append(issue)

        attribution = resolver.resolve(sample)
        attributions[sample.sample_id] = attribution

        if (
            fact.readable
            and sample.declared_width is not None
            and sample.declared_height is not None
            and (sample.declared_width, sample.declared_height) != (fact.width, fact.height)
        ):
            issues.append(
                IngestIssue(
                    code=IssueCode.DIMENSION_MISMATCH,
                    locator=sample.relpath,
                    message="annotation-declared image size does not match the file",
                    observation={
                        "declared": [sample.declared_width, sample.declared_height],
                        "actual": [fact.width, fact.height],
                        "relpath": sample.relpath,
                    },
                    sample_id=sample.sample_id,
                )
            )

        ann_records: list[AnnotationRecord] = []
        for ann in sample.annotations:
            box = resolve_bbox(ann.native, ann.bbox, fact.width, fact.height)
            if box is not None and fact.readable:
                issues.extend(_bbox_issues(sample, ann.annotation_id, box, fact))
            ann_records.append(
                AnnotationRecord(
                    annotation_id=ann.annotation_id,
                    category=ann.category,
                    bbox_xyxy=box,
                )
            )

        records.append(
            SampleRecord(
                sample_id=sample.sample_id,
                relpath=sample.relpath,
                size_bytes=fact.size_bytes,
                file_sha256=fact.file_sha256,
                pixel_sha256=fact.pixel_sha256,
                width=fact.width,
                height=fact.height,
                mode=fact.mode,
                image_format=fact.image_format,
                labels=sample.labels,
                annotations=tuple(ann_records),
                contributor=attribution.contributor,
                batch=attribution.batch,
                source=attribution.source,
                attribution_source=attribution.attribution_source.value,
                readable=fact.readable,
            )
        )

    records.sort(key=lambda r: r.sample_id)
    contributor_summary = _summarise_contributors(records)

    payload: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "dataset": {
            "name": dataset.name,
            "adapter": dataset.adapter,
            "adapter_version": dataset.adapter_version,
            "task": dataset.task.value,
            **{k: v for k, v in (dataset.native or {}).items()},
        },
        "counts": {
            "samples": len(records),
            "readable": sum(1 for r in records if r.readable),
            "unreadable": sum(1 for r in records if not r.readable),
            "annotations": sum(len(r.annotations) for r in records),
            "classes": len(dataset.classes),
            "contributors": len(contributor_summary),
            "ingest_issues": len(dataset.issues) + len(issues),
        },
        "classes": list(dataset.classes),
        "contributors": contributor_summary,
        "attribution": resolver.describe(),
        "samples": [r.model_dump(mode="json") for r in records],
    }
    digest = sha256_canonical(digest_safe(payload))

    manifest = DatasetManifest(
        manifest_id=short(digest, 16),
        created_at=utc_now_iso(),
        dataset=payload["dataset"],
        counts=payload["counts"],
        classes=dataset.classes,
        contributors=contributor_summary,
        attribution=payload["attribution"],
        samples=tuple(records),
        digest=digest,
    )
    log.info(
        "manifest built: %d samples, digest %s", len(records), short(digest, 12)
    )
    return manifest, measured, attributions, issues


def _bbox_issues(
    sample: RawSample, annotation_id: str, box: tuple[float, float, float, float], fact: ImageFacts
) -> Iterable[IngestIssue]:
    x1, y1, x2, y2 = box
    width, height = fact.width or 0, fact.height or 0
    if x2 <= x1 or y2 <= y1:
        yield IngestIssue(
            code=IssueCode.INVALID_BBOX,
            locator=sample.relpath,
            message=f"annotation {annotation_id} has non-positive area",
            observation={"bbox_xyxy": [x1, y1, x2, y2], "annotation_id": annotation_id},
            sample_id=sample.sample_id,
        )
        return
    # One pixel of tolerance absorbs benign float rounding in format conversion.
    if x1 < -1 or y1 < -1 or x2 > width + 1 or y2 > height + 1:
        yield IngestIssue(
            code=IssueCode.BBOX_OUT_OF_BOUNDS,
            locator=sample.relpath,
            message=f"annotation {annotation_id} extends outside the image",
            observation={
                "bbox_xyxy": [x1, y1, x2, y2],
                "image_size": [width, height],
                "annotation_id": annotation_id,
            },
            sample_id=sample.sample_id,
        )


def _summarise_contributors(records: Iterable[SampleRecord]) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for record in records:
        entry = summary.setdefault(
            record.contributor,
            {"samples": 0, "batches": set(), "sources": set(), "attribution_sources": set()},
        )
        entry["samples"] += 1
        if record.batch:
            entry["batches"].add(record.batch)
        if record.source:
            entry["sources"].add(record.source)
        entry["attribution_sources"].add(record.attribution_source)
    return {
        name: {
            "samples": entry["samples"],
            "batches": sorted(entry["batches"]),
            "sources": sorted(entry["sources"]),
            "attribution_sources": sorted(entry["attribution_sources"]),
        }
        for name, entry in sorted(summary.items())
    }


class VerificationResult(BaseModel):
    """Outcome of re-verifying a manifest against the dataset on disk."""

    model_config = ConfigDict(extra="forbid")

    manifest_id: str
    manifest_digest: str
    digest_recomputed: str
    manifest_self_consistent: bool
    dataset_matches: bool
    checked: int
    missing: list[str] = Field(default_factory=list)
    modified: list[dict[str, Any]] = Field(default_factory=list)
    added: list[str] = Field(default_factory=list)


def verify_manifest(manifest: DatasetManifest, root: Path) -> VerificationResult:
    """Re-hash the dataset on disk and compare it with the manifest.

    Two independent checks:

    1. **Manifest self-consistency** — the manifest's own ``digest`` still
       matches its content, which detects tampering with the manifest file.
    2. **Dataset correspondence** — every recorded file still hashes to the
       recorded value, nothing recorded is missing, and nothing has appeared
       in the recorded directories that the manifest does not know about.
    """
    missing: list[str] = []
    modified: list[dict[str, Any]] = []
    for record in manifest.samples:
        path = root / record.relpath
        if not path.is_file():
            missing.append(record.relpath)
            continue
        if record.file_sha256 is None:
            continue
        actual = sha256_file(path)
        if actual != record.file_sha256:
            modified.append(
                {
                    "relpath": record.relpath,
                    "expected_sha256": record.file_sha256,
                    "actual_sha256": actual,
                    "expected_size": record.size_bytes,
                    "actual_size": path.stat().st_size,
                }
            )

    known = {r.relpath for r in manifest.samples}
    watched_dirs = {str(Path(r).parent) for r in known}
    added: list[str] = []
    for directory in sorted(watched_dirs):
        base = root / directory if directory != "." else root
        if not base.is_dir():
            continue
        for path in sorted(base.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            rel = path.relative_to(root).as_posix()
            if rel not in known and path.suffix.lower() in {
                ".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp",
            }:
                added.append(rel)

    recomputed = manifest.recompute_digest()
    return VerificationResult(
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.digest,
        digest_recomputed=recomputed,
        manifest_self_consistent=(recomputed == manifest.digest),
        dataset_matches=not (missing or modified or added),
        checked=len(manifest.samples),
        missing=missing,
        modified=modified,
        added=added,
    )
