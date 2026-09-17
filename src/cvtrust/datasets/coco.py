"""COCO detection-format adapter.

Parses ``images``, ``annotations`` and ``categories``.  Everything that does not
parse cleanly becomes an :class:`IngestIssue` rather than an exception, because
malformed annotation records are themselves a supported threat
(``metadata_inconsistency``) and must reach the analyst as evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.errors import AdapterError
from .base import (
    ADAPTERS,
    IngestIssue,
    IssueCode,
    ObjectAnnotation,
    RawDataset,
    RawSample,
    Task,
)


def _find_annotation_file(root: Path) -> Path | None:
    candidates = sorted(root.glob("annotations/*.json")) + sorted(root.glob("*.json"))
    for candidate in candidates:
        # contributors.json is provenance metadata, not annotations.
        if candidate.name == "contributors.json":
            continue
        try:
            with open(candidate, "rb") as handle:
                head = handle.read(4096).decode("utf-8", "ignore")
        except OSError:
            continue
        if '"images"' in head and '"annotations"' in head:
            return candidate
    return None


class CocoAdapter:
    name = "coco"
    version = "1.0"

    @staticmethod
    def detect(root: Path) -> bool:
        return root.is_dir() and _find_annotation_file(root) is not None

    def load(self, root: Path) -> RawDataset:
        ann_path = _find_annotation_file(root)
        if ann_path is None:
            raise AdapterError(f"no COCO annotation JSON found under {root}")
        try:
            doc: Any = json.loads(ann_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterError(f"cannot parse COCO annotations {ann_path}: {exc}") from exc
        if not isinstance(doc, dict):
            raise AdapterError(f"COCO annotation root must be an object: {ann_path}")

        issues: list[IngestIssue] = []
        ann_rel = ann_path.relative_to(root).as_posix()

        categories: dict[int, str] = {}
        for entry in doc.get("categories", []) or []:
            if not isinstance(entry, dict) or "id" not in entry or "name" not in entry:
                issues.append(
                    IngestIssue(
                        code=IssueCode.MALFORMED_RECORD,
                        locator=ann_rel,
                        message="category record missing 'id' or 'name'",
                        observation={"record": _truncate(entry)},
                    )
                )
                continue
            categories[int(entry["id"])] = str(entry["name"])

        image_dir = root / "images" if (root / "images").is_dir() else root

        images: dict[int, dict[str, Any]] = {}
        seen_ids: set[int] = set()
        for entry in doc.get("images", []) or []:
            if not isinstance(entry, dict) or "id" not in entry or "file_name" not in entry:
                issues.append(
                    IngestIssue(
                        code=IssueCode.MALFORMED_RECORD,
                        locator=ann_rel,
                        message="image record missing 'id' or 'file_name'",
                        observation={"record": _truncate(entry)},
                    )
                )
                continue
            image_id = int(entry["id"])
            if image_id in seen_ids:
                issues.append(
                    IngestIssue(
                        code=IssueCode.DUPLICATE_ID,
                        locator=ann_rel,
                        message=f"duplicate COCO image id {image_id}",
                        observation={"image_id": image_id, "file_name": entry["file_name"]},
                    )
                )
                continue
            seen_ids.add(image_id)
            images[image_id] = entry

        per_image: dict[int, list[ObjectAnnotation]] = {i: [] for i in images}
        for entry in doc.get("annotations", []) or []:
            if not isinstance(entry, dict) or "image_id" not in entry:
                issues.append(
                    IngestIssue(
                        code=IssueCode.MALFORMED_RECORD,
                        locator=ann_rel,
                        message="annotation record missing 'image_id'",
                        observation={"record": _truncate(entry)},
                    )
                )
                continue
            image_id = int(entry["image_id"])
            if image_id not in images:
                issues.append(
                    IngestIssue(
                        code=IssueCode.ORPHAN_ANNOTATION,
                        locator=ann_rel,
                        message=f"annotation {entry.get('id')} references unknown "
                        f"image_id {image_id}",
                        observation={
                            "annotation_id": entry.get("id"),
                            "image_id": image_id,
                        },
                    )
                )
                continue

            cat_id = entry.get("category_id")
            category = categories.get(int(cat_id)) if cat_id is not None else None
            relpath = _image_relpath(root, image_dir, images[image_id]["file_name"])
            if category is None:
                issues.append(
                    IngestIssue(
                        code=IssueCode.UNKNOWN_CATEGORY,
                        locator=relpath,
                        message=f"annotation references category_id {cat_id!r} that is "
                        "not declared in 'categories'",
                        observation={
                            "annotation_id": entry.get("id"),
                            "category_id": cat_id,
                            "declared_categories": sorted(categories),
                        },
                        sample_id=relpath,
                    )
                )
                category = f"__unknown_{cat_id}__"

            bbox = _parse_bbox(entry.get("bbox"))
            if entry.get("bbox") is not None and bbox is None:
                issues.append(
                    IngestIssue(
                        code=IssueCode.INVALID_BBOX,
                        locator=relpath,
                        message=f"annotation {entry.get('id')} has a malformed bbox",
                        observation={
                            "annotation_id": entry.get("id"),
                            "bbox": _truncate(entry.get("bbox")),
                        },
                        sample_id=relpath,
                    )
                )

            per_image[image_id].append(
                ObjectAnnotation(
                    annotation_id=str(entry.get("id", f"{image_id}:{len(per_image[image_id])}")),
                    category=category,
                    bbox=bbox,
                    native={"category_id": cat_id},
                )
            )

        samples: list[RawSample] = []
        for image_id, entry in images.items():
            relpath = _image_relpath(root, image_dir, entry["file_name"])
            abspath = root / relpath
            anns = tuple(sorted(per_image[image_id], key=lambda a: a.annotation_id))
            if not anns:
                issues.append(
                    IngestIssue(
                        code=IssueCode.UNLABELLED_SAMPLE,
                        locator=relpath,
                        message="image has no annotations",
                        observation={"image_id": image_id, "relpath": relpath},
                        sample_id=relpath,
                    )
                )
            samples.append(
                RawSample(
                    sample_id=relpath,
                    relpath=relpath,
                    abspath=abspath,
                    labels=tuple(sorted({a.category for a in anns})),
                    annotations=anns,
                    declared_width=_as_int(entry.get("width")),
                    declared_height=_as_int(entry.get("height")),
                    native={
                        k: v
                        for k, v in entry.items()
                        if k in {"contributor", "batch", "source", "license", "date_captured"}
                    },
                )
            )

        if not samples:
            raise AdapterError(f"COCO annotations at {ann_path} declare no images")

        return RawDataset(
            name=root.name,
            root=root,
            adapter=self.name,
            adapter_version=self.version,
            task=Task.DETECTION,
            classes=tuple(sorted(categories.values())),
            samples=samples,
            issues=issues,
            native={"annotation_file": ann_rel},
        )


def _image_relpath(root: Path, image_dir: Path, file_name: str) -> str:
    candidate = (image_dir / file_name).resolve()
    try:
        return candidate.relative_to(root.resolve()).as_posix()
    except ValueError:
        # file_name escaped the dataset root (e.g. '../../etc/passwd'); keep it
        # visible as-is so the integrity detector reports a missing file rather
        # than the adapter following the traversal.
        return file_name


def _parse_bbox(value: Any) -> tuple[float, float, float, float] | None:
    """COCO bbox is ``[x, y, w, h]``; normalised here to ``(x1, y1, x2, y2)``."""
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    try:
        x, y, w, h = (float(v) for v in value)
    except (TypeError, ValueError):
        return None
    return (x, y, x + w, y + h)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _truncate(value: Any, limit: int = 200) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "..."


ADAPTERS.add("coco", CocoAdapter())
