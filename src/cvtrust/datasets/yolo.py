"""YOLO detection-format adapter: ``images/`` + ``labels/`` + a class list.

YOLO label files are normalised ``class cx cy w h`` per line.  Converting to
absolute pixels needs the true image size, which is read from the image itself
rather than from any declaration — a YOLO dataset makes no width/height claim,
so there is nothing to trust or distrust here.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..core.errors import AdapterError
from .base import (
    ADAPTERS,
    IMAGE_EXTENSIONS,
    IngestIssue,
    IssueCode,
    ObjectAnnotation,
    RawDataset,
    RawSample,
    Task,
)


def _load_classes(root: Path) -> tuple[list[str], str | None]:
    """Class names from ``data.yaml`` (preferred) or ``classes.txt``."""
    for name in ("data.yaml", "data.yml", "dataset.yaml"):
        path = root / name
        if path.is_file():
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise AdapterError(f"cannot parse {path}: {exc}") from exc
            names = doc.get("names")
            if isinstance(names, dict):
                ordered = [str(names[k]) for k in sorted(names, key=lambda x: int(x))]
                return ordered, name
            if isinstance(names, list):
                return [str(n) for n in names], name
    path = root / "classes.txt"
    if path.is_file():
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()]
        return [ln for ln in lines if ln], "classes.txt"
    return [], None


class YoloAdapter:
    name = "yolo"
    version = "1.0"

    @staticmethod
    def detect(root: Path) -> bool:
        if not root.is_dir():
            return False
        if not (root / "images").is_dir() or not (root / "labels").is_dir():
            return False
        classes, _ = _load_classes(root)
        return bool(classes) or any((root / "labels").rglob("*.txt"))

    def load(self, root: Path) -> RawDataset:
        images_dir = root / "images"
        labels_dir = root / "labels"
        if not images_dir.is_dir() or not labels_dir.is_dir():
            raise AdapterError(f"YOLO layout requires images/ and labels/ under {root}")

        class_names, class_source = _load_classes(root)
        if not class_names:
            raise AdapterError(
                f"no class list found under {root} (expected data.yaml or classes.txt)"
            )

        issues: list[IngestIssue] = []
        samples: list[RawSample] = []

        image_paths = sorted(
            p
            for p in images_dir.rglob("*")
            if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS
        )
        if not image_paths:
            raise AdapterError(f"no images found under {images_dir}")

        image_stems = set()
        for path in image_paths:
            relpath = path.relative_to(root).as_posix()
            stem_rel = path.relative_to(images_dir).with_suffix("")
            image_stems.add(stem_rel.as_posix())
            label_path = labels_dir / stem_rel.with_suffix(".txt")

            anns: list[ObjectAnnotation] = []
            if not label_path.is_file():
                issues.append(
                    IngestIssue(
                        code=IssueCode.UNLABELLED_SAMPLE,
                        locator=relpath,
                        message="no YOLO label file for this image",
                        observation={
                            "expected_label_file": label_path.relative_to(root).as_posix()
                        },
                        sample_id=relpath,
                    )
                )
            else:
                label_rel = label_path.relative_to(root).as_posix()
                for lineno, line in enumerate(
                    label_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
                ):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 5:
                        issues.append(
                            IngestIssue(
                                code=IssueCode.MALFORMED_RECORD,
                                locator=f"{label_rel}:{lineno}",
                                message=f"YOLO label line has {len(parts)} fields, expected >= 5",
                                observation={"line": line[:200], "lineno": lineno},
                                sample_id=relpath,
                            )
                        )
                        continue
                    try:
                        cls_idx = int(parts[0])
                        cx, cy, bw, bh = (float(v) for v in parts[1:5])
                    except ValueError:
                        issues.append(
                            IngestIssue(
                                code=IssueCode.MALFORMED_RECORD,
                                locator=f"{label_rel}:{lineno}",
                                message="YOLO label line has non-numeric fields",
                                observation={"line": line[:200], "lineno": lineno},
                                sample_id=relpath,
                            )
                        )
                        continue

                    if not 0 <= cls_idx < len(class_names):
                        issues.append(
                            IngestIssue(
                                code=IssueCode.UNKNOWN_CATEGORY,
                                locator=f"{label_rel}:{lineno}",
                                message=f"class index {cls_idx} outside declared class list "
                                f"of size {len(class_names)}",
                                observation={
                                    "class_index": cls_idx,
                                    "n_classes": len(class_names),
                                    "class_source": class_source,
                                },
                                sample_id=relpath,
                            )
                        )
                        category = f"__unknown_{cls_idx}__"
                    else:
                        category = class_names[cls_idx]

                    if not all(0.0 <= v <= 1.0 for v in (cx, cy, bw, bh)) or bw <= 0 or bh <= 0:
                        issues.append(
                            IngestIssue(
                                code=IssueCode.INVALID_BBOX,
                                locator=f"{label_rel}:{lineno}",
                                message="YOLO bbox is not a valid normalised box",
                                observation={
                                    "cx": cx, "cy": cy, "w": bw, "h": bh, "lineno": lineno,
                                },
                                sample_id=relpath,
                            )
                        )

                    anns.append(
                        ObjectAnnotation(
                            annotation_id=f"{stem_rel.as_posix()}:{lineno}",
                            category=category,
                            # Normalised box kept as-is; converted to pixels once
                            # the true image size is known (manifest stage).
                            bbox=None,
                            native={
                                "class_index": cls_idx,
                                "norm_bbox": [cx, cy, bw, bh],
                            },
                        )
                    )

            samples.append(
                RawSample(
                    sample_id=relpath,
                    relpath=relpath,
                    abspath=path,
                    labels=tuple(sorted({a.category for a in anns})),
                    annotations=tuple(anns),
                    native={"class_source": class_source},
                )
            )

        for label_path in sorted(labels_dir.rglob("*.txt")):
            stem = label_path.relative_to(labels_dir).with_suffix("").as_posix()
            if stem not in image_stems:
                issues.append(
                    IngestIssue(
                        code=IssueCode.ORPHAN_ANNOTATION,
                        locator=label_path.relative_to(root).as_posix(),
                        message="label file has no corresponding image",
                        observation={"stem": stem},
                    )
                )

        return RawDataset(
            name=root.name,
            root=root,
            adapter=self.name,
            adapter_version=self.version,
            task=Task.DETECTION,
            classes=tuple(class_names),
            samples=samples,
            issues=issues,
            native={"class_source": class_source},
        )


ADAPTERS.add("yolo", YoloAdapter())
