"""ImageFolder-style classification adapter: ``root/<class>/<image>``.

Included because it is the lowest-friction way to hand an analyst a pile of
labelled imagery, and because it exercises the classification path of every
label detector without a COCO/YOLO parse in the way.
"""

from __future__ import annotations

from pathlib import Path

from ..core.errors import AdapterError
from .base import (
    ADAPTERS,
    IMAGE_EXTENSIONS,
    IngestIssue,
    IssueCode,
    RawDataset,
    RawSample,
    Task,
)


class FolderAdapter:
    name = "folder"
    version = "1.0"

    @staticmethod
    def detect(root: Path) -> bool:
        if not root.is_dir():
            return False
        # Reject anything that another adapter owns outright. contributors.json
        # is provenance metadata that any layout may carry, so it does not
        # count as an annotation document here.
        if (root / "annotations").is_dir():
            return False
        if any(p.name != "contributors.json" for p in root.glob("*.json")):
            return False
        if (root / "labels").is_dir() and (root / "images").is_dir():
            return False
        class_dirs = [d for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if len(class_dirs) < 2:
            return False
        return any(
            any(p.suffix.lower() in IMAGE_EXTENSIONS for p in d.iterdir() if p.is_file())
            for d in class_dirs
        )

    def load(self, root: Path) -> RawDataset:
        if not root.is_dir():
            raise AdapterError(f"dataset root is not a directory: {root}")

        samples: list[RawSample] = []
        issues: list[IngestIssue] = []
        classes: set[str] = set()

        for class_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            if class_dir.name.startswith("."):
                continue
            classes.add(class_dir.name)
            for path in sorted(class_dir.rglob("*")):
                if not path.is_file() or path.name.startswith("."):
                    continue
                relpath = path.relative_to(root).as_posix()
                if path.suffix.lower() not in IMAGE_EXTENSIONS:
                    issues.append(
                        IngestIssue(
                            code=IssueCode.UNSUPPORTED_EXTENSION,
                            locator=relpath,
                            message=f"file with unsupported extension {path.suffix!r} "
                            "inside a class directory",
                            observation={"extension": path.suffix, "relpath": relpath},
                        )
                    )
                    continue
                samples.append(
                    RawSample(
                        sample_id=relpath,
                        relpath=relpath,
                        abspath=path,
                        labels=(class_dir.name,),
                    )
                )

        if not samples:
            raise AdapterError(f"no images found under {root}")

        return RawDataset(
            name=root.name,
            root=root,
            adapter=self.name,
            adapter_version=self.version,
            task=Task.CLASSIFICATION,
            classes=tuple(sorted(classes)),
            samples=samples,
            issues=issues,
        )


ADAPTERS.add("folder", FolderAdapter())
