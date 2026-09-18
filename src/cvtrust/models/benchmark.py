"""Optional ingestion of locally-vendored backdoor benchmark artifacts.

The point of this module is what it does **not** do.

NIST TrojAI and BackdoorBench are the two standard evaluation corpora for
backdoor detection, and being evaluated against them is what would turn Module
2's measured numbers from "measured on our own synthetic lab" into "measured on
a community benchmark".  Neither can be downloaded here: the runtime is
air-gapped, and a tool that quietly fetched several gigabytes of models the
first time it ran would break the single property this project is built on.

So the contract is:

* artifacts are **vendored** into a local directory by an operator, out of band;
* this module reads that directory if it exists, and ingests whatever it finds
  through the ordinary :class:`~cvtrust.models.base.ModelAdapter` path, so a
  benchmark model is analysed by exactly the same detectors as any other model;
* if the directory is absent, empty or unreadable, the answer is
  ``NOT_ASSESSED`` with the reason ``"required local artifact unavailable"``;
* **nothing is ever downloaded**, and no URL appears anywhere in this file.

Layout expected in the local directory
--------------------------------------
::

    <benchmark_dir>/
      index.json          # required; describes the vendored models
      models/
        id-00000001/model.onnx
        ...

``index.json``::

    {
      "benchmark": "trojai",              # or "backdoorbench", or any local id
      "round": "train-round-1",
      "license": "...",                   # recorded verbatim, never interpreted
      "models": [
        {"id": "id-00000001",
         "path": "models/id-00000001/model.onnx",
         "ground_truth": {"poisoned": true, "trigger_family": "polygon",
                          "target_class": 3}}
      ]
    }

``ground_truth`` is read **only** by the evaluation harness, never by a
detector — the same separation Module 1 enforces by keeping attack ground truth
outside the dataset root.

Vendoring instructions for an air-gapped deployment are in
``docs/model-security.md``; they are instructions for a human, deliberately not
an automated fetch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import DetectorUnavailable
from ..core.hashing import sha256_file
from ..core.logging import get_logger

log = get_logger("models.benchmark")

BENCHMARK_INDEX_VERSION = "1.0"

#: The exact reason string reported when benchmark artifacts are not present.
#: Fixed text, because the coverage statement and the tests both key on it.
UNAVAILABLE_REASON = "required local artifact unavailable"


@dataclass(frozen=True, slots=True)
class BenchmarkModel:
    """One vendored benchmark model."""

    model_id: str
    path: Path
    file_sha256: str
    ground_truth: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BenchmarkIndex:
    """A local benchmark directory, as read."""

    benchmark: str
    round_id: str | None
    license_text: str | None
    root: Path
    models: tuple[BenchmarkModel, ...]

    def describe(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "round": self.round_id,
            "license": self.license_text,
            "root": str(self.root),
            "model_count": len(self.models),
            "model_ids": [m.model_id for m in self.models[:50]],
            "ingestion": "local directory only; nothing was downloaded",
        }


def load_benchmark(directory: Path | str | None) -> BenchmarkIndex:
    """Read a local benchmark directory.

    Raises :class:`~cvtrust.core.errors.DetectorUnavailable` — the Module 1
    contract for "a requirement was not met" — whenever the artifacts are not
    there.  The caller records ``NOT_ASSESSED`` with this reason rather than
    treating an absent benchmark as a passed one.
    """
    if directory is None:
        raise DetectorUnavailable(
            f"benchmark evaluation not performed: {UNAVAILABLE_REASON} "
            "(no benchmark directory configured; set model.benchmark_dir to a "
            "locally vendored TrojAI or BackdoorBench directory). Benchmark "
            "artifacts are never downloaded."
        )
    root = Path(directory)
    index_path = root / "index.json"
    if not root.is_dir() or not index_path.is_file():
        raise DetectorUnavailable(
            f"benchmark evaluation not performed: {UNAVAILABLE_REASON} "
            f"(no index.json under {root}). Vendor the benchmark artifacts into "
            "that directory following docs/model-security.md; they are never "
            "downloaded."
        )
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DetectorUnavailable(
            f"benchmark evaluation not performed: {index_path} is not readable "
            f"JSON ({exc})"
        ) from exc

    entries = payload.get("models")
    if not isinstance(entries, list) or not entries:
        raise DetectorUnavailable(
            f"benchmark evaluation not performed: {UNAVAILABLE_REASON} "
            f"({index_path} lists no models)"
        )

    models: list[BenchmarkModel] = []
    missing: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        model_id = str(entry.get("id") or "")
        relative = entry.get("path")
        if not model_id or not relative:
            continue
        path = root / str(relative)
        if not path.is_file():
            missing.append(model_id)
            continue
        ground_truth = entry.get("ground_truth")
        models.append(
            BenchmarkModel(
                model_id=model_id,
                path=path,
                file_sha256=sha256_file(path),
                ground_truth=dict(ground_truth) if isinstance(ground_truth, dict) else {},
            )
        )
    if missing:
        log.warning(
            "%d benchmark entries reference files that are not present: %s",
            len(missing), ", ".join(missing[:10]),
        )
    if not models:
        raise DetectorUnavailable(
            f"benchmark evaluation not performed: {UNAVAILABLE_REASON} "
            f"(every model listed in {index_path} is missing from disk)"
        )

    index = BenchmarkIndex(
        benchmark=str(payload.get("benchmark", "local")),
        round_id=(str(payload["round"]) if payload.get("round") else None),
        license_text=(str(payload["license"]) if payload.get("license") else None),
        root=root,
        models=tuple(sorted(models, key=lambda m: m.model_id)),
    )
    log.info(
        "benchmark '%s' ingested from %s: %d model(s)",
        index.benchmark, root, len(index.models),
    )
    return index


def benchmark_status(directory: Path | str | None) -> dict[str, Any]:
    """Report benchmark availability without raising, for the report header."""
    try:
        index = load_benchmark(directory)
    except DetectorUnavailable as exc:
        return {
            "available": False,
            "coverage": "NOT_ASSESSED",
            "reason": str(exc),
            "downloads_attempted": False,
        }
    return {"available": True, "coverage": "SUPPORTED", "downloads_attempted": False,
            **index.describe()}
