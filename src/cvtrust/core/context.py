"""Run context — the reproducibility record.

Every analysis carries one of these, it is embedded in every report, and its
``run_id`` is derived from the inputs rather than generated randomly.  Two runs
over the same dataset with the same configuration and seed produce the same
``run_id`` on any machine; if they do not, something that should have been
deterministic was not, and that is a defect the determinism test catches.
"""

from __future__ import annotations

import platform
import sys
import time
from typing import Any

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from .. import __version__
from .canonical import digest_safe
from .evidence import SCHEMA_VERSION, utc_now_iso
from .hashing import sha256_canonical, short

#: Report fields that legitimately differ between two identical runs.  The
#: determinism test strips exactly these and requires byte equality of the rest.
VOLATILE_FIELDS: tuple[str, ...] = (
    "observed_at",
    "started_at",
    "finished_at",
    "duration_ms",
    "timings_ms",
    "throughput_samples_per_s",
)


class RunContext(BaseModel):
    """Identity and environment of a single analysis run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    schema_version: str = SCHEMA_VERSION
    software_version: str = __version__
    seed: int
    config_hash: str
    dataset_digest: str | None = None
    detector_versions: dict[str, str] = Field(default_factory=dict)
    python_version: str = Field(default_factory=lambda: sys.version.split()[0])
    platform: str = Field(default_factory=lambda: platform.platform())
    numpy_version: str = Field(default_factory=lambda: np.__version__)
    started_at: str = Field(default_factory=utc_now_iso)
    finished_at: str | None = None
    duration_ms: int | None = None
    timings_ms: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        seed: int,
        config_hash: str,
        dataset_digest: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "RunContext":
        payload = {
            "software_version": __version__,
            "schema_version": SCHEMA_VERSION,
            "seed": seed,
            "config_hash": config_hash,
            "dataset_digest": dataset_digest,
            "extra": digest_safe(extra or {}),
        }
        return cls(
            run_id=short(sha256_canonical(payload), 16),
            seed=seed,
            config_hash=config_hash,
            dataset_digest=dataset_digest,
        )

    def rng(self, stream: str = "default") -> np.random.Generator:
        """A seeded generator for a named stream.

        Components never touch global RNG state.  Deriving each stream from
        ``(seed, stream name)`` means adding a component cannot perturb the
        random draws of an existing one, so results stay reproducible as the
        system grows.
        """
        mixed = int(sha256_canonical({"seed": self.seed, "stream": stream})[:16], 16)
        return np.random.default_rng(mixed)

    def timer(self, label: str) -> "_Timer":
        return _Timer(self, label)

    def finish(self) -> "RunContext":
        self.finished_at = utc_now_iso()
        self.duration_ms = sum(self.timings_ms.values())
        return self


class _Timer:
    def __init__(self, ctx: RunContext, label: str) -> None:
        self._ctx = ctx
        self._label = label
        self._start = 0.0

    def __enter__(self) -> "_Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        elapsed = int((time.perf_counter() - self._start) * 1000)
        self._ctx.timings_ms[self._label] = (
            self._ctx.timings_ms.get(self._label, 0) + elapsed
        )
