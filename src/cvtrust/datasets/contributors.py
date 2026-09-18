"""Contributor / batch / source attribution.

The problem statement requires evidence to be aggregated to contributors "where
contributor/batch/source metadata exists".  In a multi-contributor pipeline that
metadata is itself untrusted, so two rules apply:

1. **Precedence is explicit and recorded.**  Each sample's manifest record
   carries ``attribution_source`` naming *how* the attribution was obtained.
   An analyst can therefore see that contributor "bravo" was inferred from a
   directory name rather than asserted by a signed sidecar.
2. **A filename is never an identity.**  Path-pattern attribution is opt-in
   (``contributor.path_pattern``), off by default, and always reported as the
   weakest source.  From Module 3 the sidecar becomes signable, at which point
   ``sidecar_signed`` becomes the only strong attribution source.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from ..core.config import ContributorConfig
from ..core.errors import AdapterError
from .base import RawSample


class AttributionSource(str, Enum):
    SIDECAR = "sidecar"
    ADAPTER_NATIVE = "adapter_native"
    PATH_PATTERN = "path_pattern"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class Attribution:
    contributor: str
    batch: str | None
    source: str | None
    attribution_source: AttributionSource


class ContributorResolver:
    """Resolves attribution for each sample under a documented precedence."""

    version = "1.0"

    def __init__(self, cfg: ContributorConfig, root: Path) -> None:
        self._cfg = cfg
        self._pattern = re.compile(cfg.path_pattern) if cfg.path_pattern else None
        self._sidecar: dict[str, Mapping[str, Any]] = {}
        self._sidecar_path: str | None = None
        if cfg.sidecar:
            self._load_sidecar(root / cfg.sidecar)

    def _load_sidecar(self, path: Path) -> None:
        if not path.is_file():
            return
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterError(f"cannot parse contributor sidecar {path}: {exc}") from exc
        entries = doc.get("samples", doc) if isinstance(doc, dict) else {}
        if not isinstance(entries, dict):
            raise AdapterError(f"contributor sidecar {path} has no 'samples' mapping")
        for relpath, value in entries.items():
            if isinstance(value, str):
                self._sidecar[relpath] = {"contributor": value}
            elif isinstance(value, dict):
                self._sidecar[relpath] = value
        self._sidecar_path = path.name

    @property
    def sidecar_present(self) -> bool:
        return bool(self._sidecar)

    def resolve(self, sample: RawSample) -> Attribution:
        entry = self._sidecar.get(sample.relpath)
        if entry and entry.get("contributor"):
            return Attribution(
                contributor=str(entry["contributor"]),
                batch=_opt_str(entry.get("batch")),
                source=_opt_str(entry.get("source")),
                attribution_source=AttributionSource.SIDECAR,
            )

        native = sample.native or {}
        if native.get("contributor"):
            return Attribution(
                contributor=str(native["contributor"]),
                batch=_opt_str(native.get("batch")),
                source=_opt_str(native.get("source")),
                attribution_source=AttributionSource.ADAPTER_NATIVE,
            )

        if self._pattern is not None:
            match = self._pattern.search(sample.relpath)
            if match:
                groups = match.groupdict()
                if groups.get("contributor"):
                    return Attribution(
                        contributor=str(groups["contributor"]),
                        batch=_opt_str(groups.get("batch")),
                        source=_opt_str(groups.get("source")),
                        attribution_source=AttributionSource.PATH_PATTERN,
                    )

        return Attribution(
            contributor=self._cfg.unknown_label,
            batch=None,
            source=None,
            attribution_source=AttributionSource.NONE,
        )

    def describe(self) -> dict[str, Any]:
        """Provenance of the attribution mechanism itself, for the report."""
        return {
            "resolver_version": self.version,
            "sidecar": self._sidecar_path,
            "sidecar_entries": len(self._sidecar),
            "path_pattern": self._cfg.path_pattern,
            "precedence": [s.value for s in (
                AttributionSource.SIDECAR,
                AttributionSource.ADAPTER_NATIVE,
                AttributionSource.PATH_PATTERN,
                AttributionSource.NONE,
            )],
        }


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)
