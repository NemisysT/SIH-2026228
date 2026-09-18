"""Feature extractor interface and registry."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import numpy as np
from PIL import Image

from ..core.registry import Registry


@runtime_checkable
class FeatureExtractor(Protocol):
    name: str
    version: str

    @property
    def dim(self) -> int: ...

    def describe(self) -> dict[str, Any]:
        """Self-description recorded in every report, so that a finding can
        always be traced to the feature space that produced it."""

    def extract(self, image: Image.Image) -> np.ndarray:
        """Return an L2-normalised float32 embedding.  Must be deterministic."""


EXTRACTORS: Registry[type] = Registry("feature extractor")
