"""Optional CNN feature backend.

Present so that a deployment which *has* vendored weights can use a stronger
feature space without changing any detector.  It follows the same
graceful-degradation contract Module 2 uses for white-box-only methods: if
PyTorch or the local weight file is absent it raises
:class:`~cvtrust.core.errors.DetectorUnavailable` with a precise reason, and the
caller records ``NOT_ASSESSED``.  It never reaches the network — ``weights_path``
must point at a file already on disk, and its SHA-256 is recorded in the report
so the feature space itself is an assured artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from ..core.errors import DetectorUnavailable
from ..core.hashing import sha256_file


class TorchFeatureExtractor:
    name = "torch_cnn"
    version = "1.0"

    def __init__(self, weights_path: str | Path | None = None, arch: str = "resnet18") -> None:
        self.arch = arch
        self.weights_path = Path(weights_path) if weights_path else None
        self._model: Any = None
        self._weights_digest: str | None = None

    def _ensure(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            import torch
            import torchvision
        except ImportError as exc:
            raise DetectorUnavailable(
                "torch feature backend unavailable: PyTorch/torchvision are not "
                "installed in this offline environment"
            ) from exc
        if self.weights_path is None or not self.weights_path.is_file():
            raise DetectorUnavailable(
                "torch feature backend unavailable: no local weight file was "
                f"provided ({self.weights_path}). Weights are never downloaded; "
                "vendor them into the deployment and set features.weights_path."
            )
        self._weights_digest = sha256_file(self.weights_path)
        model = getattr(torchvision.models, self.arch)(weights=None)
        state = torch.load(self.weights_path, map_location="cpu", weights_only=True)
        model.load_state_dict(state, strict=False)
        model.fc = torch.nn.Identity()
        model.eval()
        torch.set_grad_enabled(False)
        self._model = model
        return model

    @property
    def dim(self) -> int:
        self._ensure()
        return 512 if self.arch in {"resnet18", "resnet34"} else 2048

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "arch": self.arch,
            "weights_path": str(self.weights_path) if self.weights_path else None,
            "weights_sha256": self._weights_digest,
            "requires_pretrained_weights": True,
            "deterministic": True,
        }

    def extract(self, image: Image.Image) -> np.ndarray:
        import torch

        model = self._ensure()
        arr = np.asarray(
            image.convert("RGB").resize((224, 224), Image.Resampling.BILINEAR),
            dtype=np.float32,
        ) / 255.0
        mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
        std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
        arr = (arr - mean) / std
        tensor = torch.from_numpy(arr.transpose(2, 0, 1)).unsqueeze(0)
        with torch.no_grad():
            out = model(tensor).numpy().reshape(-1)
        norm = float(np.linalg.norm(out))
        return (out / norm if norm > 1e-8 else out).astype(np.float32)
