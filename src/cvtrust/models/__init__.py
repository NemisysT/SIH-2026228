"""Model ingestion and analysis — the Module 2 primitives.

Registration is explicit and conditional.  An adapter whose runtime is not
installed is simply not registered, and the pipeline then reports
``NOT_ASSESSED`` with a reason naming the missing package — the same
graceful-degradation contract Module 1 uses for its optional CNN backend.  No
import here reaches the network, and none of them can: see
``tests/security/test_offline.py``.
"""

from __future__ import annotations

from .base import (
    MODEL_ADAPTERS,
    MODEL_EXTENSIONS,
    AccessMode,
    Capability,
    LayerInfo,
    ModelAdapter,
    ModelHandle,
    ModelOutput,
    ParameterTensor,
    TensorSpec,
    detect_model_adapter,
    softmax,
)
from .battery import (
    BATTERY_VERSION,
    CATEGORIES,
    CLEAN,
    DEFAULT_TRIGGER_FAMILY,
    PERTURBATIONS,
    Probe,
    ReferenceBattery,
    apply_trigger,
    build_battery,
)
from .behaviour import (
    FINGERPRINT_VERSION,
    BehaviouralFingerprint,
    compare_fingerprints,
    compute_fingerprint,
    confidence_shift,
    distribution_divergence,
    js_divergence,
    metamorphic_consistency,
    ood_confidence_guard,
    prediction_agreement,
    targeted_transition,
)
from .manifest import (
    MODEL_MANIFEST_SCHEMA_VERSION,
    ModelManifest,
    ModelVerificationResult,
    build_model_manifest,
    compare_identity,
    load_model_manifest,
    verify_model_manifest,
)


def _register_optional_adapters() -> list[str]:
    """Register the adapters whose runtimes are actually installed.

    Import failures are swallowed *here only*, and only to decide registration.
    When a user then asks for an unavailable format, the registry's own error
    names what is available, and the adapter's ``_require_*`` helper explains
    which package is missing and that nothing will be downloaded to fix it.
    """
    registered: list[str] = []
    try:
        import onnx  # noqa: F401
        import onnxruntime  # noqa: F401
    except ImportError:
        pass
    else:
        from .onnx_adapter import OnnxModelAdapter

        MODEL_ADAPTERS.add("onnx", OnnxModelAdapter())
        registered.append("onnx")

    try:
        import torch  # noqa: F401
    except ImportError:
        pass
    else:
        from .torch_adapter import TorchModelAdapter, TorchScriptModelAdapter

        MODEL_ADAPTERS.add("torchscript", TorchScriptModelAdapter())
        MODEL_ADAPTERS.add("torch", TorchModelAdapter())
        registered += ["torchscript", "torch"]

    return registered


REGISTERED_ADAPTERS: list[str] = _register_optional_adapters()

__all__ = [
    "MODEL_ADAPTERS", "MODEL_EXTENSIONS", "REGISTERED_ADAPTERS", "AccessMode",
    "Capability", "LayerInfo", "ModelAdapter", "ModelHandle", "ModelOutput",
    "ParameterTensor", "TensorSpec", "detect_model_adapter", "softmax",
    "ModelManifest", "ModelVerificationResult", "build_model_manifest",
    "compare_identity", "load_model_manifest", "verify_model_manifest",
    "MODEL_MANIFEST_SCHEMA_VERSION",
    "ReferenceBattery", "Probe", "build_battery", "apply_trigger",
    "BATTERY_VERSION", "CATEGORIES", "CLEAN", "DEFAULT_TRIGGER_FAMILY",
    "PERTURBATIONS",
    "BehaviouralFingerprint", "compute_fingerprint", "compare_fingerprints",
    "js_divergence", "prediction_agreement", "distribution_divergence",
    "confidence_shift", "metamorphic_consistency", "targeted_transition",
    "ood_confidence_guard", "FINGERPRINT_VERSION",
]
