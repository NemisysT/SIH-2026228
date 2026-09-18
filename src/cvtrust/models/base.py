"""Model adapter interface, access modes, and the format-neutral model handle.

The design mirrors :mod:`cvtrust.datasets.base` deliberately: an adapter answers
*what does this artifact claim and expose?* and never decides whether anything
is suspicious.  That separation is what keeps a format's quirks out of the
detectors.

The part of this module that carries the most weight is :class:`Capability`.
A WHITE_BOX / BLACK_BOX binary is not sufficient to describe a model artifact
honestly, because the formats differ in ways that change which published method
can run at all:

* an **ONNX** graph exposes topology, weights and intermediate activations, but
  ONNX Runtime does not give us gradients with respect to the input — so
  Neural-Cleanse-style trigger *reconstruction* cannot be performed on it;
* a **PyTorch** ``nn.Module`` exposes everything including gradients;
* a **TorchScript** archive exposes weights and activations, and gradients to
  the extent the traced graph supports autograd;
* a model behind an inference API exposes nothing but ``infer``.

So the manifest records the headline ``access_mode`` *and* the capability set,
and a detector states which capability it needed.  A method that wanted
gradients and did not get them reports that fact rather than quietly running a
weaker variant under the stronger name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

import numpy as np

from ..core.errors import AdapterError
from ..core.registry import Registry


class AccessMode(str, Enum):
    """How much of the model the assessment can see.

    ``WHITE_BOX``
        Parameters are readable.  Structure, parameter and activation analyses
        are possible; whether *gradient* methods are possible is a separate
        question answered by :class:`Capability`.

    ``BLACK_BOX``
        Inputs and outputs only, plus whatever metadata the artifact declares
        about itself — which is untrusted.
    """

    WHITE_BOX = "WHITE_BOX"
    BLACK_BOX = "BLACK_BOX"


class Capability(str, Enum):
    """A single thing an adapter can actually do with a loaded model."""

    #: Run a forward pass.  The floor: without it nothing in Module 2 runs.
    INFERENCE = "inference"
    #: Read topology, operator sequence, tensor names, shapes and dtypes.
    GRAPH = "graph"
    #: Read weight tensor values.
    PARAMETERS = "parameters"
    #: Read intermediate tensor values for a given input.
    ACTIVATIONS = "activations"
    #: Differentiate an output with respect to the input.
    GRADIENTS = "gradients"


@dataclass(frozen=True, slots=True)
class TensorSpec:
    """Declared shape and dtype of one model input or output.

    ``shape`` entries are ``int`` for fixed dimensions and ``None`` for dynamic
    ones (batch axes, dynamic spatial axes).  ``None`` is preserved rather than
    guessed: a dynamic axis silently materialised as ``1`` would make the
    structural fingerprint claim something the artifact does not.
    """

    name: str
    dtype: str
    shape: tuple[int | None, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dtype": self.dtype,
            "shape": [None if d is None else int(d) for d in self.shape],
        }


@dataclass(frozen=True, slots=True)
class ParameterTensor:
    """One weight tensor, as read from the artifact.

    ``values`` is kept as ``float64`` for statistics so that a model stored in
    float16 does not produce statistics whose precision depends on the storage
    dtype; ``dtype`` records what the artifact actually stores.
    """

    name: str
    dtype: str
    shape: tuple[int, ...]
    values: np.ndarray
    owner: str | None = None
    op_type: str | None = None

    @property
    def count(self) -> int:
        return int(self.values.size)


@dataclass(frozen=True, slots=True)
class LayerInfo:
    """One graph node / module, for the structural fingerprint."""

    name: str
    op_type: str
    input_names: tuple[str, ...] = ()
    output_names: tuple[str, ...] = ()
    output_shape: tuple[int | None, ...] | None = None
    parameter_count: int = 0
    parameter_dtypes: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "op_type": self.op_type,
            "input_names": list(self.input_names),
            "output_names": list(self.output_names),
            "output_shape": (
                None
                if self.output_shape is None
                else [None if d is None else int(d) for d in self.output_shape]
            ),
            "parameter_count": int(self.parameter_count),
            "parameter_dtypes": list(self.parameter_dtypes),
            "attributes": dict(self.attributes),
        }


@dataclass
class ModelOutput:
    """The result of one forward pass over a batch.

    ``logits`` is ``(batch, classes)``.  ``probabilities`` is the softmax of it
    unless the model already emits a normalised distribution, in which case the
    adapter says so via ``already_normalised`` — applying softmax twice would
    flatten the distribution and silently corrupt every divergence metric.
    """

    logits: np.ndarray
    output_name: str
    already_normalised: bool = False
    activations: dict[str, np.ndarray] = field(default_factory=dict)

    def probabilities(self) -> np.ndarray:
        if self.already_normalised:
            return np.asarray(self.logits, dtype=np.float64)
        return softmax(np.asarray(self.logits, dtype=np.float64))

    def predictions(self) -> np.ndarray:
        return np.argmax(np.asarray(self.logits, dtype=np.float64), axis=1)


def softmax(logits: np.ndarray) -> np.ndarray:
    """Numerically stable row-wise softmax."""
    shifted = logits - np.max(logits, axis=1, keepdims=True)
    exponentiated = np.exp(shifted)
    return exponentiated / np.sum(exponentiated, axis=1, keepdims=True)


@dataclass
class ModelHandle:
    """A loaded model plus everything the adapter knows about it.

    ``native`` holds the format-specific object (an ``onnxruntime`` session, a
    ``torch.nn.Module``).  Detectors never touch it; they go through the
    adapter, which is what keeps the system from becoming ONNX-specific.
    """

    path: Path
    model_format: str
    adapter: str
    adapter_version: str
    access_mode: AccessMode
    capabilities: frozenset[Capability]
    inputs: tuple[TensorSpec, ...]
    outputs: tuple[TensorSpec, ...]
    native: Any = None
    declared_metadata: Mapping[str, Any] = field(default_factory=dict)
    runtime: Mapping[str, str] = field(default_factory=dict)
    #: Fields this format could not supply, recorded explicitly so the manifest
    #: can say "unavailable" instead of implying "absent".
    unavailable: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def has(self, *capabilities: Capability) -> bool:
        return all(c in self.capabilities for c in capabilities)

    def release_caches(self) -> None:
        """Drop cached runtime objects that are no longer needed.

        Activation capture builds a *second* inference session whose graph
        exposes the requested intermediate tensors, and that session holds its
        own thread pools.  It is used once per assessment, so keeping it alive
        afterwards costs memory and — on some platforms — leaves runtime
        teardown to interpreter finalisation, where ONNX Runtime's and
        PyTorch's process-wide handlers can race.

        Releasing it is hygiene rather than a correctness fix: the handle stays
        usable, and the cache simply rebuilds if capture is requested again.
        """
        if isinstance(self.native, dict):
            self.native.pop("_tap_sessions", None)

    def require(self, capability: Capability, what: str) -> None:
        """Raise the Module 1 unavailability error if a capability is missing.

        The message is the machine-readable reason the pipeline records as the
        coverage entry's ``reason``, so it must name the capability, the format
        and the method that wanted it.
        """
        from ..core.errors import DetectorUnavailable

        if capability not in self.capabilities:
            raise DetectorUnavailable(
                f"{what} requires the '{capability.value}' capability, which the "
                f"'{self.model_format}' adapter does not provide for this artifact "
                f"(access mode {self.access_mode.value}; available capabilities: "
                f"{', '.join(sorted(c.value for c in self.capabilities)) or 'none'})"
            )

    @property
    def input_spec(self) -> TensorSpec:
        if not self.inputs:
            raise AdapterError(f"model {self.path} declares no inputs")
        return self.inputs[0]

    def batch_shape(self, batch: int) -> tuple[int, ...]:
        """Concrete input shape for a batch, resolving dynamic axes.

        Only the *leading* axis may be resolved from ``batch``; any other
        dynamic axis is an error rather than a guess, because a wrong guess
        would produce a behavioural fingerprint of a shape the model was never
        meant to see.
        """
        shape = self.input_spec.shape
        if not shape:
            raise AdapterError(f"model {self.path} declares a rank-0 input")
        resolved: list[int] = [batch]
        for axis, dim in enumerate(shape[1:], start=1):
            if dim is None:
                raise AdapterError(
                    f"model {self.path} has a dynamic axis {axis} in its input "
                    f"shape {shape}; cvtrust resolves only the batch axis, because "
                    "guessing a spatial size would fingerprint a shape the model "
                    "was never declared for. Export with fixed spatial dimensions."
                )
            resolved.append(int(dim))
        return tuple(resolved)


@runtime_checkable
class ModelAdapter(Protocol):
    """Contract every model format implementation satisfies."""

    name: str
    version: str
    model_format: str

    @staticmethod
    def detect(path: Path) -> bool:
        """Cheap structural test: could this artifact plausibly be this format?"""

    def load(self, path: Path, config: Any = None) -> ModelHandle:
        """Load the artifact.  May raise :class:`AdapterError`."""

    def parameters(self, handle: ModelHandle) -> tuple[ParameterTensor, ...]:
        """Weight tensors, in a deterministic order."""

    def layers(self, handle: ModelHandle) -> tuple[LayerInfo, ...]:
        """Graph nodes / modules, in execution order where the format has one."""

    def infer(
        self, handle: ModelHandle, batch: np.ndarray, *, capture: Sequence[str] = ()
    ) -> ModelOutput:
        """Forward pass over ``batch`` (NCHW float32), optionally capturing
        named intermediate tensors."""

    def activation_layers(self, handle: ModelHandle) -> tuple[str, ...]:
        """Names of intermediate tensors that ``infer(capture=...)`` accepts."""


MODEL_ADAPTERS: Registry[ModelAdapter] = Registry("model adapter")

#: File extensions we will consider at all.  An artifact with an unknown
#: extension is refused rather than sniffed, because loading an arbitrary file
#: into a deserialiser is itself the attack surface (see docs/model-security.md).
MODEL_EXTENSIONS = frozenset({".onnx", ".pt", ".pth", ".bin", ".torchscript"})


def detect_model_adapter(path: Path) -> ModelAdapter:
    """Pick an adapter for ``path``.

    Ambiguity is an operator decision (``--model-adapter``), never a guess:
    guessing the format wrong changes what "the model" means, and in this system
    that would change an identity claim.
    """
    matches = [adapter for _, adapter in MODEL_ADAPTERS if adapter.detect(path)]
    if not matches:
        registered = ", ".join(MODEL_ADAPTERS.names())
        raise AdapterError(
            f"no registered model adapter recognises {path}; tried: "
            + (registered or "none registered — install the 'onnx' or 'torch' extra")
        )
    if len(matches) > 1:
        names = ", ".join(a.name for a in matches)
        raise AdapterError(
            f"ambiguous model format at {path}: {names}. "
            "Select one explicitly with --model-adapter."
        )
    return matches[0]
