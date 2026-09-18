"""PyTorch and TorchScript model adapters.

These are the only adapters that can offer :data:`Capability.GRADIENTS`, and
gradients are what make Neural-Cleanse-style trigger *reconstruction* possible
at all.  Everything else Module 2 does works on ONNX too; trigger
reconstruction does not, and that asymmetry is reported rather than smoothed
over.

Deserialisation is the attack surface
-------------------------------------
A ``.pt``/``.pth`` file produced by ``torch.save`` on an ``nn.Module`` is a
**pickle**, and unpickling executes code from the file.  Loading an untrusted
model artifact is therefore itself a code-execution risk, and this is an
integrity tool whose whole premise is that the artifact is untrusted.

The policy, implemented here and documented in ``docs/model-security.md``:

* ``torch.load(..., weights_only=True)`` is used by default, which restricts the
  unpickler to tensors and plain containers and refuses arbitrary globals.
  A full-module pickle will fail that check, and the failure is reported as an
  explained refusal rather than worked around.
* Loading a full-module pickle requires the operator to opt in explicitly
  (``--allow-unsafe-deserialisation``), and the resulting manifest records that
  it happened.  We do not silently take the dangerous path because it is more
  convenient.
* **TorchScript** (``torch.jit.load``) does not unpickle arbitrary Python and
  is the recommended interchange format for an untrusted supplier; so is ONNX.

A state-dict-only artifact carries weights but no graph.  That is recorded as
``graph`` being *unavailable*, not as a model with no structure — the
distinction is exactly what the manifest's ``unavailable_fields`` exists for.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from ..core.errors import AdapterError, DetectorUnavailable
from ..core.logging import get_logger
from .base import (
    AccessMode,
    Capability,
    LayerInfo,
    ModelHandle,
    ModelOutput,
    ParameterTensor,
    TensorSpec,
)

log = get_logger("models.torch")


def _require_torch() -> Any:
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised by the extras test
        raise DetectorUnavailable(
            "PyTorch support unavailable: the 'torch' package is not installed in "
            "this offline environment. Install the 'torch' extra from a local "
            "wheel directory; nothing is downloaded at run time."
        ) from exc
    # Single-threaded for reproducible float reduction order, for the same
    # reason the ONNX session is pinned: a reordered sum changes the low bits of
    # a logit, which changes an argmax at a decision boundary.
    torch.set_num_threads(1)
    torch.set_grad_enabled(False)
    return torch


def _is_torchscript(path: Path) -> bool:
    """TorchScript archives are zips carrying a ``constants.pkl`` entry."""
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except Exception:  # noqa: BLE001
        return False
    return any(n.endswith("constants.pkl") for n in names) and any(
        n.endswith("code/__torch__.py") or "/code/" in n for n in names
    )


class TorchScriptModelAdapter:
    """Adapter for TorchScript archives (``torch.jit.save``)."""

    name = "torchscript"
    version = "1.0"
    model_format = "torchscript"

    @staticmethod
    def detect(path: Path) -> bool:
        path = Path(path)
        if path.suffix.lower() not in {".pt", ".pth", ".torchscript"} or not path.is_file():
            return False
        return _is_torchscript(path)

    def load(self, path: Path, config: Any = None) -> ModelHandle:
        torch = _require_torch()
        path = Path(path)
        try:
            module = torch.jit.load(str(path), map_location="cpu")
        except Exception as exc:
            raise AdapterError(f"{path} is not a loadable TorchScript archive: {exc}") from exc
        module.eval()

        declared: dict[str, Any] = {"torchscript": True}
        try:
            extra = getattr(module, "original_name", None)
            if extra:
                declared["architecture"] = str(extra)
        except Exception:  # noqa: BLE001 - metadata is untrusted and optional
            pass

        inputs, outputs, note = _probe_signature(torch, module, path, config)
        return ModelHandle(
            path=path,
            model_format=self.model_format,
            adapter=self.name,
            adapter_version=self.version,
            access_mode=AccessMode.WHITE_BOX,
            capabilities=frozenset(
                {
                    Capability.INFERENCE,
                    Capability.PARAMETERS,
                    Capability.GRAPH,
                    Capability.GRADIENTS,
                    # ACTIVATIONS is deliberately absent — see the note below.
                }
            ),
            inputs=inputs,
            outputs=outputs,
            native={"module": module, "torch": torch},
            declared_metadata=declared,
            runtime={"torch": torch.__version__},
            unavailable=("activations",),
            notes=(
                note,
                "TorchScript does not unpickle arbitrary Python globals, which is "
                "why it is preferred over a module pickle for an untrusted supplier",
                "activation capture is NOT available on this format: a ScriptModule "
                "refuses register_forward_hook, so spectral-signature and "
                "activation-clustering analyses report NOT_ASSESSED rather than "
                "being run on a substitute representation. Gradients ARE available, "
                "so trigger reconstruction runs normally. Re-export to ONNX for "
                "activation analysis, or supply the nn.Module form.",
                "torch threads pinned to 1 for reproducible logits",
            ),
        )

    def parameters(self, handle: ModelHandle) -> tuple[ParameterTensor, ...]:
        return _named_parameters(handle)

    def layers(self, handle: ModelHandle) -> tuple[LayerInfo, ...]:
        return _module_layers(handle)

    def activation_layers(self, handle: ModelHandle) -> tuple[str, ...]:
        # Empty by contract, matching the absent ACTIVATIONS capability: a
        # ScriptModule refuses forward hooks, so there is nothing to tap.
        return ()

    def infer(
        self, handle: ModelHandle, batch: np.ndarray, *, capture: Sequence[str] = ()
    ) -> ModelOutput:
        if capture:
            raise DetectorUnavailable(
                "activation capture is not available on a TorchScript artifact: "
                "a ScriptModule refuses register_forward_hook. Re-export to ONNX "
                "or supply the nn.Module form for activation analysis."
            )
        return _torch_infer(handle, batch)


class TorchModelAdapter:
    """Adapter for ``torch.save`` artifacts: ``nn.Module`` pickles and state dicts."""

    name = "torch"
    version = "1.0"
    model_format = "torch"

    def __init__(self, allow_unsafe_deserialisation: bool = False) -> None:
        self.allow_unsafe_deserialisation = allow_unsafe_deserialisation

    @staticmethod
    def detect(path: Path) -> bool:
        path = Path(path)
        if path.suffix.lower() not in {".pt", ".pth", ".bin"} or not path.is_file():
            return False
        # TorchScript archives share the .pt extension and are handled by the
        # other adapter; claiming both would make detection ambiguous, which the
        # registry correctly refuses.
        return not _is_torchscript(path)

    def load(self, path: Path, config: Any = None) -> ModelHandle:
        torch = _require_torch()
        path = Path(path)
        allow_unsafe = bool(
            getattr(getattr(config, "model", None), "allow_unsafe_deserialisation", False)
            or self.allow_unsafe_deserialisation
        )

        obj: Any
        safe_note = (
            "loaded with torch.load(weights_only=True): the unpickler was "
            "restricted to tensors and plain containers"
        )
        try:
            obj = torch.load(str(path), map_location="cpu", weights_only=True)
        except Exception as safe_exc:
            if not allow_unsafe:
                raise AdapterError(
                    f"{path} could not be loaded with weights_only=True "
                    f"({type(safe_exc).__name__}: {safe_exc}). This artifact is a "
                    "full Python pickle, and unpickling it would execute code from "
                    "a file this tool treats as untrusted. cvtrust refuses by "
                    "default. Either re-export the model as ONNX or TorchScript "
                    "(both recommended for untrusted suppliers), or re-run with "
                    "--allow-unsafe-deserialisation in a sandbox, accepting that "
                    "the artifact executes code during load."
                ) from safe_exc
            log.warning(
                "loading %s with weights_only=False at operator request: this "
                "executes code from an untrusted artifact", path,
            )
            try:
                obj = torch.load(str(path), map_location="cpu", weights_only=False)
            except Exception as exc:
                raise AdapterError(f"{path} is not a loadable torch artifact: {exc}") from exc
            safe_note = (
                "UNSAFE: loaded with torch.load(weights_only=False) at explicit "
                "operator request; arbitrary code in the artifact executed during "
                "load, and any analysis below inherits that exposure"
            )

        if isinstance(obj, torch.nn.Module):
            return self._handle_from_module(torch, obj, path, safe_note, config)
        if isinstance(obj, dict):
            return self._handle_from_state_dict(torch, obj, path, safe_note)
        raise AdapterError(
            f"{path} deserialised to {type(obj).__name__}, which is neither an "
            "nn.Module nor a state dict"
        )

    def _handle_from_module(
        self, torch: Any, module: Any, path: Path, safe_note: str, config: Any
    ) -> ModelHandle:
        module.eval()
        inputs, outputs, probe_note = _probe_signature(torch, module, path, config)
        return ModelHandle(
            path=path,
            model_format="torch_module",
            adapter=self.name,
            adapter_version=self.version,
            access_mode=AccessMode.WHITE_BOX,
            capabilities=frozenset(
                {
                    Capability.INFERENCE,
                    Capability.GRAPH,
                    Capability.PARAMETERS,
                    Capability.ACTIVATIONS,
                    Capability.GRADIENTS,
                }
            ),
            inputs=inputs,
            outputs=outputs,
            native={"module": module, "torch": torch},
            declared_metadata={"architecture": _module_type_name(module)},
            runtime={"torch": torch.__version__},
            notes=(safe_note, probe_note, "torch threads pinned to 1"),
        )

    def _handle_from_state_dict(
        self, torch: Any, state: dict, path: Path, safe_note: str
    ) -> ModelHandle:
        tensors = {
            key: value for key, value in state.items()
            if hasattr(value, "detach") and hasattr(value, "shape")
        }
        if not tensors:
            raise AdapterError(
                f"{path} is a dict but contains no tensors; it is not a state dict"
            )
        return ModelHandle(
            path=path,
            model_format="torch_state_dict",
            adapter=self.name,
            adapter_version=self.version,
            # Weights are readable, so this is genuinely white-box for parameter
            # analysis — but there is no graph and no forward pass, so every
            # behavioural method must report NOT_ASSESSED. The capability set is
            # what makes that happen automatically instead of by remembering to.
            access_mode=AccessMode.WHITE_BOX,
            capabilities=frozenset({Capability.PARAMETERS}),
            inputs=(),
            outputs=(),
            native={"state_dict": tensors, "torch": torch},
            declared_metadata={},
            runtime={"torch": torch.__version__},
            unavailable=("graph", "inference", "activations", "gradients",
                         "inputs", "outputs"),
            notes=(
                safe_note,
                "state-dict artifact: weights are present but no executable graph "
                "is, so structural, behavioural, activation and trigger "
                "assessments are NOT_ASSESSED rather than performed on a guess at "
                "the architecture",
            ),
        )

    def parameters(self, handle: ModelHandle) -> tuple[ParameterTensor, ...]:
        if "state_dict" in handle.native:
            out: list[ParameterTensor] = []
            for name, tensor in handle.native["state_dict"].items():
                array = tensor.detach().cpu().numpy()
                out.append(
                    ParameterTensor(
                        name=str(name),
                        dtype=str(array.dtype),
                        shape=tuple(int(d) for d in array.shape),
                        values=np.asarray(array),
                        owner=str(name).rsplit(".", 1)[0] if "." in str(name) else None,
                        op_type=None,
                    )
                )
            out.sort(key=lambda t: t.name)
            return tuple(out)
        return _named_parameters(handle)

    def layers(self, handle: ModelHandle) -> tuple[LayerInfo, ...]:
        if "state_dict" in handle.native:
            return ()
        return _module_layers(handle)

    def activation_layers(self, handle: ModelHandle) -> tuple[str, ...]:
        if "state_dict" in handle.native:
            return ()
        return _module_activation_layers(handle)

    def infer(
        self, handle: ModelHandle, batch: np.ndarray, *, capture: Sequence[str] = ()
    ) -> ModelOutput:
        if "state_dict" in handle.native:
            raise DetectorUnavailable(
                "inference is not possible on a state-dict artifact: it carries "
                "weights but no executable graph"
            )
        return _torch_infer(handle, batch, capture=capture)


# ----------------------------------------------------------------------
# Shared torch helpers
# ----------------------------------------------------------------------


def _module_type_name(sub: Any) -> str:
    """The module's logical class name.

    A TorchScript module is a ``RecursiveScriptModule`` whatever it was
    scripted from, and reporting that would collapse every layer in the model
    into one operator type — destroying both the operator histogram and the
    peer-group comparison that parameter analysis depends on.  ``original_name``
    carries the real class, so it wins where it exists.
    """
    return str(getattr(sub, "original_name", None) or type(sub).__name__)


def _named_parameters(handle: ModelHandle) -> tuple[ParameterTensor, ...]:
    module = handle.native["module"]
    owners = {name: _module_type_name(sub) for name, sub in module.named_modules()}
    out: list[ParameterTensor] = []
    seen: set[str] = set()
    for name, tensor in list(module.named_parameters()) + list(module.named_buffers()):
        if name in seen:
            continue
        seen.add(name)
        array = tensor.detach().cpu().numpy()
        owner = name.rsplit(".", 1)[0] if "." in name else ""
        out.append(
            ParameterTensor(
                name=str(name),
                dtype=str(array.dtype),
                shape=tuple(int(d) for d in array.shape),
                values=np.asarray(array),
                owner=owner or None,
                op_type=owners.get(owner),
            )
        )
    out.sort(key=lambda t: t.name)
    return tuple(out)


def _module_layers(handle: ModelHandle) -> tuple[LayerInfo, ...]:
    module = handle.native["module"]
    out: list[LayerInfo] = []
    for name, sub in module.named_modules():
        if name == "":
            continue
        children = list(sub.children())
        if children:
            # Containers carry no computation of their own; recording them would
            # make the graph digest sensitive to how the author nested modules
            # rather than to what the model computes.
            continue
        params = list(sub.named_parameters(recurse=False)) + list(
            sub.named_buffers(recurse=False)
        )
        count = sum(int(t.numel()) for _, t in params)
        dtypes = sorted({str(t.detach().cpu().numpy().dtype) for _, t in params})
        out.append(
            LayerInfo(
                name=str(name),
                op_type=_module_type_name(sub),
                parameter_count=count,
                parameter_dtypes=tuple(dtypes),
                attributes=_module_attributes(sub),
            )
        )
    return tuple(out)


def _module_attributes(sub: Any) -> dict[str, Any]:
    keys = (
        "in_channels", "out_channels", "kernel_size", "stride", "padding",
        "dilation", "groups", "in_features", "out_features", "num_features",
        "eps", "p",
    )
    out: dict[str, Any] = {}
    for key in keys:
        if not hasattr(sub, key):
            continue
        value = getattr(sub, key)
        if isinstance(value, (int, str, bool)):
            out[key] = value
        elif isinstance(value, float):
            out[key] = repr(value)
        elif isinstance(value, (tuple, list)) and all(isinstance(v, int) for v in value):
            out[key] = list(value)
    return dict(sorted(out.items()))


def _module_activation_layers(handle: ModelHandle) -> tuple[str, ...]:
    """Leaf modules worth tapping for representations.

    Restricted to activation and pooling/linear outputs, which is where the
    backdoor literature reads representations from; tapping every leaf would
    multiply cost without adding signal.
    """
    module = handle.native["module"]
    interesting = {
        "ReLU", "LeakyReLU", "GELU", "SiLU", "Tanh", "Sigmoid",
        "Linear", "AdaptiveAvgPool2d", "AvgPool2d", "MaxPool2d", "Flatten",
    }
    return tuple(
        name
        for name, sub in module.named_modules()
        if name and _module_type_name(sub) in interesting and not list(sub.children())
    )


def _torch_infer(
    handle: ModelHandle, batch: np.ndarray, *, capture: Sequence[str] = ()
) -> ModelOutput:
    torch = handle.native["torch"]
    module = handle.native["module"]
    capture = tuple(capture)

    captured: dict[str, np.ndarray] = {}
    hooks = []
    if capture:
        by_name = dict(module.named_modules())
        for name in capture:
            target = by_name.get(name)
            if target is None:
                continue

            def _hook(_module, _inputs, output, _name=name):
                tensor = output[0] if isinstance(output, (tuple, list)) else output
                captured[_name] = tensor.detach().cpu().numpy().astype(np.float64)

            hooks.append(target.register_forward_hook(_hook))

    try:
        tensor = torch.from_numpy(np.ascontiguousarray(batch, dtype=np.float32))
        with torch.no_grad():
            raw = module(tensor)
    except Exception as exc:
        raise AdapterError(f"inference failed on {handle.path}: {exc}") from exc
    finally:
        for hook in hooks:
            hook.remove()

    if isinstance(raw, (tuple, list)):
        raw = raw[0]
    logits = raw.detach().cpu().numpy().astype(np.float64)
    if logits.ndim == 1:
        logits = logits.reshape(1, -1)
    return ModelOutput(
        logits=logits,
        output_name=handle.outputs[0].name if handle.outputs else "output",
        already_normalised=False,
        activations=captured,
    )


#: Input shapes tried, in order, when a torch artifact does not declare one.
#: A torch module has no input signature, so the shape must come from somewhere:
#: the configuration if the operator supplied it, otherwise these conventional
#: CV shapes, and the *first one that executes* is recorded in the manifest as a
#: probed rather than declared fact.
_PROBE_SHAPES: tuple[tuple[int, ...], ...] = (
    (1, 3, 32, 32), (1, 3, 64, 64), (1, 3, 128, 128), (1, 3, 224, 224),
    (1, 1, 28, 28), (1, 3, 256, 256),
)


def _probe_signature(
    torch: Any, module: Any, path: Path, config: Any
) -> tuple[tuple[TensorSpec, ...], tuple[TensorSpec, ...], str]:
    """Determine input/output specs for a torch model.

    Unlike ONNX, a torch module declares no signature, so one has to be
    established empirically.  The declared configuration wins; otherwise a short
    list of conventional shapes is tried and the first that runs is recorded —
    explicitly marked as *probed*, because a probed shape is weaker evidence
    than a declared one and the manifest must not pretend otherwise.
    """
    declared = getattr(getattr(config, "model", None), "input_shape", None)
    candidates = ([tuple(declared)] if declared else []) + list(_PROBE_SHAPES)
    for shape in candidates:
        try:
            with torch.no_grad():
                out = module(torch.zeros(*shape, dtype=torch.float32))
        except Exception:  # noqa: BLE001 - a shape that does not run is simply not it
            continue
        if isinstance(out, (tuple, list)):
            out = out[0]
        out_shape = tuple(int(d) for d in out.shape)
        source = "declared in configuration" if declared and tuple(shape) == tuple(declared) else "probed"
        return (
            (TensorSpec(name="input", dtype="float32", shape=(None, *shape[1:])),),
            (TensorSpec(name="output", dtype="float32", shape=(None, *out_shape[1:])),),
            f"input shape {list(shape)} {source}; torch artifacts declare no "
            "signature, so this is an empirical fact, not a claim by the artifact",
        )
    raise AdapterError(
        f"could not establish an input shape for {path}: none of the probed shapes "
        f"{[list(s) for s in candidates]} produced a forward pass. Set "
        "model.input_shape in the configuration."
    )
