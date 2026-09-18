"""ONNX model adapter.

ONNX is the format this module treats as the baseline, because it is the one a
supplier is most likely to hand over and the one whose graph is fully
introspectable without executing any supplier-authored Python.

What ONNX gives us, and what it does not
----------------------------------------
``graph``, ``parameters`` and ``activations`` are all available: the protobuf
carries the full topology and every initializer, and ONNX Runtime will return
any intermediate tensor if it is added to the graph's outputs.

``gradients`` are **not** available.  ONNX Runtime's inference session does not
differentiate, and we do not add a training-runtime dependency to get it.  The
consequence is stated everywhere it matters: Neural-Cleanse-style trigger
*reconstruction* cannot run on an ONNX artifact, and the gradient-free
trigger-family probe runs instead under a different method name and
``Coverage.PARTIAL``.

Determinism
-----------
The session is pinned to one intra-op and one inter-op thread.  Multi-threaded
float reduction changes summation order, which changes the low bits of a logit,
which changes an argmax at a decision boundary — and that would make a
behavioural fingerprint non-reproducible.  One thread is slower and correct.
"""

from __future__ import annotations

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

log = get_logger("models.onnx")

#: ONNX elem_type -> numpy dtype name.  Explicit rather than derived, because
#: onnx's helper mapping has changed across releases and a silent dtype change
#: would alter a parameter digest.
_ELEM_TYPE: dict[int, str] = {
    1: "float32", 2: "uint8", 3: "int8", 4: "uint16", 5: "int16", 6: "int32",
    7: "int64", 9: "bool", 10: "float16", 11: "float64", 12: "uint32",
    13: "uint64", 16: "bfloat16",
}

#: Operators that carry learned parameters.  Used to attribute an initializer to
#: the node that consumes it, so parameter statistics can be grouped by layer
#: type rather than by whatever the exporter happened to name the tensor.
_PARAMETRIC_OPS = frozenset(
    {"Conv", "ConvTranspose", "Gemm", "MatMul", "BatchNormalization",
     "InstanceNormalization", "LayerNormalization", "PRelu", "Einsum", "LSTM", "GRU"}
)

#: Node output tensors worth offering as activation taps.  Capturing *every*
#: intermediate tensor of a large graph is both slow and mostly uninformative;
#: these are the representation-bearing ones the backdoor literature uses.
_ACTIVATION_OPS = frozenset(
    {"Relu", "Gemm", "Conv", "MatMul", "GlobalAveragePool", "AveragePool",
     "MaxPool", "Flatten", "Softmax", "Sigmoid", "Tanh", "Add", "Concat"}
)


def _require_onnx() -> tuple[Any, Any]:
    try:
        import onnx
        import onnxruntime
    except ImportError as exc:  # pragma: no cover - exercised by the extras test
        raise DetectorUnavailable(
            "ONNX support unavailable: the 'onnx' and 'onnxruntime' packages are "
            "not installed in this offline environment. Install the 'onnx' extra "
            "from a local wheel directory; nothing is downloaded at run time."
        ) from exc
    return onnx, onnxruntime


class OnnxModelAdapter:
    """Adapter for ``.onnx`` artifacts."""

    name = "onnx"
    version = "1.0"
    model_format = "onnx"

    @staticmethod
    def detect(path: Path) -> bool:
        path = Path(path)
        if path.suffix.lower() != ".onnx" or not path.is_file():
            return False
        # A protobuf has no magic number, so the extension is the only cheap
        # signal.  Content is validated at load time, where a failure becomes an
        # explained AdapterError rather than a wrong-format guess.
        return True

    # -- loading ---------------------------------------------------------

    def load(self, path: Path, config: Any = None) -> ModelHandle:
        onnx, onnxruntime = _require_onnx()
        path = Path(path)
        try:
            proto = onnx.load(str(path))
        except Exception as exc:
            raise AdapterError(f"{path} is not a readable ONNX artifact: {exc}") from exc

        try:
            onnx.checker.check_model(proto, full_check=False)
            check_note = "onnx.checker: passed"
        except Exception as exc:  # noqa: BLE001 - a fact to record, not a failure
            # A model that fails the checker is still analysable and the failure
            # is itself evidence, so it is recorded rather than raised.
            check_note = f"onnx.checker: FAILED ({exc})"
            log.warning("%s failed onnx.checker: %s", path, exc)

        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.execution_mode = onnxruntime.ExecutionMode.ORT_SEQUENTIAL
        # Graph optimisation rewrites the executed graph (operator fusion), which
        # would make captured activation names unavailable and make timing
        # incomparable between artifacts. Disabled so that what runs is what the
        # manifest describes.
        options.graph_optimization_level = (
            onnxruntime.GraphOptimizationLevel.ORT_DISABLE_ALL
        )
        try:
            session = onnxruntime.InferenceSession(
                str(path), sess_options=options, providers=["CPUExecutionProvider"]
            )
        except Exception as exc:
            raise AdapterError(f"ONNX Runtime cannot load {path}: {exc}") from exc

        inputs = tuple(_spec_from_session(i) for i in session.get_inputs())
        outputs = tuple(_spec_from_session(o) for o in session.get_outputs())

        declared: dict[str, Any] = {
            "producer_name": proto.producer_name or None,
            "producer_version": proto.producer_version or None,
            "ir_version": int(proto.ir_version),
            "opset": {
                (op.domain or "ai.onnx"): int(op.version) for op in proto.opset_import
            },
            "doc_string": (proto.doc_string or None),
            "graph_name": proto.graph.name or None,
        }
        for entry in proto.metadata_props:
            declared[f"meta.{entry.key}"] = entry.value
        if "meta.architecture" in declared:
            declared["architecture"] = declared["meta.architecture"]
        declared = {k: v for k, v in declared.items() if v is not None}

        return ModelHandle(
            path=path,
            model_format=self.model_format,
            adapter=self.name,
            adapter_version=self.version,
            access_mode=AccessMode.WHITE_BOX,
            capabilities=frozenset(
                {
                    Capability.INFERENCE,
                    Capability.GRAPH,
                    Capability.PARAMETERS,
                    Capability.ACTIVATIONS,
                    # Deliberately absent: GRADIENTS.
                }
            ),
            inputs=inputs,
            outputs=outputs,
            native={"proto": proto, "session": session, "options": options},
            declared_metadata=declared,
            runtime={
                "onnx": onnx.__version__,
                "onnxruntime": onnxruntime.__version__,
                "providers": ",".join(session.get_providers()),
            },
            unavailable=("gradients",),
            notes=(
                check_note,
                "ONNX Runtime provides no input gradients: trigger reconstruction "
                "is not performed on this format; a gradient-free trigger-family "
                "probe is used instead and is reported as such.",
                "session pinned to 1 intra-op / 1 inter-op thread and graph "
                "optimisation disabled, for reproducible logits",
            ),
        )

    # -- introspection ---------------------------------------------------

    def parameters(self, handle: ModelHandle) -> tuple[ParameterTensor, ...]:
        onnx, _ = _require_onnx()
        from onnx import numpy_helper

        proto = handle.native["proto"]
        owner, op_type = self._initializer_owners(proto)
        out: list[ParameterTensor] = []
        for initializer in proto.graph.initializer:
            array = numpy_helper.to_array(initializer)
            out.append(
                ParameterTensor(
                    name=initializer.name,
                    dtype=str(array.dtype),
                    shape=tuple(int(d) for d in array.shape),
                    values=np.asarray(array),
                    owner=owner.get(initializer.name),
                    op_type=op_type.get(initializer.name),
                )
            )
        out.sort(key=lambda t: t.name)
        return tuple(out)

    @staticmethod
    def _initializer_owners(proto: Any) -> tuple[dict[str, str], dict[str, str]]:
        owner: dict[str, str] = {}
        op_type: dict[str, str] = {}
        for node in proto.graph.node:
            node_name = node.name or (node.output[0] if node.output else node.op_type)
            for input_name in node.input:
                if input_name not in owner:
                    owner[input_name] = node_name
                    op_type[input_name] = node.op_type
        return owner, op_type

    def layers(self, handle: ModelHandle) -> tuple[LayerInfo, ...]:
        proto = handle.native["proto"]
        initializer_shapes = {
            init.name: (
                tuple(int(d) for d in init.dims),
                _ELEM_TYPE.get(int(init.data_type), f"elem{init.data_type}"),
            )
            for init in proto.graph.initializer
        }
        value_shapes = _value_info_shapes(proto)

        out: list[LayerInfo] = []
        for index, node in enumerate(proto.graph.node):
            name = node.name or f"{node.op_type}_{index}"
            param_names = [n for n in node.input if n in initializer_shapes]
            count = 0
            dtypes: list[str] = []
            for param in param_names:
                shape, dtype = initializer_shapes[param]
                size = 1
                for dim in shape:
                    size *= dim
                count += size
                dtypes.append(dtype)
            first_output = node.output[0] if node.output else None
            out.append(
                LayerInfo(
                    name=name,
                    op_type=node.op_type,
                    # Initializers are excluded from input_names: they are
                    # parameters, already described by parameter records, and
                    # including them would make the graph digest change on a
                    # pure weight rename.
                    input_names=tuple(n for n in node.input if n not in initializer_shapes),
                    output_names=tuple(node.output),
                    output_shape=value_shapes.get(first_output) if first_output else None,
                    parameter_count=count,
                    parameter_dtypes=tuple(sorted(set(dtypes))),
                    attributes=_node_attributes(node),
                )
            )
        return tuple(out)

    def activation_layers(self, handle: ModelHandle) -> tuple[str, ...]:
        proto = handle.native["proto"]
        declared_outputs = {o.name for o in proto.graph.output}
        names: list[str] = []
        for node in proto.graph.node:
            if node.op_type not in _ACTIVATION_OPS:
                continue
            for output in node.output:
                if output and output not in declared_outputs:
                    names.append(output)
        return tuple(names)

    # -- inference -------------------------------------------------------

    def infer(
        self, handle: ModelHandle, batch: np.ndarray, *, capture: Sequence[str] = ()
    ) -> ModelOutput:
        onnx, onnxruntime = _require_onnx()
        session = handle.native["session"]
        capture = tuple(capture)
        if capture:
            session = self._session_with_taps(handle, capture)

        input_name = handle.inputs[0].name
        dtype = np.dtype(handle.inputs[0].dtype)
        feed = {input_name: np.ascontiguousarray(batch, dtype=dtype)}
        try:
            raw = session.run(None, feed)
        except Exception as exc:
            raise AdapterError(f"inference failed on {handle.path}: {exc}") from exc

        output_names = [o.name for o in session.get_outputs()]
        primary_name = handle.outputs[0].name
        primary_index = (
            output_names.index(primary_name) if primary_name in output_names else 0
        )
        logits = np.asarray(raw[primary_index], dtype=np.float64)
        if logits.ndim == 1:
            logits = logits.reshape(1, -1)

        activations: dict[str, np.ndarray] = {}
        for name in capture:
            if name in output_names:
                activations[name] = np.asarray(
                    raw[output_names.index(name)], dtype=np.float64
                )

        return ModelOutput(
            logits=logits,
            output_name=primary_name,
            already_normalised=_looks_normalised(handle, primary_name),
            activations=activations,
        )

    def _session_with_taps(self, handle: ModelHandle, capture: Sequence[str]) -> Any:
        """A session whose graph exposes the requested intermediate tensors.

        Cached on the handle, keyed by the tap set: rebuilding a session per
        batch would dominate runtime on a battery of several hundred probes.
        """
        onnx, onnxruntime = _require_onnx()
        key = ("taps", tuple(sorted(capture)))
        cache = handle.native.setdefault("_tap_sessions", {})
        if key in cache:
            return cache[key]

        proto = handle.native["proto"]
        patched = onnx.ModelProto()
        patched.CopyFrom(proto)
        known = {vi.name for vi in patched.graph.output}
        for name in capture:
            if name in known:
                continue
            patched.graph.output.extend(
                [onnx.helper.make_empty_tensor_value_info(name)]
            )
        try:
            session = onnxruntime.InferenceSession(
                patched.SerializeToString(),
                sess_options=handle.native["options"],
                providers=["CPUExecutionProvider"],
            )
        except Exception as exc:
            raise DetectorUnavailable(
                f"activation capture unavailable on {handle.path}: the runtime "
                f"refused a graph exposing the requested intermediate tensors ({exc})"
            ) from exc
        cache[key] = session
        return session


def _spec_from_session(node: Any) -> TensorSpec:
    shape: list[int | None] = []
    for dim in node.shape or ():
        shape.append(int(dim) if isinstance(dim, int) else None)
    return TensorSpec(
        name=node.name, dtype=_ort_dtype(node.type), shape=tuple(shape)
    )


def _ort_dtype(type_string: str) -> str:
    """``tensor(float)`` -> ``float32``."""
    mapping = {
        "tensor(float)": "float32", "tensor(double)": "float64",
        "tensor(float16)": "float16", "tensor(int64)": "int64",
        "tensor(int32)": "int32", "tensor(uint8)": "uint8",
        "tensor(int8)": "int8", "tensor(bool)": "bool",
    }
    return mapping.get(type_string, type_string)


def _value_info_shapes(proto: Any) -> dict[str, tuple[int | None, ...]]:
    shapes: dict[str, tuple[int | None, ...]] = {}
    for collection in (proto.graph.value_info, proto.graph.output, proto.graph.input):
        for value in collection:
            if not value.type.HasField("tensor_type"):
                continue
            dims: list[int | None] = []
            for dim in value.type.tensor_type.shape.dim:
                dims.append(int(dim.dim_value) if dim.HasField("dim_value") and dim.dim_value else None)
            shapes[value.name] = tuple(dims)
    return shapes


def _node_attributes(node: Any) -> dict[str, Any]:
    """Structural attributes only (ints and int lists).

    Tensor-valued attributes are excluded: they are parameters in disguise, and
    including them here would make the *graph* digest sensitive to weight
    values, destroying the separation the three-digest design depends on.
    """
    out: dict[str, Any] = {}
    for attribute in node.attribute:
        if attribute.type == 2:  # INT
            out[attribute.name] = int(attribute.i)
        elif attribute.type == 7:  # INTS
            out[attribute.name] = [int(v) for v in attribute.ints]
        elif attribute.type == 3:  # STRING
            out[attribute.name] = attribute.s.decode("utf-8", errors="replace")
    return dict(sorted(out.items()))


def _looks_normalised(handle: ModelHandle, output_name: str) -> bool:
    """Whether the primary output is already a probability distribution.

    Determined from the graph (is the producing node a ``Softmax``?), not from
    the values: inferring it from the values would misclassify a logit vector
    that happens to sum near 1, and applying softmax twice silently flattens
    every distribution the divergence metrics are computed from.
    """
    proto = handle.native.get("proto")
    if proto is None:
        return False
    for node in proto.graph.node:
        if output_name in node.output and node.op_type in {"Softmax", "LogSoftmax"}:
            return node.op_type == "Softmax"
    return False
