"""Structural fingerprint comparison.

Answers one question: *is this the same architecture?*  Deterministically, from
the graph digest, and then — where it differs — by naming exactly what differs,
because "the structure changed" is not an actionable statement and "the third
convolution's output channel count went from 32 to 48" is.

The structural fingerprint is deliberately weight-blind (see
:mod:`cvtrust.models.manifest`).  A model whose weights were replaced wholesale
has an identical structural fingerprint, and that is correct behaviour: weights
are the parameter detector's subject, and a detector that answered both
questions with one number would be able to answer neither precisely.

Without a reference, structure cannot be *compared*, but it can still be
*described*, and two description-level facts are worth reporting on their own:
an artifact whose declared architecture contradicts its measured graph, and an
artifact carrying operators outside the set a classifier needs.
"""

from __future__ import annotations

from typing import Any

from ..core.evidence import (
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Severity,
)
from ..models.base import Capability
from ..models.manifest import LayerRecord, ModelManifest
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext, white_box_coverage

ATTACK_CLASS = "model_tampering"


def _layer_signature(layer: LayerRecord) -> tuple[Any, ...]:
    """The part of a layer that defines its structural role.

    Names are excluded: an exporter is free to rename nodes, and a rename is not
    a structural change.  Op type, output shape, parameter count and dtypes are
    what determine what the layer computes.
    """
    return (
        layer.op_type,
        tuple(layer.output_shape) if layer.output_shape else None,
        layer.parameter_count,
        tuple(layer.parameter_dtypes),
    )


def diff_structure(
    supplied: ModelManifest, reference: ModelManifest
) -> dict[str, Any]:
    """Locate structural differences between two manifests."""
    differences: list[dict[str, Any]] = []

    if len(supplied.layers) != len(reference.layers):
        differences.append({
            "kind": "layer_count",
            "supplied": len(supplied.layers),
            "reference": len(reference.layers),
        })

    for index, (left, right) in enumerate(zip(supplied.layers, reference.layers)):
        if _layer_signature(left) != _layer_signature(right):
            differences.append({
                "kind": "layer_mismatch",
                "position": index,
                "supplied": {
                    "name": left.name, "op_type": left.op_type,
                    "output_shape": list(left.output_shape or []),
                    "parameter_count": left.parameter_count,
                },
                "reference": {
                    "name": right.name, "op_type": right.op_type,
                    "output_shape": list(right.output_shape or []),
                    "parameter_count": right.parameter_count,
                },
            })

    operator_delta: dict[str, dict[str, int]] = {}
    for op in sorted(set(supplied.operators) | set(reference.operators)):
        a, b = supplied.operators.get(op, 0), reference.operators.get(op, 0)
        if a != b:
            operator_delta[op] = {"supplied": a, "reference": b}

    io_differences: list[dict[str, Any]] = []
    for label, left_specs, right_specs in (
        ("input", supplied.inputs, reference.inputs),
        ("output", supplied.outputs, reference.outputs),
    ):
        left_shapes = [list(s.shape) for s in left_specs]
        right_shapes = [list(s.shape) for s in right_specs]
        left_dtypes = [s.dtype for s in left_specs]
        right_dtypes = [s.dtype for s in right_specs]
        if left_shapes != right_shapes or left_dtypes != right_dtypes:
            io_differences.append({
                "kind": f"{label}_specification",
                "supplied": {"shapes": left_shapes, "dtypes": left_dtypes},
                "reference": {"shapes": right_shapes, "dtypes": right_dtypes},
            })

    return {
        "graph_match": supplied.graph_digest == reference.graph_digest,
        "supplied_graph_digest": supplied.graph_digest,
        "reference_graph_digest": reference.graph_digest,
        "layer_differences": differences[:40],
        "layer_difference_count": len(differences),
        "operator_histogram_delta": operator_delta,
        "io_differences": io_differences,
        "supplied_parameter_count": supplied.parameter_count,
        "reference_parameter_count": reference.parameter_count,
        "parameter_count_delta": (
            (supplied.parameter_count or 0) - (reference.parameter_count or 0)
        ),
    }


class ModelStructureDetector:
    """Graph-level comparison against a trusted reference."""

    name = "model_structure"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = (Capability.GRAPH,)

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        supplied = ctx.supplied_manifest

        if not ctx.supplied.has(Capability.GRAPH) or supplied.graph_digest is None:
            reason = (
                f"structural assessment requires graph access, which the "
                f"'{supplied.model_format}' artifact does not provide "
                f"(access mode {ctx.access_mode.value}). No architecture "
                "comparison was performed."
            )
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS,
                    white_box_coverage(ctx, Capability.GRAPH),
                    detector=self.name, detector_version=self.version, reason=reason,
                )
            )
            return out

        out.stats = {
            "graph_digest": supplied.graph_digest,
            "layer_count": len(supplied.layers),
            "operators": supplied.operators,
            "parameter_count": supplied.parameter_count,
            "inputs": [s.model_dump(mode="json") for s in supplied.inputs],
            "outputs": [s.model_dump(mode="json") for s in supplied.outputs],
        }

        if not ctx.has_reference:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.PARTIAL,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        "the structural fingerprint was computed and recorded, but "
                        "with no trusted reference there is nothing to compare it "
                        "to; structural *modification* is therefore not assessed"
                    ),
                    limitations=(
                        "a fingerprint with no baseline detects nothing on its own. "
                        "It establishes the baseline for a future assessment",
                    ),
                )
            )
            return out

        reference = ctx.reference_manifest
        assert reference is not None
        if reference.graph_digest is None:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        f"the reference artifact's '{reference.model_format}' format "
                        "exposes no graph, so a structural comparison is undefined"
                    ),
                )
            )
            return out

        difference = diff_structure(supplied, reference)
        ctx.shared["structure_comparison"] = difference
        out.stats["comparison"] = difference

        if difference["graph_match"]:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=("the reference artifact is the architecture that was assured",),
                    limitations=(
                        "a structural match is weight-blind by design: a model whose "
                        "weights were replaced entirely has an identical structural "
                        "fingerprint. Weight-level change is the parameter "
                        "detector's subject",
                    ),
                )
            )
            out.flagged[ATTACK_CLASS] = set()
            return out

        # Cross-format comparison is a known confounder and is called out rather
        # than silently producing a finding: an ONNX export and a TorchScript
        # archive of the *same* model have genuinely different graphs, because
        # the exporters fuse and name operators differently.
        cross_format = supplied.model_format != reference.model_format
        severity = Severity.MEDIUM if cross_format else Severity.HIGH
        limitations = [
            "a structural difference is not by itself evidence of an attack: a "
            "re-export at a different opset, a different exporter version or a "
            "recompilation can change the graph without changing the model",
        ]
        if cross_format:
            limitations.insert(
                0,
                f"the artifacts are in different formats ({supplied.model_format} "
                f"vs {reference.model_format}), whose exporters name and fuse "
                "operators differently. A structural difference between formats is "
                "expected and this finding is severity-capped accordingly",
            )

        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title="Model structure differs from the trusted reference",
                severity=severity,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                coverage=Coverage.SUPPORTED,
                discriminator=("graph", str(reference.graph_digest)),
                evidence=[
                    EvidenceItem(
                        kind="structural_fingerprint",
                        statement=(
                            "The weight-blind graph digest differs between the "
                            "supplied artifact and the reference."
                        ),
                        observation={
                            "supplied_graph_digest": difference["supplied_graph_digest"],
                            "reference_graph_digest": difference["reference_graph_digest"],
                            "match": False,
                            "supplied_format": supplied.model_format,
                            "reference_format": reference.model_format,
                            "cross_format_comparison": cross_format,
                        },
                        refs=(str(ctx.supplied.path),),
                    ),
                    EvidenceItem(
                        kind="structural_difference",
                        statement=(
                            f"{difference['layer_difference_count']} layer-level "
                            f"difference(s), with a parameter-count delta of "
                            f"{difference['parameter_count_delta']}."
                        ),
                        observation={
                            "layer_difference_count": difference["layer_difference_count"],
                            "layer_differences": difference["layer_differences"],
                            "operator_histogram_delta": difference["operator_histogram_delta"],
                            "io_differences": difference["io_differences"],
                            "supplied_parameter_count": difference["supplied_parameter_count"],
                            "reference_parameter_count": difference["reference_parameter_count"],
                            "parameter_count_delta": difference["parameter_count_delta"],
                        },
                        refs=(),
                    ),
                ],
                assumptions=(
                    "the reference artifact is the architecture that was assured",
                    "the structural fingerprint covers topology, operator types, "
                    "tensor shapes and dtypes; it deliberately excludes weight "
                    "values and node names",
                ),
                limitations=tuple(limitations),
            )
        )
        out.flagged[ATTACK_CLASS] = {supplied.model_id}
        out.scores[ATTACK_CLASS] = {supplied.model_id: 1.0}
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=("a trusted reference manifest is available",),
                limitations=tuple(limitations),
            )
        )
        return out
