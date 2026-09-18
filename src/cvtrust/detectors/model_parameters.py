"""White-box parameter analysis detector.

Emits three distinct kinds of claim, and keeps them distinct because they have
very different evidential weight:

1. **Non-finite weights** — a deterministic defect.  A NaN in a weight tensor
   will produce undefined behaviour at inference; it is a fact about the
   artifact and gets confidence 1.0.

2. **Parameter difference from a trusted reference** — also deterministic.
   Tensor digests either match or they do not, and where they do not, the
   per-tensor relative L2 delta localises the change.  The *interpretation*
   (targeted edit versus fine-tune) is offered as a reading with its own
   evidence, not asserted.

3. **Peer-group statistical outliers** — a screening signal, nothing more.
   This is where the temptation to overclaim lives, and it is resisted
   structurally: the finding is titled a ``PARAMETER ANOMALY INDICATOR``, its
   severity is capped at ``MEDIUM``, and it carries a limitation stating that
   no published result connects unusual weight statistics to backdoors.

The attack lab contains a clean model with deliberately unusual weights
(``clean_unusual_init``) precisely so that (3)'s false-positive behaviour is
measured rather than assumed.
"""

from __future__ import annotations

from ..core.evidence import (
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Severity,
)
from ..models.base import Capability
from ..models.params import (
    analyse_parameters,
    compare_parameters,
    non_finite_weights,
    peer_outliers,
)
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext, white_box_coverage

ATTACK_CLASS = "model_tampering"

#: Prior used when no calibration table covers this detector.  Capped at the
#: uncalibrated ceiling by the schema anyway; stated here so the number in the
#: report has a source.
PEER_OUTLIER_PRIOR = 0.35


class ModelParameterDetector:
    """Layer-wise weight statistics, compared to a reference or to peers."""

    name = "model_parameters"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = (Capability.PARAMETERS,)

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)

        if not ctx.supplied.has(Capability.PARAMETERS):
            reason = (
                f"parameter analysis requires weight access, which the "
                f"'{ctx.supplied.model_format}' artifact does not provide "
                f"(access mode {ctx.access_mode.value}). Layer statistics, "
                "reference comparison and peer-outlier screening were all "
                "skipped, not passed."
            )
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS,
                    white_box_coverage(ctx, Capability.PARAMETERS),
                    detector=self.name, detector_version=self.version, reason=reason,
                )
            )
            return out

        tensors = ctx.supplied_adapter.parameters(ctx.supplied)
        statistics = analyse_parameters(tensors)
        out.stats = {
            "access_mode": ctx.access_mode.value,
            "tensor_count": statistics["tensor_count"],
            "parameter_count": statistics["parameter_count"],
            "global": statistics["global"],
            "by_op_type": statistics["by_op_type"],
        }

        # -- 1. non-finite weights: deterministic --------------------------
        non_finite = non_finite_weights(tensors)
        if non_finite["total_non_finite"]:
            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.model_asset(),
                    category=Category.MODEL,
                    title="Model contains non-finite weights",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    basis=ConfidenceBasis.DETERMINISTIC,
                    coverage=Coverage.SUPPORTED,
                    discriminator=("non_finite",),
                    evidence=[
                        EvidenceItem(
                            kind="non_finite_weights",
                            statement=(
                                f"{non_finite['total_non_finite']} weight element(s) "
                                f"across {len(non_finite['affected_tensors'])} tensor(s) "
                                "are NaN or infinite."
                            ),
                            observation=non_finite,
                            refs=(str(ctx.supplied.path),),
                        )
                    ],
                    assumptions=(),
                    limitations=(
                        "non-finite weights are a defect, not necessarily an "
                        "attack: a diverged training run produces them too",
                    ),
                )
            )
            out.flagged[ATTACK_CLASS] = {ctx.supplied_manifest.model_id}

        # -- 2. reference comparison: deterministic ------------------------
        if ctx.has_reference and ctx.reference is not None and ctx.reference_adapter is not None:
            if ctx.reference.has(Capability.PARAMETERS):
                self._compare_to_reference(ctx, factory, out, tensors)
            else:
                out.coverage.append(
                    coverage_entry(
                        ATTACK_CLASS, Coverage.PARTIAL,
                        detector=self.name, detector_version=self.version,
                        reason=(
                            "the reference artifact does not expose weights, so the "
                            "comparison fell back to reference-free peer screening"
                        ),
                    )
                )

        # -- 3. peer-group screening: a signal, not a verdict --------------
        peers = peer_outliers(
            tensors, z_threshold=ctx.config.model.parameters.peer_z_threshold
        )
        out.stats["peer_screening"] = {
            "n_outliers": peers["n_outliers"],
            "peer_groups": peers["peer_groups"],
            "skipped_small_groups": peers["skipped_small_groups"],
        }
        if peers["outliers"] and not ctx.has_reference:
            # Only raised when there is no reference. With a reference, the
            # deterministic comparison above is strictly better evidence, and
            # adding a weaker statistical claim beside it would be noise.
            self._emit_peer_finding(ctx, factory, out, peers)

        if not out.coverage:
            out.coverage.append(self._coverage(ctx, peers))
        return out

    # ------------------------------------------------------------------

    def _compare_to_reference(self, ctx, factory, out, tensors) -> None:
        reference_tensors = ctx.reference_adapter.parameters(ctx.reference)
        comparison = compare_parameters(tensors, reference_tensors)
        ctx.shared["parameter_comparison"] = comparison
        out.stats["reference_comparison"] = {
            "changed_tensors": comparison["changed_tensors"],
            "identical_tensors": comparison["identical_tensors"],
            "max_relative_l2_delta": comparison["max_relative_l2_delta"],
            "concentration": comparison["concentration"]["pattern"],
        }

        cross_format = (
            ctx.supplied_manifest.model_format != ctx.reference_manifest.model_format
        )
        if cross_format:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.PARTIAL,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        "the artifacts are in different formats, whose exporters "
                        "name weight tensors differently, so tensor-level "
                        "correspondence is unreliable"
                    ),
                )
            )
            return

        if comparison["changed_tensors"] == 0 and not comparison["reshaped_tensors"]:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=("the reference artifact's weights are the assured weights",),
                    limitations=(
                        "identical weights mean the artifact computes what the "
                        "reference computes. Whether the reference itself carries "
                        "a backdoor is a separate question, assessed by the "
                        "backdoor detectors",
                    ),
                )
            )
            return

        concentration = comparison["concentration"]
        localised = concentration["pattern"] == "localised"
        severity = Severity.HIGH if localised else Severity.MEDIUM

        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title=(
                    f"Model weights differ from the reference in "
                    f"{comparison['changed_tensors']} tensor(s)"
                ),
                severity=severity,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                coverage=Coverage.SUPPORTED,
                discriminator=("parameter_delta", str(ctx.reference_manifest.parameter_digest)),
                evidence=[
                    EvidenceItem(
                        kind="parameter_difference",
                        statement=(
                            f"{comparison['changed_tensors']} of "
                            f"{comparison['shared_tensors']} shared tensors differ "
                            f"from the reference; the largest relative L2 change is "
                            f"{comparison['max_relative_l2_delta']:.4g} in "
                            f"'{concentration.get('top_tensor')}'."
                        ),
                        observation={
                            "shared_tensors": comparison["shared_tensors"],
                            "identical_tensors": comparison["identical_tensors"],
                            "changed_tensors": comparison["changed_tensors"],
                            "total_changed_elements": comparison["total_changed_elements"],
                            "max_relative_l2_delta": comparison["max_relative_l2_delta"],
                            "changed": comparison["changed"][:20],
                            "reshaped_tensors": comparison["reshaped_tensors"],
                            "only_in_supplied": comparison["only_in_supplied"][:20],
                            "only_in_reference": comparison["only_in_reference"][:20],
                        },
                        refs=(str(ctx.supplied.path),),
                    ),
                    EvidenceItem(
                        kind="change_concentration",
                        statement=str(concentration["reading"]),
                        observation=concentration,
                        refs=(),
                    ),
                ],
                assumptions=(
                    "the reference artifact's weights are the weights that were assured",
                    "tensor names correspond between the two artifacts",
                ),
                limitations=(
                    "a weight difference establishes that the weights changed, not "
                    "that the change was malicious: retraining, fine-tuning, "
                    "quantisation and pruning all produce weight differences",
                    "the localised-versus-distributed reading is an interpretation "
                    "of the measured distribution of change, not a classification "
                    "of intent",
                ),
            )
        )
        out.flagged.setdefault(ATTACK_CLASS, set()).add(ctx.supplied_manifest.model_id)
        out.scores.setdefault(ATTACK_CLASS, {})[ctx.supplied_manifest.model_id] = 1.0
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=("a trusted reference exposing weights is available",),
                limitations=(
                    "detects that weights changed, not that they were maliciously "
                    "changed",
                ),
            )
        )

    def _emit_peer_finding(self, ctx, factory, out, peers) -> None:
        top = peers["outliers"][0]
        # Score is the peak |robust z| squashed into [0, 1] so it can be resolved
        # against a calibration table on the same scale as every other
        # threshold-based detector in the system.
        score = min(1.0, abs(float(top["robust_z"])) / 10.0)
        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title="PARAMETER ANOMALY INDICATOR: weight statistics unlike their peers",
                # Capped at MEDIUM deliberately. A statistic about weights, with
                # no reference and no behavioural corroboration, must not be able
                # to drive a severe disposition on its own.
                severity=Severity.MEDIUM,
                score=score,
                prior=PEER_OUTLIER_PRIOR,
                coverage=Coverage.PARTIAL,
                discriminator=("peer_outlier", str(top["tensor"]), str(top["metric"])),
                evidence=[
                    EvidenceItem(
                        kind="parameter_peer_outlier",
                        statement=(
                            f"Tensor '{top['tensor']}' has {top['metric']} "
                            f"{top['value']:.6g} against a peer-group median of "
                            f"{top['peer_median']:.6g} (robust z = {top['robust_z']:.2f}, "
                            f"peer group '{top['op_type']}', n = {top['peer_group_size']})."
                        ),
                        observation={
                            "method": peers["method"],
                            "z_threshold": peers["z_threshold"],
                            "n_outliers": peers["n_outliers"],
                            "outliers": peers["outliers"][:15],
                            "peer_groups": peers["peer_groups"],
                            "skipped_small_groups": peers["skipped_small_groups"],
                        },
                        refs=(str(ctx.supplied.path),),
                    ),
                    EvidenceItem(
                        kind="interpretation_limit",
                        statement=str(peers["interpretation_limit"]),
                        observation={
                            "claim": "weight statistics are unusual within this model",
                            "not_claimed": "the model is backdoored",
                            "requires_corroboration": True,
                        },
                        refs=(),
                    ),
                ],
                assumptions=(
                    "tensors of the same operator type and parameter role are "
                    "comparable within one model",
                    "at least four comparable peers exist; smaller groups are "
                    "skipped rather than guessed at",
                ),
                limitations=(
                    "this is a screening signal about weight statistics. No "
                    "published result establishes that unusual weight statistics "
                    "imply a backdoor, and quantisation-aware training, unusual "
                    "initialisation, weight decay and layer saturation all produce "
                    "the same observation in clean models",
                    "reference-free: with a trusted reference available, the "
                    "deterministic tensor comparison is strictly better evidence "
                    "and this screening is not used",
                ),
            )
        )
        out.flagged.setdefault(ATTACK_CLASS, set()).add(ctx.supplied_manifest.model_id)
        out.scores.setdefault(ATTACK_CLASS, {})[ctx.supplied_manifest.model_id] = score

    def _coverage(self, ctx: ModelAnalysisContext, peers) -> object:
        if ctx.has_reference:
            return coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=("a trusted reference exposing weights is available",),
                limitations=("detects weight change, not malicious intent",),
            )
        return coverage_entry(
            ATTACK_CLASS, Coverage.PARTIAL,
            detector=self.name, detector_version=self.version,
            reason=(
                "no trusted reference was supplied, so only reference-free peer "
                "screening was possible"
                + (
                    "; every peer group had fewer than four comparable tensors, so "
                    "even that screening could not run on this architecture"
                    if peers["skipped_small_groups"] and not peers["outliers"]
                    and not any(n >= 4 for n in peers["peer_groups"].values())
                    else ""
                )
            ),
            limitations=(
                "peer screening is a statement about weight statistics within one "
                "model, and is far weaker evidence than a reference comparison",
            ),
        )
