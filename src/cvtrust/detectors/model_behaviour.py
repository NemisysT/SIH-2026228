"""Behavioural fingerprint detector — the black-box pathway.

This is the detector that has to work when nothing else can.  With only
``infer`` available it still produces two real measurements:

* **metamorphic consistency**, which needs no reference at all, because the
  battery's perturbations are semantics-preserving by construction and a
  prediction flip under one is instability that can be counted; and
* **behavioural divergence from a trusted reference**, where one exists.

It also publishes the fingerprints into ``ctx.shared`` for the activation and
trigger detectors that run after it, so the battery is forwarded once rather
than three times.

A deliberate omission: this detector does **not** raise a finding from the
trigger-probe metrics, even though it computes them.  Targeted-transition
evidence belongs to ``model_trigger``, which owns the ``model_backdoor`` attack
class; having two detectors raise findings from the same observation would
double-count it in every roll-up and in the calibration tables.
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
from ..models.behaviour import (
    compare_fingerprints,
    compute_fingerprint,
    metamorphic_consistency,
    ood_confidence_guard,
    targeted_transition,
)
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext

ATTACK_CLASS = "model_tampering"

#: Behavioural agreement below which a supplied model is called anomalous
#: relative to its reference.  Not a tuned constant: two artifacts of the *same*
#: model agree on 100% of probes (both re-serialisation and cross-format export
#: were measured at 1.000 agreement in the lab), so any disagreement at all is a
#: real behavioural difference.  The threshold is set just below 1.0 to absorb
#: a boundary probe flipping on last-bit float differences between runtimes.
AGREEMENT_FLOOR = 0.98

#: Metamorphic consistency below which a model is called unstable. A prediction
#: that changes under a brightness or JPEG change is a genuine robustness
#: defect regardless of cause, which is why this fires without a reference.
CONSISTENCY_FLOOR = 0.70

BEHAVIOUR_PRIOR = 0.45


class ModelBehaviourDetector:
    """Behavioural fingerprinting, with and without a reference."""

    name = "model_behaviour"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = (Capability.INFERENCE,)

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)

        if not ctx.supplied.has(Capability.INFERENCE):
            reason = (
                f"behavioural assessment requires a forward pass, which the "
                f"'{ctx.supplied.model_format}' artifact does not support "
                f"({', '.join(ctx.supplied_manifest.unavailable_fields) or 'no reason recorded'}). "
                "No behavioural claim is made."
            )
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version, reason=reason,
                )
            )
            return out

        battery = ctx.require_battery("behavioural assessment")
        supplied_fp = compute_fingerprint(
            ctx.supplied, ctx.supplied_adapter, battery,
            model_id=ctx.supplied_manifest.model_id,
        )
        ctx.shared["supplied_fingerprint"] = supplied_fp

        consistency = metamorphic_consistency(supplied_fp, battery)
        ood_guard = ood_confidence_guard(supplied_fp, battery)
        transitions = targeted_transition(supplied_fp, battery)
        ctx.shared["targeted_transition"] = transitions
        ctx.shared["metamorphic_consistency"] = consistency
        ctx.shared["ood_guard"] = ood_guard

        out.stats = {
            "access_mode": ctx.access_mode.value,
            "battery_digest": battery.digest,
            "battery_version": battery.version,
            "supplied_fingerprint": supplied_fp.summary(),
            "metamorphic_consistency": consistency,
            "ood_guard": ood_guard,
        }

        reference_fp = None
        if ctx.has_reference and ctx.reference is not None and ctx.reference_adapter is not None:
            if ctx.reference.has(Capability.INFERENCE):
                reference_fp = compute_fingerprint(
                    ctx.reference, ctx.reference_adapter, battery,
                    model_id=ctx.reference_manifest.model_id,
                )
                ctx.shared["reference_fingerprint"] = reference_fp
                out.stats["reference_fingerprint"] = reference_fp.summary()

        self._metamorphic_finding(ctx, factory, out, battery, consistency)

        if reference_fp is None:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.PARTIAL,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        "no trusted reference model was available for behavioural "
                        "comparison; only reference-free metamorphic consistency "
                        "was measured"
                    ),
                    assumptions=(
                        "the battery's perturbations preserve the semantic content "
                        "of their source probes",
                    ),
                    limitations=(
                        "without a reference, a model's behaviour can be described "
                        "but not compared. Behavioural *deviation* is not assessed",
                    ),
                )
            )
            return out

        comparison = compare_fingerprints(supplied_fp, reference_fp, battery)
        ctx.shared["behaviour_comparison"] = comparison
        out.stats["comparison"] = comparison

        if not comparison.get("comparable", False):
            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=ctx.model_asset(),
                    category=Category.MODEL,
                    title="Supplied model does not share the reference's output space",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    basis=ConfidenceBasis.DETERMINISTIC,
                    coverage=Coverage.SUPPORTED,
                    discriminator=("incomparable", str(comparison.get("reason"))[:80]),
                    evidence=[
                        EvidenceItem(
                            kind="incomparable_output_space",
                            statement=str(comparison.get("reason")),
                            observation=dict(comparison),
                            refs=(str(ctx.supplied.path),),
                        )
                    ],
                    assumptions=(),
                    limitations=(
                        "a different output dimensionality is conclusive evidence "
                        "that the artifacts are different models. It is not "
                        "evidence about which one is correct",
                    ),
                )
            )
            out.flagged.setdefault(ATTACK_CLASS, set()).add(ctx.supplied_manifest.model_id)
            out.scores.setdefault(ATTACK_CLASS, {})[ctx.supplied_manifest.model_id] = 1.0
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                )
            )
            return out

        self._divergence_finding(ctx, factory, out, battery, comparison)
        if not any(e.attack_class == ATTACK_CLASS for e in out.coverage):
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=(
                        "the reference model is the behaviour that was assured",
                        f"the assessment is scoped to the {len(battery)} probes of "
                        f"battery {battery.version} (digest {battery.digest[:12]}…)",
                    ),
                    limitations=(
                        "behavioural agreement is a statement about the battery, "
                        "not about all possible inputs. Two models that agree on "
                        "every probe may differ elsewhere",
                    ),
                )
            )
        return out

    # ------------------------------------------------------------------

    def _metamorphic_finding(self, ctx, factory, out, battery, consistency) -> None:
        value = consistency.get("consistency")
        if value is None or value >= ctx.config.model.behaviour.consistency_floor:
            return
        score = float(1.0 - value)
        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title="Model predictions are unstable under semantics-preserving change",
                severity=Severity.MEDIUM,
                score=score,
                prior=BEHAVIOUR_PRIOR,
                coverage=Coverage.PARTIAL,
                discriminator=("metamorphic", battery.digest),
                evidence=[
                    EvidenceItem(
                        kind="metamorphic_consistency",
                        statement=(
                            f"{consistency['flips']} of {consistency['n_pairs']} "
                            "semantics-preserving transformations changed the "
                            f"prediction (consistency {value:.3f})."
                        ),
                        observation={**consistency, "battery_digest": battery.digest,
                                     "battery_version": battery.version},
                        refs=(str(ctx.supplied.path),),
                    )
                ],
                assumptions=(
                    "the battery's transformations — brightness, contrast, noise, "
                    "JPEG re-encoding, small translation and crop — preserve the "
                    "semantic content of their source images",
                ),
                limitations=(
                    "instability is a robustness property, not evidence of "
                    "tampering. A legitimately brittle model produces this "
                    "observation, and so does one operating near its decision "
                    "boundaries",
                    "measured over the battery's transformation set only",
                ),
            )
        )
        out.flagged.setdefault(ATTACK_CLASS, set()).add(ctx.supplied_manifest.model_id)
        out.scores.setdefault(ATTACK_CLASS, {})[ctx.supplied_manifest.model_id] = score

    def _divergence_finding(self, ctx, factory, out, battery, comparison) -> None:
        overall = comparison["overall"]
        agreement = overall["prediction_agreement"]["agreement"]
        divergence = overall["distribution_divergence"]
        shift = overall["confidence_shift"]

        if agreement is None or agreement >= ctx.config.model.behaviour.agreement_floor:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=(
                        f"scoped to the {len(battery)} probes of battery "
                        f"{battery.version} (digest {battery.digest[:12]}…)",
                    ),
                    limitations=(
                        "agreement on the battery does not imply agreement on all "
                        "inputs",
                    ),
                )
            )
            return

        disagreement = 1.0 - float(agreement)
        # Severity scales with how far behaviour moved, because "0.3% of probes
        # disagree" and "40% disagree" are different operational situations and
        # a single severity for both would be useless to an analyst.
        severity = (
            Severity.HIGH if disagreement > 0.20
            else Severity.MEDIUM if disagreement > 0.05
            else Severity.LOW
        )
        by_category = {
            name: {
                "agreement": entry["prediction_agreement"]["agreement"],
                "mean_js": entry["distribution_divergence"]["mean_js"],
                "mean_confidence_shift": entry["confidence_shift"]["mean_shift"],
                "n": entry["prediction_agreement"]["n"],
            }
            for name, entry in comparison["by_category"].items()
        }

        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title="Model behaviour deviates from the trusted reference",
                severity=severity,
                score=min(1.0, disagreement * 2.0),
                prior=BEHAVIOUR_PRIOR,
                coverage=Coverage.SUPPORTED,
                discriminator=("behaviour", battery.digest,
                               str(ctx.reference_manifest.file_sha256)),
                evidence=[
                    EvidenceItem(
                        kind="prediction_agreement",
                        statement=(
                            f"The supplied and reference models choose a different "
                            f"class on {overall['prediction_agreement']['disagreements']} "
                            f"of {overall['prediction_agreement']['n']} probes "
                            f"(agreement {agreement:.3f})."
                        ),
                        observation={
                            **overall["prediction_agreement"],
                            "battery_digest": battery.digest,
                            "battery_version": battery.version,
                        },
                        refs=(str(ctx.supplied.path),),
                    ),
                    EvidenceItem(
                        kind="distribution_divergence",
                        statement=(
                            f"Mean Jensen–Shannon divergence between the two output "
                            f"distributions is {divergence['mean_js']:.4f} bits "
                            f"(bounded in [0, 1]); the 95th percentile is "
                            f"{divergence['p95_js']:.4f}."
                        ),
                        observation=divergence,
                        refs=(),
                    ),
                    EvidenceItem(
                        kind="confidence_shift",
                        statement=(
                            f"Mean top-1 confidence moved by {shift['mean_shift']:+.4f} "
                            f"({shift['reference_mean_confidence']:.4f} → "
                            f"{shift['supplied_mean_confidence']:.4f})."
                        ),
                        observation=shift,
                        refs=(),
                    ),
                    EvidenceItem(
                        kind="divergence_by_probe_category",
                        statement=(
                            "Divergence broken down by probe category: a model that "
                            "agrees on clean inputs but diverges on borderline ones "
                            "has been retrained rather than replaced, and an average "
                            "over the battery would hide that."
                        ),
                        observation=by_category,
                        refs=(),
                    ),
                ],
                assumptions=(
                    "the reference model's behaviour is the behaviour that was assured",
                    f"scoped to the {len(battery)} probes of battery "
                    f"{battery.version} (digest {battery.digest[:12]}…)",
                ),
                limitations=(
                    "behavioural deviation establishes that the models behave "
                    "differently. It does not establish which is correct, nor that "
                    "the difference is malicious: a legitimate retrain produces the "
                    "same observation",
                    "the measurement is scoped to the battery. Agreement on these "
                    "probes does not imply agreement on all inputs",
                    "Jensen-Shannon divergence is used rather than Kullback-Leibler "
                    "because KL is unbounded and undefined at zero probability, "
                    "which makes it unthresholdable at float32 softmax underflow",
                ),
            )
        )
        out.flagged.setdefault(ATTACK_CLASS, set()).add(ctx.supplied_manifest.model_id)
        out.scores.setdefault(ATTACK_CLASS, {})[ctx.supplied_manifest.model_id] = min(
            1.0, disagreement * 2.0
        )
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=(
                    f"scoped to battery {battery.version} (digest {battery.digest[:12]}…)",
                ),
                limitations=(
                    "detects behavioural difference, not malicious intent",
                ),
            )
        )
