"""Activation analysis: spectral signatures + activation clustering.

**This detector does not independently detect backdoors in this build, and the
reason is a measurement rather than caution.**

What was measured
-----------------
Both methods (Tran, Li & Madry, NeurIPS 2018; Chen et al., AAAI-19 SafeAI) were
published as *training-set* poisoning detectors: they assume the poisoned
training data is in hand and look for the poisoned subset inside it.  Module 2
does not have the supplier's training set — that is the premise — so the
implementation applies them to the **probe battery** instead, with the
trigger-probe portion standing in for the poisoned subset.

The design note said that adaptation would be weaker.  Running it across the
full model lab showed it is not merely weaker but **non-discriminating**.
Measuring the coincidence between each method's flagged set and the battery's
trigger probes, as a lift over the trigger probes' 0.447 base rate in the
battery:

======================  ====================  ====================
scenario group          spectral lift         clustering lift
======================  ====================  ====================
6 backdoored models     0.00 – 0.90           0.00 – 1.15
9 clean / non-backdoor  0.42 – 1.64           0.00 – 1.20
======================  ====================  ====================

The backdoored range sits *inside* the clean range, and the single highest lift
of any model in the lab belongs to a **clean** one (``clean_retrain_0``, 1.64).
A threshold on this statistic would have fired on a clean model and stayed
silent on a backdoored one — which is exactly what an earlier revision of this
file did before the lab was run against it.

Why it fails, mechanically
--------------------------
Two independent reasons, both structural rather than fixable by tuning:

1. **Any working classifier separates a bright corner patch from a clean
   image.** That is a visual difference and detecting it is the model's job, so
   separation carries almost no information about whether a backdoor exists.
2. **The majority/minority relationship inverts.** In the original setting the
   poisoned examples are a small minority *inside the target class*.  On a
   backdoored model here, the triggered probes are driven onto the target class
   and become its *majority*, so the minority cluster the method reports is the
   clean subset — the method flags the wrong half.

What this detector does instead
-------------------------------
It runs both analyses, records their full output as evidence, and reports
**corroborating context at INFO severity** when a backdoor signal has already
been established behaviourally by ``model_trigger``.  In that situation the
measurement is genuinely useful: it names the layer and the representation
structure carrying the behaviour, which is what an analyst needs in order to
investigate.  It is localisation, not detection, and it is labelled as such.

Its coverage is ``PARTIAL`` with the measured non-discrimination as the stated
reason, so no reader can mistake a quiet activation level for a clean one.  The
full numbers are in ``docs/model-security.md``.
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
from ..models.activations import (
    analyse_activations,
)
from ..models.base import Capability
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext, white_box_coverage

ATTACK_CLASS = "model_backdoor"

#: Minimum silhouette for a 2-means split to be described as well-separated.
#: Reported, not thresholded for detection — see the module docstring.
SILHOUETTE_FLOOR = 0.35

#: Minimum spectral separation ratio for the top singular direction to be
#: describing an outlier group rather than ordinary variance.  Reported, not
#: thresholded for detection.
SEPARATION_RATIO_FLOOR = 5.0

#: The measured non-discrimination, stated once and reused everywhere it needs
#: to appear.  Kept as a constant so the coverage entry, the finding limitation
#: and the report all quote the same numbers.
MEASURED_NON_DISCRIMINATION = (
    "MEASURED LIMITATION: applied to a probe battery rather than to a training "
    "set, neither method discriminates backdoored from clean models in this "
    "build. Across the 15-scenario model lab, trigger-coincidence lift over the "
    "0.447 base rate was 0.00-0.90 (spectral) and 0.00-1.15 (clustering) for "
    "the 6 backdoored models, against 0.42-1.64 and 0.00-1.20 for the 9 "
    "clean/non-backdoor models - the backdoored range lies inside the clean "
    "range, and the highest lift of any model belongs to a clean one. This "
    "level therefore reports corroborating context only and never raises an "
    "independent backdoor finding."
)


class ModelActivationDetector:
    """White-box representation analysis for backdoor-like structure."""

    name = "model_activation"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = (Capability.ACTIVATIONS,)

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)

        if not ctx.supplied.has(Capability.ACTIVATIONS):
            unavailable = ", ".join(ctx.supplied_manifest.unavailable_fields) or "not stated"
            reason = (
                f"activation analysis requires intermediate-tensor access, which "
                f"the '{ctx.supplied.model_format}' artifact does not provide "
                f"(access mode {ctx.access_mode.value}; unavailable: {unavailable}). "
                "Spectral-signature and activation-clustering analyses were not "
                "performed. Re-export to ONNX to enable them."
            )
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS,
                    white_box_coverage(ctx, Capability.ACTIVATIONS),
                    detector=self.name, detector_version=self.version, reason=reason,
                )
            )
            return out

        fingerprint = ctx.supplied_fingerprint()
        if fingerprint is None:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        "activation analysis is class-conditional and needs the "
                        "model's own predictions, which the behavioural detector "
                        "did not produce for this artifact"
                    ),
                )
            )
            return out

        battery = ctx.require_battery("activation analysis")
        cfg = ctx.config.model.activation
        analysis = analyse_activations(
            ctx.supplied, ctx.supplied_adapter, battery, fingerprint.predictions,
            layer=cfg.layer, epsilon=cfg.spectral_epsilon,
            min_support=cfg.min_class_support, seed=ctx.run.seed,
        )
        ctx.shared["activation_analysis"] = analysis
        out.stats = {
            "access_mode": ctx.access_mode.value,
            "layer_inspected": analysis["layer_inspected"],
            "layers_available": analysis["layers_available"][:20],
            "representation_shape": analysis["representation_shape"],
            "spectral_coincidence": analysis["spectral_trigger_coincidence"],
            "clustering_coincidence": analysis["clustering_trigger_coincidence"],
        }

        # This level never raises an independent backdoor finding: the lab
        # measurement above shows the statistic does not separate backdoored
        # from clean models. It reports corroborating context when another
        # detector has already established a behavioural backdoor signal.
        out.flagged[ATTACK_CLASS] = set()
        structure = self._describe_structure(analysis)
        out.stats["separation_structure"] = structure

        corroborates = self._behavioural_signal(ctx)
        if corroborates["backdoor_signal_present"]:
            self._emit_corroboration(
                ctx, factory, out, battery, analysis, structure, corroborates
            )
        out.coverage.append(self._coverage(ctx, analysis))
        return out

    # ------------------------------------------------------------------

    def _behavioural_signal(self, ctx: ModelAnalysisContext) -> dict[str, Any]:
        """Whether a backdoor signal already exists from behavioural evidence.

        Read from ``ctx.shared``, which ``model_behaviour`` populates earlier in
        the fixed execution order. This detector is deliberately downstream of
        that measurement: it explains an established signal rather than
        producing one.
        """
        transitions = ctx.shared.get("targeted_transition") or {}
        asr = float(transitions.get("max_attack_success_rate", 0.0) or 0.0)
        target = transitions.get("overall_dominant_target_class")
        return {
            "backdoor_signal_present": asr >= 0.50,
            "max_attack_success_rate": asr,
            "dominant_target_class": target,
            "overall_target_concentration":
                transitions.get("overall_target_concentration"),
            "source": "model_behaviour / targeted_transition",
        }

    def _describe_structure(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Summarise the separation each method found, without judging it."""
        spectral_classes = [
            {
                "class": entry["class"],
                "n": entry["n"],
                "separation_ratio": entry.get("separation_ratio"),
                "top_singular_energy_share": entry.get("top_singular_energy_share"),
                "well_separated": (
                    entry.get("separation_ratio") is not None
                    and entry["separation_ratio"] >= SEPARATION_RATIO_FLOOR
                ),
            }
            for entry in analysis["spectral_signature"]["by_class"].values()
        ]
        clustering_classes = [
            {
                "class": entry["class"],
                "n": entry["n"],
                "silhouette": entry["silhouette"],
                "minority_share": entry["minority_share"],
                "well_separated": entry["silhouette"] >= SILHOUETTE_FLOOR,
            }
            for entry in analysis["activation_clustering"]["by_class"].values()
        ]
        return {
            "layer_inspected": analysis["layer_inspected"],
            "spectral_by_class": spectral_classes,
            "clustering_by_class": clustering_classes,
            "spectral_trigger_coincidence": analysis["spectral_trigger_coincidence"],
            "clustering_trigger_coincidence": analysis["clustering_trigger_coincidence"],
            "silhouette_floor": SILHOUETTE_FLOOR,
            "separation_ratio_floor": SEPARATION_RATIO_FLOOR,
            "reported_for": "context and localisation only; not thresholded for detection",
        }

    def _emit_corroboration(
        self, ctx, factory, out, battery, analysis, structure, corroborates
    ) -> None:
        """An INFO-severity localisation finding beside an established signal.

        Severity INFO, not HIGH: the backdoor claim belongs to the detector that
        measured the behaviour. This finding adds *where* it is expressed in the
        representation, which is what an analyst needs to investigate, and adds
        no independent weight to whether it exists.
        """
        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title=(
                    "Representation context for the observed backdoor signal "
                    "(localisation, not independent detection)"
                ),
                severity=Severity.INFO,
                # DETERMINISTIC because every number quoted is a measured
                # statistic of the captured representations, and the finding
                # makes no inferential claim beyond reporting them.
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                coverage=Coverage.PARTIAL,
                discriminator=("activation_context", analysis["layer_inspected"]),
                evidence=[
                    EvidenceItem(
                        kind="behavioural_signal_being_explained",
                        statement=(
                            "A targeted behavioural transition was already measured "
                            f"(attack success rate {corroborates['max_attack_success_rate']:.3f} "
                            f"onto class {corroborates['dominant_target_class']}). "
                            "The representation measurements below describe where "
                            "that behaviour is expressed; they are not independent "
                            "evidence that it exists."
                        ),
                        observation=corroborates,
                        refs=(),
                    ),
                    EvidenceItem(
                        kind="activation_spectral_signature",
                        statement=(
                            "Spectral-signature analysis of the inspected layer, "
                            "per predicted class."
                        ),
                        observation={
                            "method": analysis["spectral_signature"]["method"],
                            "origin": analysis["spectral_signature"]["origin"],
                            "epsilon": analysis["spectral_signature"]["epsilon"],
                            "by_class": analysis["spectral_signature"]["by_class"],
                            "skipped_classes_low_support":
                                analysis["spectral_signature"]["skipped_classes_low_support"],
                            "trigger_coincidence": analysis["spectral_trigger_coincidence"],
                            "adaptation": analysis["spectral_signature"]["adaptation"],
                        },
                        refs=(str(ctx.supplied.path),),
                    ),
                    EvidenceItem(
                        kind="activation_clustering",
                        statement=(
                            "Activation-clustering analysis of the inspected layer, "
                            "per predicted class."
                        ),
                        observation={
                            "method": analysis["activation_clustering"]["method"],
                            "origin": analysis["activation_clustering"]["origin"],
                            "by_class": analysis["activation_clustering"]["by_class"],
                            "skipped_classes_low_support":
                                analysis["activation_clustering"]["skipped_classes_low_support"],
                            "trigger_coincidence": analysis["clustering_trigger_coincidence"],
                            "dimensionality_reduction":
                                analysis["activation_clustering"]["dimensionality_reduction"],
                            "adaptation": analysis["activation_clustering"]["adaptation"],
                        },
                        refs=(),
                    ),
                    EvidenceItem(
                        kind="separation_structure",
                        statement=(
                            f"Representation separation per class at layer "
                            f"'{analysis['layer_inspected']}', reported for context "
                            "and not thresholded for detection."
                        ),
                        observation=structure,
                        refs=(),
                    ),
                ],
                assumptions=(
                    "the inspected layer is the penultimate representation, which "
                    "is the layer both source methods operate on",
                    f"scoped to battery {battery.version} (digest {battery.digest[:12]}…)",
                ),
                limitations=(
                    MEASURED_NON_DISCRIMINATION,
                    "both methods were published as training-set poisoning "
                    "detectors and are applied here to a probe battery instead; "
                    "they say nothing about whether the supplier's training data "
                    "was poisoned",
                    "this finding is localisation, not detection: it adds no "
                    "independent weight to whether a backdoor exists",
                ),
            )
        )

    def _coverage(self, ctx, analysis):
        return coverage_entry(
            ATTACK_CLASS, Coverage.PARTIAL,
            detector=self.name, detector_version=self.version,
            reason=(
                "activation analysis ran and its measurements are recorded, but it "
                "does not contribute an independent backdoor decision in this "
                "build. " + MEASURED_NON_DISCRIMINATION
            ),
            assumptions=(
                f"white-box activation access; layer inspected: "
                f"{analysis['layer_inspected']}",
            ),
            limitations=(
                MEASURED_NON_DISCRIMINATION,
                "spectral signatures and activation clustering are applied to the "
                "probe battery rather than to the training set they were published "
                "for; the claim is correspondingly weaker",
                "adaptive backdoors trained to suppress the spectral signature are "
                "documented in the literature and are not detected",
            ),
        )
