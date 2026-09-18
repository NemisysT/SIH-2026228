"""Trigger detector: reconstruction where gradients exist, family probing where they do not.

Runs whichever mechanism the artifact's capabilities actually permit, and — this
is the part that matters — **says which one it ran**, in the finding's title, in
its method version, in its evidence and in its coverage entry.

* ``gradients`` available → Neural Cleanse reconstruction (Wang et al., S&P
  2019). Coverage ``SUPPORTED`` for the universal-patch trigger family.
* ``inference`` only → gradient-free sweep of the declared patch family.
  Coverage ``PARTIAL``, because a sweep finds only what is in the family.

Both mechanisms run when both are possible: they are independent, and Neural
Cleanse finding a small-norm trigger for a class that the family probe *also*
drives predictions onto is much stronger evidence than either alone.

The one thing this detector will not do is describe a gradient-free sweep as
reconstruction.  ``method_version`` encodes the mechanism, so even a downstream
consumer reading only the JSON can tell them apart.
"""

from __future__ import annotations

from typing import Any

from ..core.evidence import Category, Coverage, EvidenceItem, Severity
from ..models.base import Capability
from ..models.trigger import (
    ANOMALY_INDEX_THRESHOLD,
    probe_trigger_family,
    reconstruct_triggers,
)
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext

ATTACK_CLASS = "model_backdoor"

#: Attack success rate at which a swept patch is treated as a high-risk
#: indicator.
#:
#: Measured across the 15-scenario model lab: non-backdoor models score
#: 0.000–0.333, and backdoors whose trigger family the probe actually sweeps
#: score 0.667–0.833.  0.50 sits in the empty region between those regimes —
#: with margin on both sides, which is what makes it a measured operating point
#: rather than a tuned constant.
#:
#: The one backdoor below it (0.292) is `backdoor_blended_faint`, an opacity-0.08
#: blended trigger deliberately constructed to sit OUTSIDE the declared
#: full-opacity family. Lowering this threshold to catch it would not be a fix:
#: it would put the threshold under `substitution_architecture` at 0.333 and
#: start manufacturing backdoor findings on models that have none. The honest
#: answer to an out-of-family trigger is declared coverage, not a looser
#: threshold. Full table in docs/model-security.md §5.
ASR_FLOOR = 0.50

#: Share of trigger-induced flips that must land on one class before the
#: behaviour is called *targeted* rather than merely unstable.
CONCENTRATION_FLOOR = 0.70

TRIGGER_PRIOR = 0.50


class ModelTriggerDetector:
    """Trigger reconstruction and/or trigger-family probing."""

    name = "model_trigger"
    #: Base version. The emitted ``method_version`` appends the mechanism that
    #: actually ran, so a reconstruction finding and a probe finding can never be
    #: confused for one another in the JSON.
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = (Capability.INFERENCE,)

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        out = DetectorOutput(detector=self.name, version=self.version)

        if not ctx.supplied.has(Capability.INFERENCE):
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=(
                        f"trigger assessment requires a forward pass, which the "
                        f"'{ctx.supplied.model_format}' artifact does not support"
                    ),
                )
            )
            return out

        battery = ctx.require_battery("trigger assessment")
        cfg = ctx.config.model.trigger
        fingerprint = ctx.supplied_fingerprint()
        n_classes = fingerprint.n_classes if fingerprint else len(battery.classes)

        probe: dict[str, Any] | None = None
        reconstruction: dict[str, Any] | None = None
        notes: list[str] = []

        # -- gradient-free family probe: always available with inference ----
        if cfg.enable_family_probe:
            probe = probe_trigger_family(
                ctx.supplied, ctx.supplied_adapter, battery,
                opacities=tuple(cfg.probe_opacities),
            )
            ctx.shared["trigger_probe"] = probe

        # -- Neural Cleanse: gradients only ---------------------------------
        if cfg.enable_reconstruction:
            if ctx.supplied.has(Capability.GRADIENTS):
                reconstruction = reconstruct_triggers(
                    ctx.supplied, ctx.supplied_adapter, battery,
                    n_classes=n_classes, seed=ctx.run.seed,
                    steps=cfg.steps, learning_rate=cfg.learning_rate,
                    mask_penalty=cfg.mask_penalty,
                    success_threshold=cfg.success_threshold,
                )
                ctx.shared["trigger_reconstruction"] = reconstruction
            else:
                notes.append(
                    f"Neural Cleanse trigger RECONSTRUCTION was NOT performed: the "
                    f"'{ctx.supplied.model_format}' artifact provides no input "
                    f"gradients (access mode {ctx.access_mode.value}). "
                    "A gradient-free sweep of the declared patch family was used "
                    "instead; it is a weaker mechanism and is reported as such. "
                    "Supply a PyTorch or TorchScript artifact for reconstruction."
                )

        out.stats = {
            "access_mode": ctx.access_mode.value,
            "reconstruction_performed": reconstruction is not None,
            "family_probe_performed": probe is not None,
            "battery_digest": battery.digest,
            "notes": notes,
        }
        if probe:
            out.stats["probe_max_asr"] = probe["max_attack_success_rate"]
        if reconstruction:
            out.stats["reconstruction_max_anomaly_index"] = reconstruction["max_anomaly_index"]
            out.stats["reconstruction_flagged_classes"] = reconstruction["flagged_classes"]

        self._emit(ctx, out, battery, probe, reconstruction, notes)
        return out

    # ------------------------------------------------------------------

    def _emit(self, ctx, out, battery, probe, reconstruction, notes) -> None:
        mechanism = (
            "reconstruction+probe" if (reconstruction and probe)
            else "reconstruction" if reconstruction
            else "probe" if probe
            else "none"
        )
        method_version = f"{self.version}+{mechanism}"
        factory = FindingFactory(ctx, self.name, method_version)

        if mechanism == "none":
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=method_version,
                    reason="both trigger mechanisms are disabled in configuration",
                )
            )
            return

        probe_hit = self._probe_hit(probe)
        reconstruction_hit = bool(reconstruction and reconstruction["flagged_classes"])

        # Reconstruction only upgrades coverage to SUPPORTED when its anomaly
        # index is actually interpretable for this model. On a model with too
        # few classes the optimisation still runs and its ranking is still
        # reported, but it cannot support a threshold decision, so the coverage
        # stays PARTIAL and says why.
        reconstruction_decisive = bool(
            reconstruction and reconstruction.get("anomaly_index_interpretable")
        )
        coverage = Coverage.SUPPORTED if reconstruction_decisive else Coverage.PARTIAL
        if reconstruction and not reconstruction_decisive:
            notes.append(str(reconstruction["anomaly_index_uninterpretable_reason"]))
        out.coverage.append(self._coverage(ctx, coverage, method_version, notes, battery))

        if not probe_hit and not reconstruction_hit:
            out.flagged[ATTACK_CLASS] = set()
            if probe:
                out.scores[ATTACK_CLASS] = {
                    ctx.supplied_manifest.model_id: float(probe["max_attack_success_rate"])
                }
            return

        evidence: list[EvidenceItem] = []
        score = 0.0

        if probe:
            best = probe["best_trigger"] or {}
            evidence.append(
                EvidenceItem(
                    kind="trigger_family_probe",
                    statement=(
                        f"Sweeping the declared patch family, the strongest member "
                        f"drives {best.get('attack_success_rate', 0):.1%} of clean "
                        f"probes onto class {best.get('dominant_target_class')} "
                        f"(target concentration {best.get('target_concentration', 0):.1%})."
                    ),
                    observation={
                        "method": probe["method"],
                        "origin": probe["origin"],
                        "access_mode": probe["access_mode"],
                        "capability_used": probe["capability_used"],
                        "family": probe["family"],
                        "opacities": probe["opacities"],
                        "clean_probes": probe["clean_probes"],
                        "per_trigger": probe["per_trigger"],
                        "best_trigger": best,
                        "max_attack_success_rate": probe["max_attack_success_rate"],
                        "asr_floor": ASR_FLOOR,
                        "concentration_floor": CONCENTRATION_FLOOR,
                        "coverage_note": probe["coverage_note"],
                    },
                    refs=(str(ctx.supplied.path),),
                )
            )
            if probe_hit:
                score = max(score, float(best.get("attack_success_rate", 0.0)))

        if reconstruction:
            flagged = reconstruction["flagged_classes"]
            evidence.append(
                EvidenceItem(
                    kind="neural_cleanse_reconstruction",
                    statement=(
                        f"Neural Cleanse optimised a universal trigger per class. "
                        f"The smallest reconstructed mask belongs to class "
                        f"{reconstruction['smallest_mask_class']} "
                        f"(L1 {reconstruction['smallest_mask_l1']:.1f}, "
                        f"{reconstruction['mask_l1_ratio_to_next']}× smaller than the "
                        f"next). "
                        + (
                            f"Anomaly index peaked at "
                            f"{reconstruction['max_anomaly_index']:.2f} against a "
                            f"threshold of {ANOMALY_INDEX_THRESHOLD}; "
                            + (f"class(es) {flagged} are outliers."
                               if flagged
                               else "no class met both the outlier and success criteria.")
                            if reconstruction["anomaly_index_interpretable"]
                            else "The anomaly index is NOT interpretable for this "
                                 "model and was not thresholded; see the reason in "
                                 "the observation."
                        )
                    ),
                    observation={
                        "method": reconstruction["method"],
                        "origin": reconstruction["origin"],
                        "access_mode": reconstruction["access_mode"],
                        "capability_used": reconstruction["capability_used"],
                        "budget": reconstruction["budget"],
                        "per_class": reconstruction["per_class"],
                        "smallest_mask_class": reconstruction["smallest_mask_class"],
                        "smallest_mask_l1": reconstruction["smallest_mask_l1"],
                        "mask_l1_ratio_to_next": reconstruction["mask_l1_ratio_to_next"],
                        "median_mask_l1": reconstruction["median_mask_l1"],
                        "mad_mask_l1": reconstruction["mad_mask_l1"],
                        "anomaly_index_threshold": ANOMALY_INDEX_THRESHOLD,
                        "anomaly_index_interpretable":
                            reconstruction["anomaly_index_interpretable"],
                        "anomaly_index_uninterpretable_reason":
                            reconstruction["anomaly_index_uninterpretable_reason"],
                        "success_threshold": reconstruction["success_threshold"],
                        "flagged_classes": flagged,
                        "coverage_note": reconstruction["coverage_note"],
                        "measured_limit": reconstruction["measured_limit"],
                    },
                    refs=(),
                )
            )
            if reconstruction_hit:
                score = max(score, min(1.0, float(reconstruction["max_anomaly_index"]) / 6.0))

        # Independent agreement between the two mechanisms is the strongest
        # evidence this detector can produce, so it is stated explicitly rather
        # than left for the reader to notice.
        both_agree = bool(
            probe_hit and reconstruction_hit
            and probe and reconstruction
            and (probe["best_trigger"] or {}).get("dominant_target_class")
            in reconstruction["flagged_classes"]
        )
        if both_agree:
            score = min(1.0, score + 0.15)
        evidence.append(
            EvidenceItem(
                kind="mechanism_agreement",
                statement=(
                    "Both mechanisms implicate the same target class."
                    if both_agree else
                    "The two mechanisms do not agree on a target class, or only one "
                    "of them ran; the weaker reading applies."
                ),
                observation={
                    "mechanism": mechanism,
                    "reconstruction_performed": reconstruction is not None,
                    "family_probe_performed": probe is not None,
                    "probe_target_class": (
                        (probe["best_trigger"] or {}).get("dominant_target_class")
                        if probe else None
                    ),
                    "reconstruction_flagged_classes": (
                        reconstruction["flagged_classes"] if reconstruction else None
                    ),
                    "independent_agreement": both_agree,
                    "notes": notes,
                },
                refs=(),
            )
        )

        # The title names the mechanism that actually produced the hit, so a
        # gradient-free sweep can never be read as reconstruction.
        title = (
            "HIGH-RISK INDICATOR: reconstructed trigger drives targeted misclassification"
            if reconstruction_hit else
            "HIGH-RISK INDICATOR: a declared patch trigger drives targeted misclassification"
        )

        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title=title,
                # HIGH because a backdoor is consequential if real. Confidence is
                # resolved separately from the calibration table, and the two are
                # never multiplied together.
                severity=Severity.HIGH,
                score=score,
                prior=TRIGGER_PRIOR,
                coverage=coverage,
                discriminator=(mechanism, battery.digest),
                evidence=evidence,
                assumptions=self._assumptions(ctx, battery, reconstruction),
                limitations=self._limitations(reconstruction, notes),
            )
        )
        out.flagged[ATTACK_CLASS] = {ctx.supplied_manifest.model_id}
        out.scores[ATTACK_CLASS] = {ctx.supplied_manifest.model_id: score}

    def _probe_hit(self, probe: dict[str, Any] | None) -> bool:
        if not probe:
            return False
        best = probe.get("best_trigger") or {}
        return (
            float(best.get("attack_success_rate", 0.0)) >= ASR_FLOOR
            and float(best.get("target_concentration", 0.0)) >= CONCENTRATION_FLOOR
        )

    def _assumptions(self, ctx, battery, reconstruction) -> tuple[str, ...]:
        common = (
            f"scoped to battery {battery.version} (digest {battery.digest[:12]}…) "
            f"and its declared patch trigger family of {len(battery.trigger_family)} "
            "members",
            "the model's class indices are stable between probes",
        )
        if reconstruction:
            budget = reconstruction["budget"]
            return common + (
                f"the trigger search budget was {budget['steps']} optimisation steps "
                f"per class over {len(budget['target_classes_tested'])} target "
                f"class(es) and {budget['clean_probes']} clean probes; a negative "
                "result under a small budget is a weaker statement than one under a "
                "large budget",
                "the optimisation looks for ONE universal mask that works for every "
                "input — which is what makes it blind to sample-specific triggers",
            )
        return common

    def _limitations(self, reconstruction, notes) -> tuple[str, ...]:
        base = [
            "a successful trigger search is evidence of suspicious behaviour, not "
            "proof of a malicious backdoor. Neural Cleanse's own evaluation reports "
            "false positives on clean models whose classes are close in input space",
            "NOT covered, and not claimed: sample-specific / input-aware triggers, "
            "semantic backdoors, triggers large by design, and adaptive backdoors "
            "trained to keep the reconstructed mask norm inside the clean range",
        ]
        if reconstruction is None:
            base.insert(
                0,
                "trigger RECONSTRUCTION was not performed; this result comes from a "
                "gradient-free sweep of a finite, declared patch family and finds a "
                "trigger only if the trigger is in that family",
            )
        elif not reconstruction.get("anomaly_index_interpretable"):
            base.insert(
                0,
                "trigger reconstruction ran but its anomaly index is not "
                "interpretable for a model with this few classes, so it could not "
                "contribute a threshold decision. Its per-class mask ranking is "
                "reported as evidence; the decisive signal here is the "
                "trigger-family probe",
            )
        base.extend(notes)
        return tuple(base)

    def _coverage(self, ctx, coverage, method_version, notes, battery):
        reason = None
        if coverage is Coverage.PARTIAL:
            reason = (
                "gradient-free trigger-family probing only: this artifact provides "
                "no input gradients, so trigger reconstruction was not performed. "
                "Coverage is bounded by the declared patch family."
            )
        return coverage_entry(
            ATTACK_CLASS, coverage,
            detector=self.name, detector_version=method_version, reason=reason,
            assumptions=(
                f"scoped to battery {battery.version} and its {len(battery.trigger_family)}-member "
                "declared patch trigger family",
            ),
            limitations=tuple(
                [
                    "universal patch triggers only",
                    "sample-specific, semantic, distributed and adaptive triggers "
                    "are NOT assessed",
                ]
                + notes
            ),
        )
