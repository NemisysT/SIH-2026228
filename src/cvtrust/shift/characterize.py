"""The shift characteriser: five metrics, one verdict vocabulary, no score.

The output of this module is deliberately *not* a shift score.  It is a
:class:`ShiftAssessment` carrying every metric's own result, its own sample
sufficiency, and a verdict drawn from a closed vocabulary — the same discipline
Module 2 applies to its assessment matrix (ADR-012) and for the same reason: an
analyst who is told "shift = 0.62" cannot act, and an analyst who is told

::

    Joint distribution:  SHIFT_DETECTED (permutation p = 0.001)
    Centre:              moved 1.8 reference SD, 71% in the acquisition view
    Spread:              NOT_ASSESSED (current population too small)
    Marginals:           mean_luminance PSI 0.44, noise_floor PSI 0.31
    Class mix:           stable (JS 0.004 bits)
    Declared context:    illumination low -> consistent

can.

The verdict vocabulary excludes every word that would import an intent.  There
is no ``ATTACK``, no ``MALICIOUS`` and no ``SUSPICIOUS`` value, because nothing
this module measures can distinguish a hostile change from a Tuesday in
November.  The strongest thing it can say on its own is
``SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT``, which is an open question routed to
an analyst, and the fusion engine in :mod:`cvtrust.assurance` is the only place
where that observation may be combined with independent integrity evidence.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from ..core.config import ShiftConfig
from ..core.context import RunContext
from ..core.hashing import sha256_canonical, short
from .context import (
    ContextAssessment,
    ContextExplanation,
    OperationalContext,
    explain_shift,
)
from .metrics import (
    METRIC_VERSION,
    MetricResult,
    MetricStatus,
    categorical_shift,
    covariance_shift,
    energy_distance_test,
    marginal_psi,
    mean_shift,
)
from .reference import PopulationView, ReferencePopulation

CHARACTERIZER_VERSION = "1.0"


class ShiftVerdict(str, Enum):
    """The closed vocabulary for a population-shift outcome.

    Note what is absent, permanently: any value implying intent, and any value
    implying safety.  ``NO_SHIFT_DETECTED`` is a statement about the tests that
    ran at the sample sizes available, not a statement that the population is
    stable.
    """

    #: The omnibus test ran and resolved no difference at the configured alpha.
    NO_SHIFT_DETECTED = "NO_SHIFT_DETECTED"
    #: Shift detected, and confined to the views a declared operational change
    #: would move.  Consistent with declared operational drift.
    SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT = "SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT"
    #: Shift detected; a declaration exists and accounts for part of it.
    SHIFT_PARTIALLY_EXPLAINED = "SHIFT_PARTIALLY_EXPLAINED"
    #: Shift detected and the declared context does not account for it, or the
    #: declaration says nothing changed while the population did.
    SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT = "SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT"
    #: Shift detected and nothing was declared, so no adjudication is possible.
    SHIFT_DETECTED_NO_CONTEXT = "SHIFT_DETECTED_NO_CONTEXT"
    #: The populations were too small to support any claim either way.
    INSUFFICIENT_SAMPLE = "INSUFFICIENT_SAMPLE"
    #: No reference population, or no usable feature space. Never "clean".
    NOT_ASSESSED = "NOT_ASSESSED"


#: Verdicts in which a shift was actually observed.  Used by the policy engine,
#: which must never treat "not assessed" as "no shift".
SHIFT_OBSERVED_VERDICTS: frozenset[ShiftVerdict] = frozenset(
    {
        ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT,
        ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED,
        ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT,
        ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT,
    }
)

#: Verdicts that mean the question was not answered.
SHIFT_UNRESOLVED_VERDICTS: frozenset[ShiftVerdict] = frozenset(
    {ShiftVerdict.INSUFFICIENT_SAMPLE, ShiftVerdict.NOT_ASSESSED}
)


class ShiftAssessment(BaseModel):
    """Everything the shift analysis observed, and everything it could not."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    version: str = CHARACTERIZER_VERSION
    metric_version: str = METRIC_VERSION
    verdict: ShiftVerdict
    statement: str

    reference: dict[str, Any]
    current: dict[str, Any]

    metrics: list[MetricResult]
    context: ContextAssessment | None = None
    declared_context: dict[str, Any] = Field(default_factory=dict)

    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    unassessed: list[dict[str, str]] = Field(
        default_factory=list,
        description="Metrics that produced no answer, with the reason. A shift "
        "analysis missing half its metrics is not a shift analysis that found "
        "nothing.",
    )

    def metric(self, name: str) -> MetricResult | None:
        for result in self.metrics:
            if result.metric == name:
                return result
        return None

    def shift_observed(self) -> bool:
        return self.verdict in SHIFT_OBSERVED_VERDICTS

    def resolved(self) -> bool:
        """Did the analysis answer the question at all?"""
        return self.verdict not in SHIFT_UNRESOLVED_VERDICTS

    def block_shares(self) -> dict[str, float]:
        centre = self.metric("mean_shift")
        if centre is None or not centre.assessed():
            return {}
        return {
            name: float(detail["share_of_squared_displacement"])
            for name, detail in centre.observation.get("block_contributions", {}).items()
        }


_ASSUMPTIONS: tuple[str, ...] = (
    "the reference population is representative of the intended operating "
    "distribution and has not itself been contaminated; nothing in this "
    "analysis establishes either",
    "both populations were embedded by the same feature extractor at the same "
    "version, which the reference digest binds",
    "samples within a population are treated as exchangeable; a population "
    "containing near-duplicate floods violates that and will understate its own "
    "diversity",
)

_LIMITATIONS: tuple[str, ...] = (
    "a distribution shift is not an attack. Terrain, season, sensor, "
    "illumination and collection-protocol changes are the normal condition of "
    "an operational pipeline and produce exactly this signature",
    "this analysis cannot establish what caused a shift. It can establish that "
    "one was observed, where in the feature space it lives, and whether a "
    "declared operational change would predict it",
    "an adversary who matches the reference population's low-level statistics "
    "is not detected by any metric here",
    "a negative result bounds the shift these tests could resolve at the sample "
    "sizes available; it does not establish that the population is stable",
    "the feature space is a deterministic classical descriptor chosen for "
    "air-gapped operation (ADR-005). A task-trained embedding would be more "
    "sensitive to semantic change and less sensitive to acquisition change, "
    "which would move, not remove, this limitation",
)


class ShiftCharacterizer:
    """Runs the metric battery and resolves a verdict from it."""

    name = "distribution_shift"
    version = CHARACTERIZER_VERSION

    def __init__(self, cfg: ShiftConfig) -> None:
        self.cfg = cfg

    def run(
        self,
        *,
        reference_view: PopulationView,
        current_view: PopulationView,
        reference: ReferencePopulation,
        run: RunContext,
        reference_context: OperationalContext | None = None,
        current_context: OperationalContext | None = None,
        current_descriptor: dict[str, Any] | None = None,
    ) -> ShiftAssessment:
        cfg = self.cfg
        rng = run.rng("shift")
        reference_context = reference_context or OperationalContext()
        current_context = current_context or OperationalContext()

        metrics: list[MetricResult] = []

        # 1. The omnibus test first: everything downstream is conditioned on
        #    whether a difference was resolved at all.
        energy = energy_distance_test(
            np.asarray(reference_view.embeddings, dtype=np.float64),
            np.asarray(current_view.embeddings, dtype=np.float64),
            rng=rng,
            permutations=cfg.permutations,
            alpha=cfg.alpha,
            min_per_side=min(cfg.min_reference_samples, cfg.min_current_samples),
            max_per_side=cfg.max_samples_per_side,
        )
        # The per-side floors are asymmetric in configuration but the test takes
        # one number, so the asymmetry is enforced here and reported.
        energy = self._apply_asymmetric_floor(energy, reference_view, current_view)
        metrics.append(energy)

        # 2. Characterisation of the movement, whether or not it was resolved:
        #    an unresolved test with a visibly displaced centre is exactly the
        #    situation where an analyst needs to see the magnitude.
        centre = mean_shift(
            np.asarray(reference_view.embeddings, dtype=np.float64),
            np.asarray(current_view.embeddings, dtype=np.float64),
            blocks=self._blocks(reference),
            min_per_side=8,
        )
        metrics.append(centre)

        metrics.append(
            covariance_shift(
                np.asarray(reference_view.embeddings, dtype=np.float64),
                np.asarray(current_view.embeddings, dtype=np.float64),
                rng=rng,
                components=cfg.covariance_components,
                samples_per_component=cfg.covariance_samples_per_component,
                permutations=cfg.supporting_permutations,
                alpha=cfg.alpha,
            )
        )

        metrics.append(
            marginal_psi(
                np.asarray(reference_view.acquisition, dtype=np.float64),
                np.asarray(current_view.acquisition, dtype=np.float64),
                names=reference_view.acquisition_names,
                rng=rng,
                bins=cfg.psi_bins,
                min_per_bin=cfg.psi_min_samples_per_bin,
                permutations=cfg.supporting_permutations,
                max_permutations=cfg.max_supporting_permutations,
                alpha=cfg.alpha,
                reporting_band=cfg.psi_reporting_band,
            )
        )

        metrics.append(
            categorical_shift(
                reference_view.class_counts,
                current_view.class_counts,
                label="class",
                rng=rng,
                min_per_side=min(cfg.min_reference_samples, cfg.min_current_samples),
                permutations=cfg.supporting_permutations,
                alpha=cfg.alpha,
            )
        )

        for key in sorted(
            set(reference_view.metadata_counts) | set(current_view.metadata_counts)
        ):
            metrics.append(
                categorical_shift(
                    reference_view.metadata_counts.get(key, {}),
                    current_view.metadata_counts.get(key, {}),
                    label=f"metadata.{key}",
                    rng=rng,
                    min_per_side=min(
                        cfg.min_reference_samples, cfg.min_current_samples
                    ),
                    permutations=cfg.supporting_permutations,
                    alpha=cfg.alpha,
                )
            )

        verdict, context, statement = self._resolve(
            energy=energy,
            metrics=metrics,
            centre=centre,
            reference_context=reference_context,
            current_context=current_context,
        )

        payload = {
            "verdict": verdict.value,
            "reference_digest": reference.digest,
            "metrics": [
                {
                    "metric": m.metric,
                    "status": m.status.value,
                    "statistic": m.statistic,
                    "significant": m.significant,
                }
                for m in metrics
            ],
        }
        return ShiftAssessment(
            assessment_id=f"S-{short(sha256_canonical(_digest_safe(payload)), 12)}",
            verdict=verdict,
            statement=statement,
            reference=reference.describe(),
            current=(current_descriptor or {})
            | {
                "sample_count": current_view.size,
                "classes": dict(sorted(current_view.class_counts.items())),
                "contributors": dict(sorted(current_view.contributor_counts.items())),
            },
            metrics=metrics,
            context=context,
            declared_context={
                "reference": reference_context.model_dump(mode="json"),
                "current": current_context.model_dump(mode="json"),
                "validated": False,
                "note": "declared context is a claim by the supplying side. It is "
                "recorded, checked for consistency with the observed movement, "
                "and never treated as establishing what physically happened.",
            },
            assumptions=list(_ASSUMPTIONS) + [reference.caveat()],
            limitations=list(_LIMITATIONS)
            + list(context.limitations if context else ()),
            unassessed=[
                {
                    "metric": m.metric,
                    "status": m.status.value,
                    "reason": m.reason or "no reason recorded",
                }
                for m in metrics
                if not m.assessed()
            ],
        )

    # -- internals ------------------------------------------------------

    def _apply_asymmetric_floor(
        self,
        result: MetricResult,
        reference_view: PopulationView,
        current_view: PopulationView,
    ) -> MetricResult:
        """Enforce the separate reference and current floors.

        The realistic failure mode this guards is a five-thousand-sample
        reference and a three-sample current batch.  A single symmetric floor
        would pass that as soon as the reference cleared it, and the permutation
        test would dutifully return a valid, powerless, comfortable p-value.
        """
        cfg = self.cfg
        if result.status is not MetricStatus.ASSESSED:
            return result
        short_reference = reference_view.size < cfg.min_reference_samples
        short_current = current_view.size < cfg.min_current_samples
        if not (short_reference or short_current):
            return result
        which = []
        if short_reference:
            which.append(
                f"reference has {reference_view.size} samples, below "
                f"shift.min_reference_samples={cfg.min_reference_samples}"
            )
        if short_current:
            which.append(
                f"current has {current_view.size} samples, below "
                f"shift.min_current_samples={cfg.min_current_samples}"
            )
        return MetricResult(
            metric=result.metric,
            status=MetricStatus.INSUFFICIENT_SAMPLE,
            interpretation=(
                "Not enough data to support a claim either way. This is not a "
                "statement that the distribution is stable."
            ),
            requirement={
                **result.requirement,
                "min_reference_samples": cfg.min_reference_samples,
                "min_current_samples": cfg.min_current_samples,
            },
            reason="; ".join(which),
        )

    @staticmethod
    def _blocks(reference: ReferencePopulation) -> tuple[tuple[str, int, int], ...]:
        spans = reference.feature_space.get("block_spans") or {}
        return tuple(
            (name, int(bounds[0]), int(bounds[1]))
            for name, bounds in sorted(spans.items(), key=lambda kv: kv[1][0])
        )

    def _resolve(
        self,
        *,
        energy: MetricResult,
        metrics: list[MetricResult],
        centre: MetricResult,
        reference_context: OperationalContext,
        current_context: OperationalContext,
    ) -> tuple[ShiftVerdict, ContextAssessment | None, str]:
        assessed = [m for m in metrics if m.assessed()]
        # Sample sufficiency is checked BEFORE "no metric produced an answer",
        # and the order matters. A six-sample current population makes every
        # metric report INSUFFICIENT_SAMPLE, at which point "no metric was
        # assessed" is true but useless: it sends the analyst looking for a
        # broken input when the remedy is more data. Measured on the lab's
        # small_current_batch pair, which the original ordering reported as
        # NOT_ASSESSED.
        if energy.status is MetricStatus.INSUFFICIENT_SAMPLE:
            return (
                ShiftVerdict.INSUFFICIENT_SAMPLE,
                None,
                "The populations are too small to support a shift claim either "
                f"way ({energy.reason}). Population-level distribution shift is "
                "reported as INSUFFICIENT_SAMPLE rather than as absent.",
            )
        if energy.status is MetricStatus.NOT_ASSESSED or not assessed:
            reason = (
                energy.reason
                if energy.status is MetricStatus.NOT_ASSESSED
                else "no metric produced an answer on these populations"
            )
            return (
                ShiftVerdict.NOT_ASSESSED,
                None,
                f"The omnibus distribution test could not be applied ({reason}). "
                "Population-level distribution shift was NOT assessed; this is "
                "not a clean result.",
            )

        # The omnibus test is the gate. A supporting metric firing while the
        # omnibus test resolves nothing is reported as context, never promoted
        # into a shift verdict: those metrics carry declared operating points
        # rather than nulls, and letting one of them override a test that has a
        # null would be trading a calibrated decision for an uncalibrated one.
        supporting_fired = sorted(
            m.metric for m in metrics if m.fired() and m.metric != "energy_distance"
        )
        if not energy.fired():
            note = (
                f" Supporting metrics did report movement ({', '.join(supporting_fired)}), "
                "which is recorded as context: those metrics carry declared "
                "operating points rather than null distributions, so they do not "
                "override the omnibus test."
                if supporting_fired
                else ""
            )
            return (
                ShiftVerdict.NO_SHIFT_DETECTED,
                explain_shift(
                    reference_context=reference_context,
                    current_context=current_context,
                    block_shares={},
                    shift_detected=False,
                    moved_block_share=self.cfg.moved_block_share,
                ),
                f"No population-level distribution shift was resolved at alpha "
                f"{self.cfg.alpha:g} (permutation p = {energy.p_value:.4g}). This "
                "bounds what the test could see at these sample sizes; it does "
                "not establish that the population is stable." + note,
            )

        shares = {
            name: float(detail["share_of_squared_displacement"])
            for name, detail in (
                centre.observation.get("block_contributions", {})
                if centre.assessed()
                else {}
            ).items()
        }
        context = explain_shift(
            reference_context=reference_context,
            current_context=current_context,
            block_shares=shares,
            shift_detected=True,
            moved_block_share=self.cfg.moved_block_share,
        )
        verdict = {
            ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT: (
                ShiftVerdict.SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT
            ),
            ContextExplanation.PARTIALLY_EXPLAINED: ShiftVerdict.SHIFT_PARTIALLY_EXPLAINED,
            ContextExplanation.UNEXPLAINED: (
                ShiftVerdict.SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT
            ),
            ContextExplanation.NO_CONTEXT_DECLARED: ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT,
            ContextExplanation.NOT_APPLICABLE: ShiftVerdict.SHIFT_DETECTED_NO_CONTEXT,
        }[context.explanation]

        supporting = (
            f" Corroborated by: {', '.join(supporting_fired)}."
            if supporting_fired
            else " No supporting metric exceeded its own operating point, so the "
            "movement is resolvable but small in the quantities reported here."
        )
        return (
            verdict,
            context,
            f"A population-level distribution shift was observed "
            f"(permutation p = {energy.p_value:.4g} at alpha {self.cfg.alpha:g})."
            + supporting
            + " "
            + context.statement,
        )


def _digest_safe(value: Any) -> Any:
    """Local float-free view for the assessment id (ADR-004)."""
    from ..core.canonical import digest_safe

    return digest_safe(value)


__all__ = [
    "CHARACTERIZER_VERSION", "ShiftAssessment", "ShiftCharacterizer",
    "ShiftVerdict", "SHIFT_OBSERVED_VERDICTS", "SHIFT_UNRESOLVED_VERDICTS",
]
