"""Declared operational context, and the line between a claim and an observation.

The problem statement asks the system to distinguish an operational change —
new terrain, a different season, another sensor, worse illumination — from
deliberate manipulation.  The temptation is to solve that by asking the
contributor, and the answer to that temptation is the whole of this module.

A declared context is a **claim by the untrusted side**.  ``sensor = Sensor-A``
does not establish that the physical sensor was Sensor-A; it establishes that
somebody wrote that down.  So declarations are never treated as evidence of
what happened.  They are treated as **hypotheses that the observed shift can be
checked against**, and the result of that check is one of:

``EXPLAINED_BY_DECLARED_CONTEXT``
    The declared change would move the views of the image that actually moved.
    The declaration is *consistent with* the observation.  It is not confirmed
    by it — a manipulation designed to look like an illumination change would
    also land here, and the finding says so.

``PARTIALLY_EXPLAINED``
    Some of the movement is where the declaration predicts and some is not.
    The unexplained part is named.

``UNEXPLAINED``
    A declaration exists and does not predict the movement observed, or no
    change was declared at all while the population moved.

``NO_CONTEXT_DECLARED``
    Nothing was declared, so no adjudication is possible.  This is *not*
    "unexplained": there is nothing to contradict.  Collapsing the two would
    punish an operator for not filling in a form.

The mapping from a declared change to the views it would move is a **documented
heuristic over a specific feature space**, listed below in full, and it is
uncalibrated.  Every finding that rests on it carries that limitation and is
capped accordingly.  It exists to stop the system from reporting every
legitimate seasonal change as a security event, not to certify that a change
was legitimate.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

CONTEXT_VERSION = "1.0"

#: The declarable dimensions of an operating environment, and for each one the
#: feature-space views a change along it would be **expected** to move.
#:
#: Read this table as "if the operator declares that the sensor changed, then
#: movement in the acquisition, dct and colour views is the predicted
#: consequence of that declaration".  It is a statement about this specific
#: 614-dimensional classical descriptor (``docs/research.md`` §5, ADR-005), and
#: it would have to be re-derived for a different feature space.
#:
#: Derivation, so it can be argued with rather than taken on faith:
#:
#: ``illumination``
#:     changes exposure, contrast and the luminance percentiles, all of which
#:     live in the acquisition block, and shifts the value axis of the HSV
#:     histogram (colour). Low light also suppresses high-frequency detail,
#:     which the DCT low band registers.
#: ``sensor``
#:     changes noise floor, sharpness and spectral response: acquisition
#:     (noise/focus statistics), dct (frequency content, compression) and
#:     colour (response curve).
#: ``season``
#:     changes ground cover and colour balance, and to a lesser degree the
#:     texture statistics: colour, gradient, structure.
#: ``terrain``
#:     changes what is in the frame: structure and gradient first, colour with
#:     it.
#: ``acquisition_mode``
#:     (day/night, oblique/nadir, altitude) changes exposure and geometry:
#:     acquisition, colour, dct, structure.
CONTEXT_DIMENSIONS: dict[str, dict[str, Any]] = {
    "season": {
        "explains": ("colour", "gradient", "structure"),
        "note": "vegetation, snow cover and solar angle change ground colour "
        "and texture",
    },
    "terrain": {
        "explains": ("structure", "gradient", "colour"),
        "note": "a different landscape changes frame content before it changes "
        "acquisition physics",
    },
    "sensor": {
        "explains": ("acquisition", "dct", "colour", "gradient"),
        "note": "noise floor, sharpness, spectral response and compression are "
        "properties of the imaging chain. 'gradient' was added after "
        "measurement, not from intuition: the lab's sensor transform -- a softer "
        "optical train plus column-correlated read noise -- put 81% of its "
        "squared displacement in the gradient view, because a change in optical "
        "sharpness IS a change in edge statistics. The original table predicted "
        "acquisition, dct and colour only, and reported a legitimate declared "
        "platform swap as partially unexplained.",
    },
    "illumination": {
        "explains": ("acquisition", "colour", "dct"),
        "note": "exposure and contrast move the luminance statistics and the "
        "value axis of the colour histogram",
    },
    "acquisition_mode": {
        "explains": ("acquisition", "colour", "dct", "structure"),
        "note": "day/night, viewing geometry and altitude change both the "
        "exposure regime and the frame content",
    },
}


class ContextExplanation(str, Enum):
    """How the declared context relates to the observed movement."""

    EXPLAINED_BY_DECLARED_CONTEXT = "EXPLAINED_BY_DECLARED_CONTEXT"
    PARTIALLY_EXPLAINED = "PARTIALLY_EXPLAINED"
    UNEXPLAINED = "UNEXPLAINED"
    NO_CONTEXT_DECLARED = "NO_CONTEXT_DECLARED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class OperationalContext(BaseModel):
    """What the operator declares about an operating environment.

    Every field is optional and every field is a claim.  ``source`` records who
    made the claim, because "the analyst's own site log" and "a field supplied
    by the contributor alongside the imagery" are very different evidential
    weights and the report must not flatten them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    season: str | None = None
    terrain: str | None = None
    sensor: str | None = None
    illumination: str | None = None
    acquisition_mode: str | None = None
    extra: dict[str, str] = Field(
        default_factory=dict,
        description="Further declared conditions. Recorded and reported, but "
        "not interpretable by the explanation table, so they never explain a "
        "shift — they are context for the analyst only.",
    )
    source: str | None = Field(
        default=None,
        description="Who made this declaration. Recorded verbatim, never "
        "validated, and never treated as evidence of what physically happened.",
    )

    def declared(self) -> dict[str, str]:
        return {
            key: value
            for key, value in (
                ("season", self.season),
                ("terrain", self.terrain),
                ("sensor", self.sensor),
                ("illumination", self.illumination),
                ("acquisition_mode", self.acquisition_mode),
            )
            if value is not None
        }

    def is_empty(self) -> bool:
        return not self.declared() and not self.extra

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> "OperationalContext":
        if not payload:
            return cls()
        known = {"season", "terrain", "sensor", "illumination", "acquisition_mode", "source"}
        fields = {k: str(v) for k, v in payload.items() if k in known and v is not None}
        extra = {
            str(k): str(v) for k, v in payload.items() if k not in known and v is not None
        }
        return cls(**fields, extra=extra)


class ContextDelta(BaseModel):
    """What changed between the reference's context and the current one."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    changed: tuple[str, ...]
    unchanged: tuple[str, ...]
    declared_only_on_one_side: tuple[str, ...]
    reference: dict[str, str]
    current: dict[str, str]

    def any_declared(self) -> bool:
        return bool(self.reference or self.current)


def diff_context(
    reference: OperationalContext, current: OperationalContext
) -> ContextDelta:
    """Which declared dimensions differ between the two populations."""
    ref = reference.declared()
    cur = current.declared()
    changed: list[str] = []
    unchanged: list[str] = []
    one_sided: list[str] = []
    for dimension in sorted(CONTEXT_DIMENSIONS):
        left, right = ref.get(dimension), cur.get(dimension)
        if left is None and right is None:
            continue
        if left is None or right is None:
            one_sided.append(dimension)
        elif left != right:
            changed.append(dimension)
        else:
            unchanged.append(dimension)
    return ContextDelta(
        changed=tuple(changed),
        unchanged=tuple(unchanged),
        declared_only_on_one_side=tuple(one_sided),
        reference=ref,
        current=cur,
    )


class ContextAssessment(BaseModel):
    """The adjudication, with everything it rests on."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    explanation: ContextExplanation
    statement: str
    delta: ContextDelta
    explained_blocks: tuple[str, ...]
    moved_blocks: tuple[str, ...]
    unexplained_blocks: tuple[str, ...]
    observation: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()


#: A view has to carry at least this share of the squared displacement before it
#: counts as having "moved".  A declared change that explains 97% of the
#: movement should not be called partially explained because a fourth decimal
#: place of the residual landed somewhere else.
DEFAULT_MOVED_BLOCK_SHARE = 0.15

_HEURISTIC_LIMITATION = (
    "the mapping from a declared operational change to the feature-space views "
    "it would move is a documented heuristic over this specific descriptor "
    "(see cvtrust.shift.context.CONTEXT_DIMENSIONS); it is uncalibrated, and "
    "consistency with a declaration is not confirmation of it"
)

#: Measured, and stated on every explanation that rests on the table.
#:
#: Illumination, season and terrain changes all put ~93% of their squared
#: displacement in the SAME view (colour) in this feature space, so the
#: attribution cannot tell them apart.  A declaration naming any one of the
#: three will therefore be reported as consistent with a movement caused by
#: another of the three.  What the check still does reliably -- and what the
#: policy actually depends on -- is the coarser question: does the declaration
#: predict movement in the views that moved, at all?  A declaration of "nothing
#: changed" against a moved population, and a movement in a view no declared
#: change predicts, are both caught.
_RESOLUTION_LIMITATION = (
    "the feature-view attribution is coarse: illumination, season and terrain "
    "changes all move predominantly the same view in this descriptor, so a "
    "declaration naming one of them is reported consistent with a movement "
    "actually caused by another. The check distinguishes 'the declaration "
    "predicts this movement' from 'it does not'; it does not identify which "
    "declared change occurred"
)

_ADVERSARY_LIMITATION = (
    "a manipulation engineered to move the same views a declared change would "
    "move is reported as consistent with the declaration; consistency bounds "
    "what the evidence contradicts, it does not establish what happened"
)

_CLAIM_LIMITATION = (
    "the declared context is a claim by the supplying side and was not "
    "independently verified; no part of this system can establish which "
    "physical sensor, season or terrain produced an image"
)


def explain_shift(
    *,
    reference_context: OperationalContext,
    current_context: OperationalContext,
    block_shares: Mapping[str, float],
    shift_detected: bool,
    moved_block_share: float = DEFAULT_MOVED_BLOCK_SHARE,
) -> ContextAssessment:
    """Check the observed movement against what the declaration would predict.

    ``block_shares`` is the share of squared mean displacement per feature view,
    as produced by :func:`cvtrust.shift.metrics.mean_shift`.
    """
    delta = diff_context(reference_context, current_context)
    moved = tuple(
        sorted(
            name
            for name, share in block_shares.items()
            if share >= moved_block_share
        )
    )
    limitations = (_CLAIM_LIMITATION, _HEURISTIC_LIMITATION, _RESOLUTION_LIMITATION)

    if not shift_detected:
        return ContextAssessment(
            explanation=ContextExplanation.NOT_APPLICABLE,
            statement=(
                "No population shift was resolved, so there is nothing for the "
                "declared operational context to explain."
            ),
            delta=delta,
            explained_blocks=(),
            moved_blocks=moved,
            unexplained_blocks=(),
            observation={"block_shares": dict(sorted(block_shares.items()))},
            limitations=limitations,
        )

    if not delta.any_declared():
        return ContextAssessment(
            explanation=ContextExplanation.NO_CONTEXT_DECLARED,
            statement=(
                "A population shift was observed and no operational context was "
                "declared for either population, so the shift can be neither "
                "explained nor contradicted. This is a missing input, not a "
                "suspicious one."
            ),
            delta=delta,
            explained_blocks=(),
            moved_blocks=moved,
            unexplained_blocks=moved,
            observation={"block_shares": dict(sorted(block_shares.items()))},
            limitations=limitations,
        )

    explained: set[str] = set()
    for dimension in (*delta.changed, *delta.declared_only_on_one_side):
        explained.update(CONTEXT_DIMENSIONS[dimension]["explains"])
    unexplained = tuple(sorted(set(moved) - explained))

    observation = {
        "block_shares": dict(sorted(block_shares.items())),
        "moved_block_share_threshold": moved_block_share,
        "declared_changes": list(delta.changed),
        "declared_on_one_side_only": list(delta.declared_only_on_one_side),
        "declared_unchanged": list(delta.unchanged),
        "blocks_predicted_by_declaration": sorted(explained),
        "explanation_table": {
            dimension: list(meta["explains"])
            for dimension, meta in sorted(CONTEXT_DIMENSIONS.items())
        },
        "declaration_source": current_context.source,
        "declaration_validated": False,
    }

    if not delta.changed and not delta.declared_only_on_one_side:
        return ContextAssessment(
            explanation=ContextExplanation.UNEXPLAINED,
            statement=(
                "A population shift was observed while the declared operational "
                "context is identical on both sides ("
                + ", ".join(f"{k}={v}" for k, v in sorted(delta.current.items()))
                + "). The declaration predicts no change and the population "
                "changed. That is an open question for an analyst, not evidence "
                "of manipulation."
            ),
            delta=delta,
            explained_blocks=(),
            moved_blocks=moved,
            unexplained_blocks=moved,
            observation=observation,
            limitations=limitations,
        )

    changes = ", ".join(
        f"{dimension}: {delta.reference.get(dimension, '(undeclared)')} -> "
        f"{delta.current.get(dimension, '(undeclared)')}"
        for dimension in (*delta.changed, *delta.declared_only_on_one_side)
    )
    if not unexplained:
        return ContextAssessment(
            explanation=ContextExplanation.EXPLAINED_BY_DECLARED_CONTEXT,
            statement=(
                f"The observed movement is confined to the feature views a "
                f"declared change would move ({changes}). Every view carrying at "
                f"least {moved_block_share:.0%} of the displacement "
                f"({', '.join(moved) or 'none'}) is predicted by the declaration. "
                "The shift is consistent with the declared operational change; "
                "it is not thereby confirmed to be one."
            ),
            delta=delta,
            explained_blocks=tuple(sorted(explained)),
            moved_blocks=moved,
            unexplained_blocks=(),
            observation=observation,
            limitations=(*limitations, _ADVERSARY_LIMITATION),
        )

    return ContextAssessment(
        explanation=(
            ContextExplanation.PARTIALLY_EXPLAINED
            if len(unexplained) < len(moved)
            else ContextExplanation.UNEXPLAINED
        ),
        statement=(
            f"The declared change ({changes}) predicts movement in "
            f"{', '.join(sorted(explained))}, but the population also moved in "
            f"{', '.join(unexplained)}, which the declaration does not account "
            "for. The unexplained residual is an open question for an analyst."
        ),
        delta=delta,
        explained_blocks=tuple(sorted(explained)),
        moved_blocks=moved,
        unexplained_blocks=unexplained,
        observation=observation,
        limitations=limitations,
    )


__all__ = [
    "CONTEXT_VERSION", "CONTEXT_DIMENSIONS", "ContextExplanation",
    "OperationalContext", "ContextDelta", "ContextAssessment",
    "DEFAULT_MOVED_BLOCK_SHARE", "diff_context", "explain_shift",
]
