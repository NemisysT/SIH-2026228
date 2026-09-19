"""Evidence families: the answer to "are these three detectors three attacks?"

They are usually not, and a fusion engine that assumes they are is a machine for
manufacturing confidence.  Consider the single most common real situation in
this domain — a genuine seasonal or sensor change arriving in a new batch:

::

    ood                 fires: samples sit outside the reference distribution
    label_consistency   fires: those samples have unrepresentative neighbourhoods,
                               so their labels disagree with their neighbours
    distribution_shift  fires: the population centre moved

Three detectors, three attack classes, one phenomenon.  Counting them as three
independent pieces of evidence turns a Tuesday in November into a coordinated
attack.  Averaging their confidences makes it worse, because the average of
three correlated numbers looks like a consensus.

This module encodes two separate relationships, and keeping them separate is
the point:

**Family** (``EvidenceFamily``)
    Which underlying phenomenon this evidence is *about*.  Evidence in the same
    family is correlated by construction, so a family contributes **at most one
    unit of independent support** to any policy rule, however many findings it
    contains.  More findings inside a family still matter — they raise
    *corroboration*, which is reported — but they never multiply the count of
    independent concerns.

**Confounding** (``CONFOUNDED_BY``)
    Which *other* family's phenomenon could produce this evidence as a side
    effect.  A label-consistency finding is confounded by distribution shift,
    because a shifted population has unrepresentative neighbourhoods; a
    cryptographic signature failure is confounded by nothing, because no amount
    of drift forges a signature.  When a confounding phenomenon is actually
    present in this run, the confounded evidence is **kept, reported, and
    marked** — never deleted — but it stops counting as independent
    corroboration of manipulation.

Both tables are data, printed in the report, and testable.  The alternative —
an implicit correlation assumption living inside a fusion function — is
precisely the kind of hidden weighting the brief forbids.
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class EvidenceFamily(str, Enum):
    """The phenomenon a piece of evidence is about."""

    DATASET_DUPLICATION = "DATASET_DUPLICATION"
    DATASET_LABELLING = "DATASET_LABELLING"
    DATASET_METADATA = "DATASET_METADATA"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    MODEL_IDENTITY = "MODEL_IDENTITY"
    MODEL_TAMPERING = "MODEL_TAMPERING"
    MODEL_BACKDOOR = "MODEL_BACKDOOR"
    PROVENANCE_INTEGRITY = "PROVENANCE_INTEGRITY"
    PROVENANCE_TRUST = "PROVENANCE_TRUST"
    PROVENANCE_REPLAY = "PROVENANCE_REPLAY"
    #: Evidence whose attack class this build does not recognise. Kept visible
    #: rather than silently dropped: an unknown class is a build-version
    #: mismatch, and dropping it would let a newer detector's findings vanish
    #: from a fusion run without a word.
    UNCLASSIFIED = "UNCLASSIFIED"


class EvidenceClass(str, Enum):
    """The *kind* of evidence, which the brief forbids collapsing (§3).

    A data-integrity observation, a model-integrity observation, a
    cryptographic-provenance fact and a distribution measurement are different
    kinds of statement with different failure modes.  ``model suspicious +
    provenance valid`` and ``model clean + provenance invalid`` are both real
    states calling for opposite actions, and any function that mapped them onto
    one scale would map them onto the same value (ADR-014).
    """

    DATA_INTEGRITY = "DATA_INTEGRITY"
    MODEL_INTEGRITY = "MODEL_INTEGRITY"
    PROVENANCE_INTEGRITY = "PROVENANCE_INTEGRITY"
    DISTRIBUTION_SHIFT = "DISTRIBUTION_SHIFT"
    OPERATIONAL_CONTEXT = "OPERATIONAL_CONTEXT"


#: attack class -> (family, evidence class).  Every class in
#: ``cvtrust.risk.coverage.ATTACK_CLASS_REGISTRY`` appears here; a test asserts
#: that, so adding a detector without deciding what family it belongs to is a
#: test failure rather than a silent ``UNCLASSIFIED``.
FAMILY_OF: dict[str, tuple[EvidenceFamily, EvidenceClass]] = {
    "duplicate_flood": (EvidenceFamily.DATASET_DUPLICATION, EvidenceClass.DATA_INTEGRITY),
    "near_duplicate_flood": (
        EvidenceFamily.DATASET_DUPLICATION,
        EvidenceClass.DATA_INTEGRITY,
    ),
    "label_flip": (EvidenceFamily.DATASET_LABELLING, EvidenceClass.DATA_INTEGRITY),
    "systematic_mislabel": (
        EvidenceFamily.DATASET_LABELLING,
        EvidenceClass.DATA_INTEGRITY,
    ),
    "metadata_inconsistency": (
        EvidenceFamily.DATASET_METADATA,
        EvidenceClass.DATA_INTEGRITY,
    ),
    "dataset_tamper": (EvidenceFamily.DATASET_METADATA, EvidenceClass.DATA_INTEGRITY),
    # The load-bearing entry. Module 1's per-sample OOD detector and Module 4's
    # population-shift characteriser answer different questions about the SAME
    # phenomenon, so they share a family and cannot corroborate each other into
    # two concerns.
    "ood_insertion": (
        EvidenceFamily.DISTRIBUTION_SHIFT,
        EvidenceClass.DISTRIBUTION_SHIFT,
    ),
    "distribution_shift": (
        EvidenceFamily.DISTRIBUTION_SHIFT,
        EvidenceClass.DISTRIBUTION_SHIFT,
    ),
    "trigger_injection": (EvidenceFamily.MODEL_BACKDOOR, EvidenceClass.DATA_INTEGRITY),
    "model_substitution": (EvidenceFamily.MODEL_IDENTITY, EvidenceClass.MODEL_INTEGRITY),
    "model_tampering": (EvidenceFamily.MODEL_TAMPERING, EvidenceClass.MODEL_INTEGRITY),
    "model_backdoor": (EvidenceFamily.MODEL_BACKDOOR, EvidenceClass.MODEL_INTEGRITY),
    "inference_tampering": (
        EvidenceFamily.PROVENANCE_INTEGRITY,
        EvidenceClass.PROVENANCE_INTEGRITY,
    ),
    "record_reordering": (
        EvidenceFamily.PROVENANCE_INTEGRITY,
        EvidenceClass.PROVENANCE_INTEGRITY,
    ),
    "chain_truncation": (
        EvidenceFamily.PROVENANCE_INTEGRITY,
        EvidenceClass.PROVENANCE_INTEGRITY,
    ),
    "provenance_key_trust": (
        EvidenceFamily.PROVENANCE_TRUST,
        EvidenceClass.PROVENANCE_INTEGRITY,
    ),
    "inference_replay": (
        EvidenceFamily.PROVENANCE_REPLAY,
        EvidenceClass.PROVENANCE_INTEGRITY,
    ),
}


#: family -> families whose phenomenon could produce it as a side effect.
#:
#: Each entry is a claim about causation and each one is argued, because an
#: unargued confounding table is a way to suppress inconvenient findings:
#:
#: ``DATASET_LABELLING <- DISTRIBUTION_SHIFT``
#:     A sample outside the reference distribution has an unrepresentative
#:     neighbourhood, so k-NN label disagreement is the *expected* consequence
#:     of a domain shift rather than evidence of a flip. This is not a
#:     hypothesis: Module 1's evaluation harness measured it and the pipeline
#:     already caps such findings to LOW severity in-run
#:     (``docs/research.md`` §"Measured corrections" item 6).
#:
#: ``DISTRIBUTION_SHIFT <- (nothing)``
#:     Shift is the root phenomenon here, not a side effect of one.
#:
#: ``DATASET_DUPLICATION <- (nothing)``
#:     Two files with the same SHA-256 are the same file in any season.
#:
#: ``MODEL_* <- (nothing)``
#:     Module 2 measures a model against a *fixed, versioned probe battery*, not
#:     against operating data. A shift in the field cannot move a behavioural
#:     fingerprint measured on probes that never change. Listing shift as a
#:     confounder here would be a plausible-sounding excuse for exactly the
#:     evidence an adversary most wants discounted.
#:
#: ``PROVENANCE_* <- (nothing)``
#:     No amount of drift forges a signature, breaks a hash chain or reuses a
#:     nonce. These are deterministic facts (ADR-014).
CONFOUNDED_BY: dict[EvidenceFamily, tuple[EvidenceFamily, ...]] = {
    EvidenceFamily.DATASET_LABELLING: (EvidenceFamily.DISTRIBUTION_SHIFT,),
    EvidenceFamily.DATASET_DUPLICATION: (),
    EvidenceFamily.DATASET_METADATA: (),
    EvidenceFamily.DISTRIBUTION_SHIFT: (),
    EvidenceFamily.MODEL_IDENTITY: (),
    EvidenceFamily.MODEL_TAMPERING: (),
    EvidenceFamily.MODEL_BACKDOOR: (),
    EvidenceFamily.PROVENANCE_INTEGRITY: (),
    EvidenceFamily.PROVENANCE_TRUST: (),
    EvidenceFamily.PROVENANCE_REPLAY: (),
    EvidenceFamily.UNCLASSIFIED: (),
}


def classify(attack_class: str) -> tuple[EvidenceFamily, EvidenceClass]:
    """Family and evidence class for an attack class, defaulting visibly."""
    return FAMILY_OF.get(
        attack_class, (EvidenceFamily.UNCLASSIFIED, EvidenceClass.DATA_INTEGRITY)
    )


def confounders_of(family: EvidenceFamily) -> tuple[EvidenceFamily, ...]:
    return CONFOUNDED_BY.get(family, ())


def describe_families() -> dict[str, Any]:
    """The two tables, verbatim, for inclusion in the report.

    Printed for the same reason the disposition rule table is printed: a
    correlation assumption an analyst cannot read is a correlation assumption
    an analyst cannot argue with.
    """
    members: dict[str, list[str]] = {}
    for attack_class, (family, _) in sorted(FAMILY_OF.items()):
        members.setdefault(family.value, []).append(attack_class)
    return {
        "principle": "a family contributes at most one unit of independent "
        "support to any policy rule, however many findings it contains; "
        "additional findings within a family raise corroboration, which is "
        "reported, and never multiply the count of independent concerns",
        "families": [
            {
                "family": family,
                "attack_classes": classes,
                "evidence_classes": sorted(
                    {FAMILY_OF[c][1].value for c in classes}
                ),
                "confounded_by": [
                    f.value for f in confounders_of(EvidenceFamily(family))
                ],
            }
            for family, classes in sorted(members.items())
        ],
        "confounding_note": "a confounded finding is kept, reported and marked. "
        "It never counts as independent corroboration of manipulation while its "
        "confounding phenomenon is present, and it is never deleted: suppressing "
        "a real observation is worse than qualifying it",
    }


__all__ = [
    "EvidenceFamily", "EvidenceClass", "FAMILY_OF", "CONFOUNDED_BY",
    "classify", "confounders_of", "describe_families",
]
