"""Dataset forensics detectors.

Registration order here is also the execution order in the pipeline, and it is a
real dependency chain:

* ``exact_duplicate`` and ``near_duplicate`` publish duplicate groups that
  ``label_consistency`` excludes from its neighbourhoods, so that a flooding
  attack cannot manufacture agreement for a flipped label;
* ``ood`` publishes the samples that sit outside the reference distribution,
  which ``label_consistency`` uses to qualify its own evidence -- a sample the
  reference set does not cover has an unrepresentative neighbourhood, and a
  label claim about it is weaker for a stated, measurable reason;
* ``label_consistency`` publishes the label suggestions that
  ``systematic_mislabel`` tests for directional structure.
"""

from .base import (
    DETECTORS,
    AnalysisContext,
    Detector,
    DetectorOutput,
    FindingFactory,
    coverage_entry,
)
from .exact_duplicate import ExactDuplicateDetector
from .integrity import IntegrityDetector
from .label_consistency import LabelConsistencyDetector
from .near_duplicate import NearDuplicateDetector
from .ood import OODDetector
from .systematic_mislabel import SystematicMislabelDetector

DETECTORS.add("integrity", IntegrityDetector())
DETECTORS.add("exact_duplicate", ExactDuplicateDetector())
DETECTORS.add("near_duplicate", NearDuplicateDetector())
DETECTORS.add("label_consistency", LabelConsistencyDetector())
DETECTORS.add("systematic_mislabel", SystematicMislabelDetector())
DETECTORS.add("ood", OODDetector())

#: Fixed execution order. Not alphabetical, not config-order: detectors later in
#: this list consume artifacts published by earlier ones.
EXECUTION_ORDER: tuple[str, ...] = (
    "integrity",
    "exact_duplicate",
    "near_duplicate",
    "ood",
    "label_consistency",
    "systematic_mislabel",
)


# ---------------------------------------------------------------------------
# Module 2 — model forensics.
#
# Registered in a separate registry from the dataset detectors, not the same
# one: they consume a different context and are driven by a different pipeline,
# and a single registry would let `cvtrust dataset scan --detectors` name a
# model detector that cannot possibly run.  They share everything that matters —
# the Finding schema, FindingFactory, the calibration set, the disposition
# policy and the coverage statement.
# ---------------------------------------------------------------------------
from .model_activation import ModelActivationDetector
from .model_base import (
    MODEL_DETECTORS,
    MODEL_EXECUTION_ORDER,
    ModelAnalysisContext,
    ModelDetector,
    unavailable_output,
    white_box_coverage,
)
from .model_behaviour import ModelBehaviourDetector
from .model_identity import ModelIdentityDetector
from .model_parameters import ModelParameterDetector
from .model_structure import ModelStructureDetector
from .model_trigger import ModelTriggerDetector

MODEL_DETECTORS.add("model_identity", ModelIdentityDetector())
MODEL_DETECTORS.add("model_structure", ModelStructureDetector())
MODEL_DETECTORS.add("model_parameters", ModelParameterDetector())
MODEL_DETECTORS.add("model_behaviour", ModelBehaviourDetector())
MODEL_DETECTORS.add("model_activation", ModelActivationDetector())
MODEL_DETECTORS.add("model_trigger", ModelTriggerDetector())

__all__ = [
    "DETECTORS", "EXECUTION_ORDER", "AnalysisContext", "Detector", "DetectorOutput",
    "FindingFactory", "coverage_entry", "IntegrityDetector", "ExactDuplicateDetector",
    "NearDuplicateDetector", "LabelConsistencyDetector", "SystematicMislabelDetector",
    "OODDetector",
    "MODEL_DETECTORS", "MODEL_EXECUTION_ORDER", "ModelAnalysisContext",
    "ModelDetector", "unavailable_output", "white_box_coverage",
    "ModelIdentityDetector", "ModelStructureDetector", "ModelParameterDetector",
    "ModelBehaviourDetector", "ModelActivationDetector", "ModelTriggerDetector",
]
