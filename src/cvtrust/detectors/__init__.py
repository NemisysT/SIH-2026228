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

__all__ = [
    "DETECTORS", "EXECUTION_ORDER", "AnalysisContext", "Detector", "DetectorOutput",
    "FindingFactory", "coverage_entry", "IntegrityDetector", "ExactDuplicateDetector",
    "NearDuplicateDetector", "LabelConsistencyDetector", "SystematicMislabelDetector",
    "OODDetector",
]
