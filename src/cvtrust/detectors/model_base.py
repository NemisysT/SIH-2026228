"""Model detector framework.

The dataset-side :class:`~cvtrust.detectors.base.AnalysisContext` carries a
dataset, a manifest, features and contributor attributions — none of which a
model assessment has.  So Module 2 gets its own context, and deliberately *not*
its own everything-else: :class:`~cvtrust.detectors.base.FindingFactory`,
``CalibrationSet``, ``DispositionPolicy``, ``CoverageStatement`` and the
``Finding`` schema are the Module 1 originals, reused verbatim.

Two contracts carry over unchanged, because they are the reason Module 1's
output is trustworthy and nothing about models makes them less necessary:

1. **A detector that cannot run says so.**  A white-box method on a black-box
   artifact returns ``REQUIRES_WHITE_BOX``; a method whose capability is absent
   returns ``NOT_ASSESSED`` with a machine-readable reason.  Zero findings
   because a method could not run must never be presentable as zero findings
   because the model is clean.

2. **Confidence goes through one door.**  Every Module 2 finding is built by
   ``FindingFactory.emit``, so it is resolved against the same calibration
   tables and the same disposition policy as a dataset finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..core.config import Config
from ..core.context import RunContext
from ..core.errors import DetectorUnavailable
from ..core.evidence import AssetRef, AssetType, Coverage
from ..core.registry import Registry
from ..models.base import AccessMode, Capability, ModelAdapter, ModelHandle
from ..models.battery import ReferenceBattery
from ..models.behaviour import BehaviouralFingerprint
from ..models.manifest import ModelManifest
from ..risk.calibration import CalibrationSet
from ..risk.disposition import DispositionPolicy
from .base import DetectorOutput, coverage_entry


@dataclass
class ModelAnalysisContext:
    """Everything a model detector is allowed to see.

    Note what is *not* here, exactly as in Module 1: attack ground truth.  The
    model attack lab writes ground truth outside the directory holding the
    artifact, and the evaluation harness joins it to findings afterwards, so a
    detector can never read the answer.

    ``reference`` is optional throughout.  A great deal of Module 2 degrades
    rather than fails without one, and which parts degrade is the substance of
    the coverage statement — so the absence of a reference is modelled as a
    first-class state, not as an error.
    """

    supplied: ModelHandle
    supplied_adapter: ModelAdapter
    supplied_manifest: ModelManifest

    reference: ModelHandle | None
    reference_adapter: ModelAdapter | None
    reference_manifest: ModelManifest | None

    battery: ReferenceBattery | None
    config: Config
    run: RunContext
    calibration: CalibrationSet
    policy: DispositionPolicy

    #: Cross-detector artifacts. Detectors run in a fixed order (see
    #: ``MODEL_EXECUTION_ORDER``) so this is a dependency, not a race:
    #: ``model_behaviour`` publishes the fingerprints that ``model_activation``
    #: and ``model_trigger`` consume rather than recomputing.
    shared: dict[str, Any] = field(default_factory=dict)

    @property
    def has_reference(self) -> bool:
        return self.reference_manifest is not None

    @property
    def access_mode(self) -> AccessMode:
        return self.supplied.access_mode

    def model_asset(self) -> AssetRef:
        """The asset every Module 2 finding is about.

        ``digest`` is the file SHA-256, so a finding is bound to the exact
        artifact bytes that produced it — not to a path, which an adversary
        controls.
        """
        return AssetRef(
            type=AssetType.MODEL,
            id=self.supplied_manifest.model_id,
            locator=str(self.supplied.path),
            digest=self.supplied_manifest.file_sha256,
        )

    def supplied_fingerprint(self) -> BehaviouralFingerprint | None:
        return self.shared.get("supplied_fingerprint")

    def reference_fingerprint(self) -> BehaviouralFingerprint | None:
        return self.shared.get("reference_fingerprint")

    def require_capability(self, capability: Capability, what: str) -> None:
        self.supplied.require(capability, what)

    def require_reference(self, what: str) -> None:
        if not self.has_reference:
            raise DetectorUnavailable(
                f"{what} requires a trusted reference model to compare against, "
                "and none was supplied. Pass --reference <path> with an artifact "
                "you have independent grounds to trust; without one this "
                "assessment is NOT_ASSESSED rather than clean."
            )

    def require_battery(self, what: str) -> ReferenceBattery:
        if self.battery is None:
            raise DetectorUnavailable(
                f"{what} requires a reference battery, and none could be built "
                "for this artifact (its input specification could not be "
                "resolved to a concrete shape)"
            )
        return self.battery


@runtime_checkable
class ModelDetector(Protocol):
    """Contract every model detector satisfies."""

    name: str
    version: str
    attack_classes: tuple[str, ...]
    #: The capabilities this detector needs.  Declared rather than discovered so
    #: the pipeline can report what a black-box run will not assess *before*
    #: running anything, which is what the report's access section prints.
    required_capabilities: tuple[Capability, ...]

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput: ...


MODEL_DETECTORS: Registry[ModelDetector] = Registry("model detector")


def unavailable_output(
    detector: ModelDetector, reason: str, *, coverage: Coverage = Coverage.NOT_ASSESSED
) -> DetectorOutput:
    """The output a detector produces when it could not run.

    One coverage entry per attack class, each carrying the machine-readable
    reason.  This is the shape the pipeline builds on a
    :class:`~cvtrust.core.errors.DetectorUnavailable`, and detectors may build
    it directly when they can tell in advance.
    """
    output = DetectorOutput(detector=detector.name, version=detector.version)
    for attack_class in detector.attack_classes:
        output.coverage.append(
            coverage_entry(
                attack_class,
                coverage,
                detector=detector.name,
                detector_version=detector.version,
                reason=reason,
            )
        )
    return output


def white_box_coverage(ctx: ModelAnalysisContext, capability: Capability) -> Coverage:
    """The coverage value for a method whose capability is missing.

    ``REQUIRES_WHITE_BOX`` when the artifact is a black box — the analyst's
    remedy is to obtain the weights.  ``NOT_ASSESSED`` when the artifact *is*
    white-box but this particular capability is missing anyway (an ONNX graph
    with no gradients, a TorchScript archive with no activation hooks) — the
    remedy there is a different export, not more access, and conflating the two
    would send the analyst after the wrong thing.
    """
    if ctx.access_mode is AccessMode.BLACK_BOX:
        return Coverage.REQUIRES_WHITE_BOX
    return Coverage.NOT_ASSESSED


#: Fixed execution order.  Not alphabetical and not configuration order:
#: ``model_behaviour`` computes the fingerprints that ``model_activation`` and
#: ``model_trigger`` consume, and ``model_identity`` publishes the identity
#: comparison that ``model_structure`` qualifies its severity with.
MODEL_EXECUTION_ORDER: tuple[str, ...] = (
    "model_identity",
    "model_structure",
    "model_parameters",
    "model_behaviour",
    "model_activation",
    "model_trigger",
)
