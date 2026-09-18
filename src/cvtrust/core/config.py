"""Configuration.

Every tunable that affects a finding lives here, is serialised into the report,
and is folded into the configuration hash that identifies a run.  A threshold
that is hard-coded in a detector is a threshold an analyst cannot audit, so
there are none.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .canonical import digest_safe
from .errors import ConfigError
from .hashing import sha256_canonical


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FeatureConfig(_Base):
    """Feature-space settings (ADR-005).

    The default extractor is ``classical``: a deterministic handcrafted
    descriptor that needs no pretrained weights and therefore no network.  A
    CNN backbone is available under the same interface but is never
    auto-downloaded.
    """

    extractor: str = Field(
        default="classical",
        description="Registered FeatureExtractor name.",
    )
    thumbnail: int = Field(default=32, ge=8, le=128)
    hsv_bins: tuple[int, int, int] = (8, 4, 4)
    gradient_bins: int = Field(default=16, ge=4, le=64)
    dct_band: int = Field(default=8, ge=4, le=16)
    max_side: int = Field(
        default=512,
        ge=64,
        description="Images are downscaled to this longest side before feature "
        "extraction, bounding cost and removing resolution as a confound.",
    )


class PerceptualHashConfig(_Base):
    hash_size: Literal[8] = 8  # 64-bit hashes; packing assumes exactly 64 bits
    dct_size: int = Field(default=32, ge=16, le=64)


class NearDuplicateConfig(_Base):
    """Two-stage near-duplicate detection.

    Stage 1 (recall): pHash Hamming distance.  Stage 2 (precision): cosine
    similarity in the classical feature space, which rejects the structurally
    different images that pHash collides on low-detail content.
    """

    phash_hamming_max: int = Field(
        default=8,
        ge=0,
        le=32,
        description="Stage-1 candidate threshold over 64 bits. 8/64 is the "
        "conventional operating point in the perceptual-hash literature.",
    )
    confirm_cosine_min: float = Field(default=0.90, ge=0.0, le=1.0)
    flood_cluster_size: int = Field(
        default=5,
        ge=2,
        description="Cluster size at which a near-duplicate group is treated as "
        "flooding rather than incidental redundancy.",
    )
    max_pairwise_samples: int = Field(
        default=50_000,
        ge=100,
        description="Above this, exact all-pairs comparison is refused and the "
        "detector reports PARTIAL coverage rather than silently sampling.",
    )


class LabelConsistencyConfig(_Base):
    k: int = Field(default=10, ge=3, le=100)
    disagreement_min: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Minimum distance-weighted neighbour disagreement before a "
        "label is called suspicious.",
    )
    min_class_support: int = Field(
        default=8,
        ge=3,
        description="Classes with fewer samples than this are excluded; kNN "
        "label agreement is meaningless without neighbours.",
    )
    exclude_near_duplicates: bool = Field(
        default=True,
        description="Near-duplicates of the query are removed from its "
        "neighbourhood, otherwise a flooding attack manufactures agreement.",
    )


class SystematicMislabelConfig(_Base):
    alpha: float = Field(default=0.01, ge=0.0, le=0.5)
    min_pair_count: int = Field(
        default=4,
        ge=2,
        description="Minimum observed (declared -> suggested) pair count before "
        "a test is performed at all.",
    )
    min_contributor_samples: int = Field(default=10, ge=3)


class OODConfig(_Base):
    """Out-of-distribution scoring against a declared reference set."""

    methods: tuple[Literal["mahalanobis", "knn", "residual"], ...] = (
        "mahalanobis",
        "knn",
        "residual",
    )
    knn_k: int = Field(default=5, ge=1, le=50)
    target_fpr: float = Field(
        default=0.01,
        gt=0.0,
        lt=0.5,
        description="Nominal false-positive rate. The decision threshold is the "
        "(1 - target_fpr) quantile of cross-fitted reference scores, so the "
        "threshold has a stated meaning instead of being a chosen constant.",
    )
    min_reference_samples: int = Field(
        default=30,
        ge=10,
        description="Below this the covariance estimate is not trustworthy and "
        "the detector reports NOT_ASSESSED.",
    )
    pca_components: int = Field(
        default=48,
        ge=2,
        description="Reference-fitted PCA applied before distance computation, "
        "so that covariance estimation is well-conditioned.",
    )


class BatteryConfig(_Base):
    """The probe battery every behavioural claim is measured against (Module 2).

    Every value here changes what a behavioural finding means, so every value is
    in the configuration hash and printed in the report.
    """

    clean_per_class: int = Field(default=4, ge=1, le=64)
    borderline_pairs: int = Field(
        default=6,
        ge=0,
        le=64,
        description="Class pairs interpolated to probe the decision boundary, "
        "which is where two models that differ at all differ most visibly.",
    )
    ood_count: int = Field(
        default=8,
        ge=0,
        le=128,
        description="Out-of-distribution probes. Present to guard the inverse "
        "error: OOD behaviour is never treated as evidence of a backdoor.",
    )
    trigger_bases: int = Field(
        default=6,
        ge=0,
        le=64,
        description="Clean probes each declared trigger is stamped onto.",
    )
    batch_size: int = Field(
        default=32,
        ge=1,
        le=512,
        description="Fixed, not adaptive: on some runtimes the reduction order "
        "inside a batched matmul depends on the batch dimension, so a variable "
        "batch size would make an argmax at a boundary depend on chunking.",
    )


class BehaviourConfig(_Base):
    """Thresholds for the behavioural comparison (Module 2)."""

    agreement_floor: float = Field(
        default=0.98,
        ge=0.0,
        le=1.0,
        description="Prediction agreement below which a supplied model is called "
        "behaviourally anomalous relative to its reference. Two artifacts of the "
        "same model measure 1.000, so this is set just below to absorb a boundary "
        "probe flipping on last-bit float differences between runtimes.",
    )
    consistency_floor: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description="Metamorphic consistency below which predictions are called "
        "unstable. Reference-free, so it is the black-box pathway's own signal.",
    )


class ParameterAnalysisConfig(_Base):
    """White-box weight analysis (Module 2)."""

    peer_z_threshold: float = Field(
        default=8.0,
        ge=1.0,
        le=50.0,
        description="Robust z (median/MAD, 1.4826-scaled, finite-sample "
        "corrected) above which a tensor is called a peer-group outlier. "
        "Deliberately NOT the conventional Iglewicz-Hoaglin 3.5: that operating "
        "point is for a single statistic on a large sample, while this screening "
        "tests four statistics per group on groups often smaller than ten "
        "tensors. Measured against the null, 3.5 gives a ~35% false-alarm rate "
        "and 8.0 gives <=3%. See cvtrust.models.params.DEFAULT_PEER_Z.",
    )


class ActivationConfig(_Base):
    """Activation-based backdoor analysis (Module 2)."""

    layer: str | None = Field(
        default=None,
        description="Intermediate tensor to inspect. Absent means the last tap "
        "the adapter offers, which is the penultimate representation — the layer "
        "both source methods operate on.",
    )
    spectral_epsilon: float = Field(
        default=0.15,
        gt=0.0,
        lt=1.0,
        description="Fraction of each class removed as spectral-signature "
        "candidates (Tran et al. 2018).",
    )
    min_class_support: int = Field(
        default=12,
        ge=4,
        description="Below this a top singular vector and a 2-means split are "
        "both fitting noise, and the class is reported as skipped rather than "
        "scored.",
    )


class TriggerConfig(_Base):
    """Trigger search (Module 2).

    Budgets are small by default so that a full assessment stays runnable on a
    normal CPU. The budget is recorded in every finding, because a negative
    result under a small budget is a weaker statement than one under a large
    budget and an analyst must be able to tell which they are reading.
    """

    enable_reconstruction: bool = Field(
        default=True,
        description="Neural Cleanse. Requires input gradients, so it runs on "
        "PyTorch/TorchScript and is reported NOT_ASSESSED on ONNX.",
    )
    enable_family_probe: bool = Field(
        default=True,
        description="Gradient-free sweep of the declared patch family. Works "
        "under black-box access; explicitly not reconstruction.",
    )
    steps: int = Field(default=200, ge=10, le=5000)
    learning_rate: float = Field(default=0.1, gt=0.0, le=1.0)
    mask_penalty: float = Field(
        default=0.03,
        gt=0.0,
        description="L1 penalty on the mask. This term is what makes Neural "
        "Cleanse work, and it is also what makes it blind to a trigger that is "
        "large by design.",
    )
    success_threshold: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
        description="Attack success rate a reconstructed trigger must reach "
        "before an anomaly-index outlier is treated as a hit. The conjunction is "
        "what suppresses Neural Cleanse's known false positives on clean models.",
    )
    probe_opacities: tuple[float, ...] = Field(
        default=(1.0,),
        description="Opacities swept by the family probe. Values below 1.0 probe "
        "the blended-trigger family (Chen et al. 2017).",
    )


class ModelConfig(_Base):
    """Module 2: model forensics and backdoor assurance."""

    detectors: tuple[str, ...] = (
        "model_identity",
        "model_structure",
        "model_parameters",
        "model_behaviour",
        "model_activation",
        "model_trigger",
    )
    input_shape: tuple[int, int, int, int] | None = Field(
        default=None,
        description="Declared model input as (batch, C, H, W). Needed only for "
        "torch artifacts, which carry no input signature; when absent, a short "
        "list of conventional shapes is probed and the manifest records that the "
        "shape was probed rather than declared.",
    )
    allow_unsafe_deserialisation: bool = Field(
        default=False,
        description="Permit torch.load(weights_only=False) on a full module "
        "pickle. OFF by default: unpickling executes code from an artifact this "
        "tool treats as untrusted. See docs/model-security.md.",
    )
    benchmark_dir: str | None = Field(
        default=None,
        description="Locally vendored TrojAI/BackdoorBench directory. Absent "
        "means benchmark evaluation is NOT_ASSESSED. Never downloaded.",
    )
    battery: BatteryConfig = BatteryConfig()
    behaviour: BehaviourConfig = BehaviourConfig()
    parameters: ParameterAnalysisConfig = ParameterAnalysisConfig()
    activation: ActivationConfig = ActivationConfig()
    trigger: TriggerConfig = TriggerConfig()


class ProvenanceConfig(_Base):
    """Module 3: inference provenance and cryptographic integrity.

    Small on purpose.  Almost nothing about cryptographic verification is a
    tunable: a digest either matches or it does not, and a "signature strictness"
    knob would be a way to turn verification off.  What is here are the genuine
    policy choices an operator has to make, and each one changes what a
    verification *means*, so each is in the configuration hash and printed in
    the report.
    """

    validity_policy: Literal["at_record_timestamp", "at_verification_time"] = Field(
        default="at_record_timestamp",
        description="When to evaluate a signing key's validity window. "
        "'at_record_timestamp' honours key rotation -- a record signed last year "
        "by a key retired since still verifies -- at the cost that the moment is "
        "the record's own self-asserted clock, which a key holder also controls. "
        "'at_verification_time' is immune to backdating and invalidates the "
        "entire history of every key that has ever expired.",
    )
    required_key_purpose: Literal["inference_provenance", "log_anchor", "any"] = Field(
        default="inference_provenance",
        description="Purpose a key must be authorised for to sign inference "
        "records. A key trusted to sign records is not thereby trusted to attest "
        "that a log is complete.",
    )
    record_observations: bool = Field(
        default=True,
        description="Whether verifying a log adds its records to the replay "
        "database. Off makes a verification a pure dry run; the database is "
        "returned either way and the caller decides whether to persist it.",
    )
    require_signature: bool = Field(
        default=True,
        description="Whether an unsigned record is a finding. On by default: an "
        "unsigned record attributes itself to no one.",
    )
    output_quantization_places: int = Field(
        default=6,
        ge=0,
        le=12,
        description="Decimal places used to put confidences, box coordinates and "
        "configuration floats on a fixed grid before hashing (ADR-004). Recorded "
        "in every record, so changing it produces visibly different records "
        "rather than silently incompatible ones.",
    )


class AggregationConfig(_Base):
    alpha: float = Field(default=0.05, ge=0.0, le=0.5)
    min_contributor_samples: int = Field(default=8, ge=1)
    min_flagged: int = Field(default=2, ge=1)


class DispositionConfig(_Base):
    """Severity/confidence gates for the recommended disposition.

    Expressed as data so that the rule an analyst sees in the report is the rule
    the code executed.
    """

    quarantine_min_severity: str = "HIGH"
    quarantine_min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    review_min_severity: str = "LOW"
    review_min_confidence: float = Field(default=0.30, ge=0.0, le=1.0)


class ContributorConfig(_Base):
    """How contributor / batch / source metadata is resolved.

    Precedence is explicit and reported, because a contributor attribution that
    silently falls back to a path guess would let an adversary launder its own
    submissions into another contributor's risk profile.
    """

    sidecar: str | None = Field(
        default="contributors.json",
        description="Dataset-root-relative sidecar mapping relpath -> metadata.",
    )
    path_pattern: str | None = Field(
        default=None,
        description=r"Optional regex with named groups (contributor, batch, "
        r"source) matched against the sample relpath, e.g. "
        r"'^(?P<contributor>[^/]+)/'.",
    )
    unknown_label: str = "unknown"


class Config(_Base):
    """Top-level configuration."""

    seed: int = Field(default=20260917, ge=0)
    #: Which detectors to run.  This is a *set* of names, not an order: the
    #: execution order is fixed in ``detectors.EXECUTION_ORDER`` because later
    #: detectors consume artifacts published by earlier ones.  Listed here in
    #: execution order anyway, so the configuration does not imply an order the
    #: pipeline ignores.
    detectors: tuple[str, ...] = (
        "integrity",
        "exact_duplicate",
        "near_duplicate",
        "ood",
        "label_consistency",
        "systematic_mislabel",
    )
    features: FeatureConfig = FeatureConfig()
    phash: PerceptualHashConfig = PerceptualHashConfig()
    near_duplicate: NearDuplicateConfig = NearDuplicateConfig()
    label_consistency: LabelConsistencyConfig = LabelConsistencyConfig()
    systematic_mislabel: SystematicMislabelConfig = SystematicMislabelConfig()
    ood: OODConfig = OODConfig()
    #: Module 2. Present in the configuration from this build onward, so that a
    #: model assessment's thresholds are folded into the same config hash as a
    #: dataset scan's and the two are comparable artifacts.
    model: ModelConfig = ModelConfig()
    #: Module 3. Present from this build onward for the same reason Module 2's
    #: section was: a provenance verification's policy choices belong in the
    #: same config hash as a dataset scan's thresholds, so the two are
    #: comparable artifacts.
    provenance: ProvenanceConfig = ProvenanceConfig()
    aggregation: AggregationConfig = AggregationConfig()
    disposition: DispositionConfig = DispositionConfig()
    contributor: ContributorConfig = ContributorConfig()
    calibration_path: str | None = Field(
        default=None,
        description="Path to a calibration table produced by `cvtrust evaluate`. "
        "Absent means every threshold-based detector reports "
        "HEURISTIC_UNCALIBRATED confidence.",
    )

    def config_hash(self) -> str:
        """SHA-256 over a float-free digest view of the whole configuration."""
        return sha256_canonical(digest_safe(self.model_dump(mode="json")))

    @classmethod
    def load(cls, path: Path | str | None) -> "Config":
        if path is None:
            return cls()
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"configuration file not found: {p}")
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"configuration root must be a mapping: {p}")
        try:
            return cls.model_validate(raw)
        except Exception as exc:
            raise ConfigError(f"invalid configuration in {p}: {exc}") from exc

    def merged(self, overrides: dict[str, Any]) -> "Config":
        """Return a copy with a shallow-per-section override applied."""
        base = self.model_dump(mode="json")
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = {**base[key], **value}
            else:
                base[key] = value
        return Config.model_validate(base)
