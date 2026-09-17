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

    methods: tuple[Literal["mahalanobis", "knn"], ...] = ("mahalanobis", "knn")
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
    detectors: tuple[str, ...] = (
        "integrity",
        "exact_duplicate",
        "near_duplicate",
        "label_consistency",
        "systematic_mislabel",
        "ood",
    )
    features: FeatureConfig = FeatureConfig()
    phash: PerceptualHashConfig = PerceptualHashConfig()
    near_duplicate: NearDuplicateConfig = NearDuplicateConfig()
    label_consistency: LabelConsistencyConfig = LabelConsistencyConfig()
    systematic_mislabel: SystematicMislabelConfig = SystematicMislabelConfig()
    ood: OODConfig = OODConfig()
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
