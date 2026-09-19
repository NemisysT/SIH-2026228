"""Single-pass feature computation.

Every image is decoded exactly once.  In that one pass we obtain the measured
facts the manifest needs (size, dimensions, content digest), the perceptual
hashes the duplicate detectors need, and the embedding the label and OOD
detectors need.  Decoding a dataset three times would be the dominant cost of
the whole tool.

Unreadable samples are carried through as invalid rows rather than dropped:
a corrupt file is itself a finding, and silently shrinking the sample set would
distort every rate the contributor aggregator computes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np
from PIL import Image

from ..core.config import Config
from ..core.logging import get_logger
from ..datasets.base import IngestIssue, RawDataset
from ..datasets.manifest import ImageFacts, measure_image, resolve_bbox
from .classical import ACQUISITION_NAMES, ClassicalFeatureExtractor
from .perceptual import ahash, dhash, phash

log = get_logger("features.store")

#: Object crops smaller than this (in pixels per side) are skipped: a 4x6 crop
#: has no reliable texture or colour statistics, and scoring it would
#: manufacture noise that the label detectors would then report as evidence.
MIN_CROP_SIDE = 16


@dataclass
class FeatureSet:
    """Per-sample features, aligned by row index."""

    sample_ids: list[str]
    embeddings: np.ndarray            # (n, d) float32, L2-normalised
    phash: np.ndarray                 # (n,) uint64
    ahash: np.ndarray                 # (n,) uint64
    dhash: np.ndarray                 # (n,) uint64
    valid: np.ndarray                 # (n,) bool - image decoded successfully
    facts: dict[str, ImageFacts]
    extractor: dict[str, Any]
    index: dict[str, int] = field(default_factory=dict)
    #: (n, k) un-normalised acquisition statistics in physical units, aligned by
    #: row with ``sample_ids``, and the name of each column.  Added for Module 4
    #: (ADR-016): population shift in a *named* physical quantity ("mean
    #: luminance fell 22%") is a statement an analyst can check against the
    #: imagery, while shift in a twice-normalised embedding coordinate is not.
    #: Optional, defaulting to an empty array, so a feature extractor that does
    #: not expose physical statistics degrades to NOT_ASSESSED for the marginal
    #: metric rather than breaking the contract.
    acquisition: np.ndarray = field(default_factory=lambda: np.zeros((0, 0), dtype=np.float64))
    acquisition_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.index = {sid: i for i, sid in enumerate(self.sample_ids)}

    @property
    def n(self) -> int:
        return len(self.sample_ids)

    def valid_rows(self) -> np.ndarray:
        return np.nonzero(self.valid)[0]


@dataclass
class ObjectFeatureSet:
    """Per-annotation crop features, for detection datasets."""

    keys: list[tuple[str, str]]       # (sample_id, annotation_id)
    labels: list[str]
    embeddings: np.ndarray
    contributors: list[str]

    @property
    def n(self) -> int:
        return len(self.keys)


def build_features(
    dataset: RawDataset,
    cfg: Config,
    *,
    with_objects: bool = True,
) -> tuple[FeatureSet, ObjectFeatureSet | None, list[IngestIssue]]:
    extractor = ClassicalFeatureExtractor(cfg.features)
    dim = extractor.dim

    sample_ids: list[str] = []
    embeddings = np.zeros((len(dataset.samples), dim), dtype=np.float32)
    p_codes = np.zeros(len(dataset.samples), dtype=np.uint64)
    a_codes = np.zeros(len(dataset.samples), dtype=np.uint64)
    d_codes = np.zeros(len(dataset.samples), dtype=np.uint64)
    valid = np.zeros(len(dataset.samples), dtype=bool)
    facts: dict[str, ImageFacts] = {}
    issues: list[IngestIssue] = []

    object_keys: list[tuple[str, str]] = []
    object_labels: list[str] = []
    object_vectors: list[np.ndarray] = []
    acquisition = np.zeros((len(dataset.samples), len(ACQUISITION_NAMES)), dtype=np.float64)

    for row, sample in enumerate(dataset.samples):
        sample_ids.append(sample.sample_id)
        fact, issue = measure_image(sample)
        facts[sample.sample_id] = fact
        if issue is not None:
            issues.append(issue)
        if not fact.readable:
            continue

        with Image.open(sample.abspath) as handle:
            image = handle.convert("RGB")

        embeddings[row], raw_blocks = extractor.extract_with_blocks(image)
        acquisition[row] = raw_blocks["acquisition"]
        p_codes[row] = phash(image, cfg.phash.dct_size, cfg.phash.hash_size)
        a_codes[row] = ahash(image)
        d_codes[row] = dhash(image)
        valid[row] = True

        if with_objects and sample.annotations:
            for annotation in sample.annotations:
                box = resolve_bbox(annotation.native, annotation.bbox, fact.width, fact.height)
                if box is None:
                    continue
                x1, y1, x2, y2 = (int(round(v)) for v in box)
                x1, y1 = max(0, x1), max(0, y1)
                x2, y2 = min(fact.width or 0, x2), min(fact.height or 0, y2)
                if x2 - x1 < MIN_CROP_SIDE or y2 - y1 < MIN_CROP_SIDE:
                    continue
                crop = image.crop((x1, y1, x2, y2))
                object_keys.append((sample.sample_id, annotation.annotation_id))
                object_labels.append(annotation.category)
                object_vectors.append(extractor.extract(crop))

    feature_set = FeatureSet(
        sample_ids=sample_ids,
        embeddings=embeddings,
        phash=p_codes,
        ahash=a_codes,
        dhash=d_codes,
        valid=valid,
        facts=facts,
        extractor=extractor.describe(),
        acquisition=acquisition,
        acquisition_names=ACQUISITION_NAMES,
    )
    log.info(
        "features: %d/%d samples decoded, %d object crops",
        int(valid.sum()), len(sample_ids), len(object_keys),
    )

    objects = None
    if object_keys:
        objects = ObjectFeatureSet(
            keys=object_keys,
            labels=object_labels,
            embeddings=np.vstack(object_vectors).astype(np.float32),
            contributors=[""] * len(object_keys),
        )
    return feature_set, objects, issues
