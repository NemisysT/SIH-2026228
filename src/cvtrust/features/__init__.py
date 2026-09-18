"""Feature extraction: perceptual hashes and image embeddings."""

from .base import EXTRACTORS, FeatureExtractor
from .classical import ClassicalFeatureExtractor
from .perceptual import ahash, dhash, hamming, hamming_pairs_within, phash, popcount
from .store import FeatureSet, ObjectFeatureSet, build_features
from .torch_backend import TorchFeatureExtractor

EXTRACTORS.add("classical", ClassicalFeatureExtractor)
EXTRACTORS.add("torch_cnn", TorchFeatureExtractor)

__all__ = [
    "EXTRACTORS", "FeatureExtractor", "ClassicalFeatureExtractor",
    "TorchFeatureExtractor", "FeatureSet", "ObjectFeatureSet", "build_features",
    "ahash", "dhash", "phash", "hamming", "hamming_pairs_within", "popcount",
]
