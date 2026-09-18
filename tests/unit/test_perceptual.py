"""Perceptual hash properties.

These tests state, and therefore pin, exactly what the near-duplicate detector's
``limitations`` claim: what the hash survives and what it does not.
"""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from cvtrust.features.perceptual import (
    HASH_BITS,
    ahash,
    dhash,
    hamming,
    hamming_pairs_within,
    phash,
    popcount,
)


@pytest.fixture
def image() -> Image.Image:
    """A structured image; pure noise has an unrepresentatively fragile hash."""
    rng = np.random.default_rng(7)
    canvas = np.zeros((128, 128, 3), dtype=np.float64)
    yy, xx = np.mgrid[0:128, 0:128]
    canvas[..., 0] = 0.3 + 0.3 * np.sin(xx / 9.0)
    canvas[..., 1] = 0.4 + 0.3 * np.cos(yy / 13.0)
    canvas[..., 2] = 0.5
    canvas[30:70, 40:100] = [0.85, 0.85, 0.8]
    canvas = np.clip(canvas + rng.normal(0, 0.01, canvas.shape), 0, 1)
    return Image.fromarray((canvas * 255).astype(np.uint8))


def _jpeg(image: Image.Image, quality: int) -> Image.Image:
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    return Image.open(buffer).convert("RGB")


def _scaled(image: Image.Image, factor: float) -> Image.Image:
    array = np.clip(np.asarray(image, dtype=np.float64) / 255.0 * factor, 0, 1)
    return Image.fromarray((array * 255).astype(np.uint8))


def test_hashes_are_deterministic(image):
    assert phash(image) == phash(image)
    assert ahash(image) == ahash(image)
    assert dhash(image) == dhash(image)


def test_phash_survives_jpeg_recompression(image):
    assert hamming(phash(image), phash(_jpeg(image, 75))) <= 4


def test_phash_survives_exposure_change(image):
    """The DC coefficient is excluded precisely so this holds."""
    assert hamming(phash(image), phash(_scaled(image, 1.12))) <= 4
    assert hamming(phash(image), phash(_scaled(image, 0.88))) <= 4


def test_phash_survives_downscale_and_back(image):
    small = image.resize((64, 64), Image.Resampling.LANCZOS)
    restored = small.resize((128, 128), Image.Resampling.LANCZOS)
    assert hamming(phash(image), phash(restored)) <= 6


def test_phash_separates_genuinely_different_content(image):
    rng = np.random.default_rng(99)
    other = Image.fromarray(rng.integers(0, 255, (128, 128, 3), dtype=np.uint8))
    assert hamming(phash(image), phash(other)) > 8


def test_phash_is_not_rotation_invariant_as_documented(image):
    """The detector claims no rotation invariance; this pins that claim."""
    rotated = image.rotate(90, expand=False)
    assert hamming(phash(image), phash(rotated)) > 8


def test_popcount_matches_python_bit_count():
    values = np.array([0, 1, 2**63, 2**64 - 1, 123456789], dtype=np.uint64)
    assert list(popcount(values)) == [int(v).bit_count() for v in values]


def test_hamming_distance_bounds(image):
    code = phash(image)
    assert hamming(code, code) == 0
    assert hamming(code, np.uint64(~np.uint64(code))) == HASH_BITS


def test_pairwise_search_is_exact_and_symmetric():
    codes = np.array([0b1111, 0b1110, 0b1100, 0xFFFFFFFFFFFFFFFF], dtype=np.uint64)

    assert hamming_pairs_within(codes, threshold=0) == []
    # 1111~1110 and 1110~1100 differ by one bit; 1111~1100 differs by two.
    assert hamming_pairs_within(codes, threshold=1) == [(0, 1, 1), (1, 2, 1)]

    within_two = hamming_pairs_within(codes, threshold=2)
    assert (0, 2, 2) in within_two
    assert all(i < j for i, j, _ in within_two)
    # The all-ones code is 60+ bits away from the rest and never pairs.
    assert not any(3 in (i, j) for i, j, _ in within_two)


def test_pairwise_search_blocking_does_not_change_results():
    rng = np.random.default_rng(3)
    codes = rng.integers(0, 2**63, 300, dtype=np.uint64)
    codes[100] = codes[7]
    assert hamming_pairs_within(codes, 4, block=16) == hamming_pairs_within(
        codes, 4, block=4096
    )
