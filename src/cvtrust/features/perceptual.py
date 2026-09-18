"""Perceptual image hashes.

Three 64-bit hashes are implemented from first principles rather than pulled
from a third-party package.  Reasons: no additional dependency in an air-gapped
deployment, exact control over the transform (so the hash is reproducible
across machines and versions), and the ability to state precisely what each
hash is invariant to — which is what the near-duplicate finding has to justify
to an analyst.

======  ==========================================  ==================================
hash    construction                                 invariant to
======  ==========================================  ==================================
aHash   8x8 mean threshold                           uniform brightness, mild blur
dHash   8x9 horizontal gradient sign                 uniform brightness, mild contrast
pHash   32x32 DCT, 8x8 low band, median threshold    gamma, mild noise, re-encode, scale
======  ==========================================  ==================================

None of them is invariant to rotation, flip, crop or heavy geometric warping.
That is stated in the detector's ``limitations`` and is measured by the
adversarial test suite rather than assumed.

pHash is the primary signal because the DCT low band is the most robust of the
three to the re-encoding and mild photometric edits a near-duplicate flooding
adversary actually uses (Zauner, 2010, "Implementation and Benchmarking of
Perceptual Image Hash Functions").
"""

from __future__ import annotations

import numpy as np
from PIL import Image
from scipy.fft import dct

#: All hashes in this module are exactly 64 bits so they pack into one uint64
#: and Hamming distance becomes a single popcount.
HASH_BITS = 64

_HAS_BITWISE_COUNT = hasattr(np, "bitwise_count")
if not _HAS_BITWISE_COUNT:  # pragma: no cover - numpy >= 2.0 provides this
    _POPCOUNT16 = np.array(
        [bin(i).count("1") for i in range(1 << 16)], dtype=np.uint8
    )


def _to_gray(image: Image.Image, size: int) -> np.ndarray:
    """Deterministic grayscale resize.

    ``Image.Resampling.LANCZOS`` is fixed here rather than taken from config:
    a hash whose resampling filter can change is not a stable identifier.
    """
    return np.asarray(
        image.convert("L").resize((size, size), Image.Resampling.LANCZOS),
        dtype=np.float64,
    )


def _pack(bits: np.ndarray) -> np.uint64:
    """Pack 64 booleans into a uint64, most-significant bit first."""
    flat = bits.reshape(-1)
    if flat.size != HASH_BITS:
        raise ValueError(f"expected {HASH_BITS} bits, got {flat.size}")
    value = 0
    for bit in flat:
        value = (value << 1) | int(bool(bit))
    return np.uint64(value)


def ahash(image: Image.Image) -> np.uint64:
    gray = _to_gray(image, 8)
    return _pack(gray > gray.mean())


def dhash(image: Image.Image) -> np.uint64:
    gray = np.asarray(
        image.convert("L").resize((9, 8), Image.Resampling.LANCZOS), dtype=np.float64
    )
    return _pack(gray[:, 1:] > gray[:, :-1])


def phash(image: Image.Image, dct_size: int = 32, band: int = 8) -> np.uint64:
    """DCT-II low-band perceptual hash.

    The DC coefficient (0, 0) carries only mean brightness; including it would
    make the hash sensitive to exposure, which is precisely the edit we want to
    be blind to.  It is replaced by the band median so the bit count stays 64.
    """
    gray = _to_gray(image, dct_size)
    coefficients = dct(dct(gray, axis=0, norm="ortho"), axis=1, norm="ortho")
    low = coefficients[:band, :band].copy()
    without_dc = np.delete(low.reshape(-1), 0)
    median = float(np.median(without_dc))
    low[0, 0] = median
    return _pack(low > median)


def popcount(values: np.ndarray) -> np.ndarray:
    """Number of set bits per element of a uint64 array."""
    if _HAS_BITWISE_COUNT:
        return np.bitwise_count(values).astype(np.uint8)
    # pragma: no cover - fallback for numpy < 2.0
    out = np.zeros(values.shape, dtype=np.uint8)
    work = values.copy()
    for _ in range(4):
        out += _POPCOUNT16[(work & np.uint64(0xFFFF)).astype(np.uint32)]
        work >>= np.uint64(16)
    return out


def hamming(a: np.uint64, b: np.uint64) -> int:
    return int(popcount(np.array([a ^ b], dtype=np.uint64))[0])


def hamming_pairs_within(
    codes: np.ndarray, threshold: int, *, block: int = 2048
) -> list[tuple[int, int, int]]:
    """All index pairs ``(i, j, distance)`` with ``i < j`` and distance <= threshold.

    Exact, not approximate.  The comparison is blocked so that peak memory is
    ``block * n`` bytes rather than ``n^2``: an exhaustive scan is affordable at
    the dataset sizes this tool targets, and an exact answer is worth far more
    in an assurance context than the constant factor an LSH prefilter would
    save.  The caller is responsible for refusing datasets above
    ``near_duplicate.max_pairwise_samples`` and reporting PARTIAL coverage.
    """
    n = codes.shape[0]
    pairs: list[tuple[int, int, int]] = []
    for start in range(0, n, block):
        stop = min(start + block, n)
        chunk = codes[start:stop, None] ^ codes[None, :]
        distances = popcount(chunk)
        rows, cols = np.nonzero(distances <= threshold)
        for row, col in zip(rows, cols):
            i = start + int(row)
            j = int(col)
            if i < j:
                pairs.append((i, j, int(distances[row, col])))
    pairs.sort()
    return pairs
