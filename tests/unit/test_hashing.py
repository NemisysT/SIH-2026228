"""File and content hashing."""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from cvtrust.core.hashing import (
    pixel_sha256,
    sha256_bytes,
    sha256_canonical,
    sha256_file,
    short,
)


def test_file_hash_matches_bytes_hash(tmp_path):
    path = tmp_path / "f.bin"
    payload = b"integrity" * 5000
    path.write_bytes(payload)
    assert sha256_file(path) == sha256_bytes(payload)


def test_file_hash_changes_on_a_single_bit(tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(b"\x00" * 1024)
    before = sha256_file(path)
    data = bytearray(path.read_bytes())
    data[512] ^= 0x01
    path.write_bytes(bytes(data))
    assert sha256_file(path) != before


def test_pixel_digest_ignores_the_container_but_not_the_pixels(tmp_path):
    rng = np.random.default_rng(0)
    array = rng.integers(0, 255, (48, 64, 3), dtype=np.uint8)
    image = Image.fromarray(array)

    png, bmp = tmp_path / "a.png", tmp_path / "a.bmp"
    image.save(png)
    image.save(bmp)

    # Different files ...
    assert sha256_file(png) != sha256_file(bmp)
    # ... identical content.
    with Image.open(png) as a, Image.open(bmp) as b:
        left = pixel_sha256(np.asarray(a.convert("RGB")), "RGB")
        right = pixel_sha256(np.asarray(b.convert("RGB")), "RGB")
    assert left == right


def test_pixel_digest_binds_the_shape():
    array = np.zeros((4, 6, 3), dtype=np.uint8)
    reshaped = array.reshape(6, 4, 3)
    assert pixel_sha256(array, "RGB") != pixel_sha256(reshaped, "RGB")


def test_pixel_digest_binds_the_mode():
    array = np.zeros((4, 4, 3), dtype=np.uint8)
    assert pixel_sha256(array, "RGB") != pixel_sha256(array, "BGR")


def test_canonical_hash_is_insensitive_to_key_order():
    assert sha256_canonical({"a": 1, "b": 2}) == sha256_canonical({"b": 2, "a": 1})


def test_short_truncates_without_altering_the_prefix():
    digest = sha256_bytes(b"x")
    assert short(digest, 12) == digest[:12]
