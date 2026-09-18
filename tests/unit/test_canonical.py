"""Canonical serialisation is the base of every digest, so it is tested hardest."""

from __future__ import annotations

import math

import pytest

from cvtrust.core.canonical import (
    MAX_SAFE_INT,
    canonical_json,
    digest_safe,
    quantize,
)
from cvtrust.core.errors import CanonicalizationError


def test_key_order_is_irrelevant_to_the_encoding():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_encoding_has_no_insignificant_whitespace():
    assert canonical_json({"a": 1, "b": [1, 2]}) == b'{"a":1,"b":[1,2]}'


def test_nested_structures_are_ordered_recursively():
    left = {"x": {"z": 1, "y": [{"b": 2, "a": 1}]}}
    right = {"x": {"y": [{"a": 1, "b": 2}], "z": 1}}
    assert canonical_json(left) == canonical_json(right)


def test_unicode_is_emitted_as_utf8_not_escaped():
    assert canonical_json({"k": "सत्य"}) == '{"k":"सत्य"}'.encode("utf-8")


def test_floats_are_rejected_on_the_digest_path():
    with pytest.raises(CanonicalizationError, match="float"):
        canonical_json({"score": 0.5})


def test_floats_are_permitted_when_explicitly_opted_into():
    assert canonical_json({"score": 0.5}, float_mode="repr") == b'{"score":0.5}'


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_floats_are_always_rejected(value):
    with pytest.raises(CanonicalizationError):
        canonical_json({"v": value}, float_mode="repr")


def test_non_string_keys_are_rejected_rather_than_coerced():
    with pytest.raises(CanonicalizationError, match="non-string object key"):
        canonical_json({1: "a"})


def test_unsupported_types_are_rejected_rather_than_stringified():
    with pytest.raises(CanonicalizationError, match="unsupported type"):
        canonical_json({"v": {1, 2}})


def test_integers_beyond_double_precision_are_rejected():
    canonical_json({"v": MAX_SAFE_INT})
    with pytest.raises(CanonicalizationError, match="safe range"):
        canonical_json({"v": MAX_SAFE_INT + 1})


def test_tuples_and_lists_encode_identically():
    assert canonical_json({"v": (1, 2)}) == canonical_json({"v": [1, 2]})


def test_quantize_uses_round_half_even_and_is_platform_stable():
    assert quantize(0.9134, 3) == 913
    assert quantize(-0.0005, 3) == 0    # half-even rounds .5 to the even side
    assert quantize(1.0, 6) == 1_000_000


def test_quantize_rejects_non_finite():
    with pytest.raises(CanonicalizationError):
        quantize(math.inf)


def test_digest_safe_makes_float_bearing_structures_hashable():
    payload = {"threshold": 0.9, "nested": [{"x": 0.125}], "name": "k", "n": 3}
    encoded = canonical_json(digest_safe(payload))
    assert b"0.9" not in encoded
    assert canonical_json(digest_safe(payload)) == encoded


def test_digest_safe_is_stable_across_equal_floats_written_differently():
    assert digest_safe({"v": 0.1 + 0.2}) == digest_safe({"v": 0.30000000000000004})
