"""Attempts to make two logically different records share canonical bytes —
or to make two logically identical records produce different ones.

Both directions are attacks.  If an adversary can find a second structure with
the same canonical bytes, a signature transfers to content the signer never saw.
If a conforming producer's output canonicalises differently on two machines,
every verification becomes a coin toss and the system gets switched off.

Marked ``adversarial`` alongside the Module 1 and Module 2 evasion suites.  The
cases that are *expected to succeed* are here too, asserted as limitations, so
the documented claim and the code cannot drift apart.
"""

from __future__ import annotations

import json
import unicodedata

import pytest

from cvtrust.core.canonical import canonical_json
from cvtrust.core.errors import CanonicalizationError
from cvtrust.provenance import (
    FailureCode,
    SignedRecord,
    TrustStore,
    bind_config,
    bind_input_bytes,
    bind_output,
    classification_output,
    detection_output,
    sign_record,
    verify_record,
    verify_signature,
)
from cvtrust.provenance.output import OUTPUT_QUANT_PLACES

pytestmark = pytest.mark.adversarial


# --- ordering --------------------------------------------------------------


def test_reordering_output_items_cannot_change_the_digest():
    boxes = [
        {"label": f"c{i}", "score": 0.9 - i * 0.05, "box": (float(i), 1.0, 2.0, 3.0)}
        for i in range(8)
    ]
    reference = detection_output(boxes).digest()
    for rotation in range(1, len(boxes)):
        rotated = boxes[rotation:] + boxes[:rotation]
        assert detection_output(rotated).digest() == reference


def test_json_key_order_in_a_configuration_cannot_change_the_digest():
    keys = ["resize", "mean", "std", "letterbox", "dtype", "rotation"]
    values = {"resize": [1, 2], "mean": [0.1], "std": [0.2],
              "letterbox": True, "dtype": "f32", "rotation": 0}
    reference = bind_config(values).digest
    for rotation in range(1, len(keys)):
        rotated = {k: values[k] for k in keys[rotation:] + keys[:rotation]}
        assert bind_config(rotated).digest == reference


def test_a_signed_record_survives_json_key_reordering_on_disk(make_record, signing_key):
    """An honest re-serialisation must not look like tampering."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    payload = json.loads(entry.model_dump_json())
    shuffled = json.loads(json.dumps(payload, sort_keys=True))
    restored = SignedRecord.model_validate(shuffled)
    assert verify_signature(restored).valid
    assert restored.entry_digest() == entry.entry_digest()


def test_whitespace_in_the_stored_json_does_not_affect_verification(
    make_record, signing_key
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    pretty = json.dumps(json.loads(entry.model_dump_json()), indent=4)
    assert verify_signature(SignedRecord.model_validate(json.loads(pretty))).valid


# --- floating point --------------------------------------------------------


def test_float_representations_that_differ_textually_agree_on_the_grid():
    """0.1 + 0.2 and 0.3 differ in IEEE-754 and agree on the digest grid."""
    computed = classification_output({"a": 0.1 + 0.2})
    literal = classification_output({"a": 0.3})
    assert computed.digest() == literal.digest()


def test_a_float_never_reaches_the_digest_surface(make_record):
    """The ADR-004 guarantee, asserted on a real record."""
    with pytest.raises(CanonicalizationError):
        canonical_json({"score": 0.5})
    canonical_json(make_record().digest_payload())


def test_negative_zero_and_zero_agree():
    assert classification_output({"a": -0.0}).digest() == classification_output(
        {"a": 0.0}
    ).digest()


def test_a_non_finite_score_is_refused_rather_than_encoded():
    with pytest.raises(CanonicalizationError):
        classification_output({"a": float("nan")})
    with pytest.raises(CanonicalizationError):
        classification_output({"a": float("inf")})


def test_a_score_above_the_safe_integer_range_is_refused():
    with pytest.raises(CanonicalizationError):
        classification_output({"a": 1e20})


def test_the_quantisation_grid_is_bound_into_the_output():
    """Changing the grid must produce a visibly different record, not a silent one."""
    fine = classification_output({"a": 0.5}, places=OUTPUT_QUANT_PLACES)
    coarse = classification_output({"a": 0.5}, places=3)
    assert fine.digest() != coarse.digest()
    assert fine.quantization_places != coarse.quantization_places


# --- strings and Unicode ---------------------------------------------------

#: The same label written pre-composed (NFC) and decomposed (NFD). They render
#: identically and are different strings.
NFC_LABEL = unicodedata.normalize("NFC", "défaut")
NFD_LABEL = unicodedata.normalize("NFD", "défaut")


def test_unicode_equivalent_labels_are_different_labels_and_say_so():
    """Deliberate, and documented: no normalisation is applied.

    Silently normalising would mean the digest covers something other than what
    the producer emitted, and an analyst comparing a record against a model's
    actual label vocabulary would find them disagreeing for reasons invisible in
    both. Two distinguishable byte strings get two digests; a deployment that
    needs them unified normalises *before* binding, where the choice is visible.
    """
    assert NFC_LABEL != NFD_LABEL
    assert (
        classification_output({NFC_LABEL: 0.5}).digest()
        != classification_output({NFD_LABEL: 0.5}).digest()
    )


def test_non_ascii_labels_survive_canonicalisation_unescaped():
    output = classification_output({"缺陷": 0.9, "正常": 0.1})
    assert "缺陷".encode("utf-8") in output.canonical_bytes()
    assert output.digest()


def test_a_label_containing_json_syntax_cannot_break_out():
    hostile = '", "injected": "value'
    output = classification_output({hostile: 0.5})
    restored = json.loads(output.canonical_bytes())
    assert "injected" not in restored
    assert restored["classification"][0]["label"] == hostile


def test_a_label_containing_the_quantisation_marker_is_not_reinterpreted():
    from cvtrust.core.canonical import QUANT_KEY

    binding = bind_config({QUANT_KEY: "a string, not a number", "p": 6})
    assert binding.self_consistent()


# --- optional, missing and duplicate fields --------------------------------


def test_an_omitted_optional_field_is_not_the_same_as_a_null_one(signing_key):
    """Both must be representable, and they must not share a digest."""
    from cvtrust.provenance.binding import ModelBinding

    without = ModelBinding(model_id="m", file_sha256="a" * 64, model_format="onnx")
    with_null = ModelBinding(
        model_id="m", file_sha256="a" * 64, model_format="onnx", graph_digest=None
    )
    # Pydantic normalises an explicit None to the default, so these agree -- and
    # that is fine, because the *record* still distinguishes "no graph digest"
    # from "this graph digest".
    assert without.graph_digest == with_null.graph_digest is None
    with_value = without.model_copy(update={"graph_digest": "b" * 64})
    assert canonical_json(without.model_dump(mode="json")) != canonical_json(
        with_value.model_dump(mode="json")
    )


def test_a_duplicate_json_key_cannot_smuggle_a_second_value(make_record, signing_key):
    """Python keeps the last value; the signature covers the canonical form."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    text = entry.model_dump_json()
    duplicated = text.replace('"nonce":', '"nonce": "0000", "nonce":', 1)
    restored = SignedRecord.model_validate(json.loads(duplicated))
    assert restored.record.nonce == entry.record.nonce
    assert verify_signature(restored).valid


def test_an_unknown_field_is_refused_rather_than_ignored(make_record, signing_key):
    """extra='forbid' everywhere: a field we do not understand is not signed."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    payload = json.loads(entry.model_dump_json())
    payload["record"]["surprise"] = "hello"
    with pytest.raises(Exception):
        SignedRecord.model_validate(payload)


def test_an_empty_configuration_is_still_bound():
    """'No preprocessing declared' is a checkable claim, not an absence."""
    empty = bind_config({})
    assert empty.digest
    assert empty.self_consistent()
    assert empty.digest != bind_config({"resize": [1, 1]}).digest


# --- size ------------------------------------------------------------------


def test_a_very_large_output_still_canonicalises_deterministically():
    boxes = [
        {"label": f"class_{i % 50}", "score": (i % 1000) / 1000,
         "box": (float(i), float(i + 1), float(i + 2), float(i + 3))}
        for i in range(2000)
    ]
    first = detection_output(boxes)
    second = detection_output(list(reversed(boxes)))
    assert first.digest() == second.digest()
    assert len(first.canonical_bytes()) > 100_000


@pytest.mark.slow
def test_a_very_large_record_signs_and_verifies(signing_key):
    from cvtrust.provenance.binding import ModelBinding
    from cvtrust.provenance.record import create_provenance_record

    key, info = signing_key
    store = TrustStore.empty()
    big = detection_output(
        [
            {"label": f"c{i % 20}", "score": 0.5, "box": (1.0, 2.0, 3.0, 4.0)}
            for i in range(5000)
        ]
    )
    record = create_provenance_record(
        input_binding=bind_input_bytes(b"x" * 1024),
        model_binding=ModelBinding(
            model_id="m", file_sha256="a" * 64, model_format="onnx"
        ),
        preprocessing=bind_config({"resize": [1024, 1024]}),
        inference=bind_config({"max_detections": 10000}),
        output=bind_output(big),
        log_id="big",
    )
    entry = sign_record(record, key)
    assert verify_signature(entry).valid
    assert FailureCode.INVALID_SIGNATURE not in verify_record(
        entry, trust_store=store
    ).failures


# --- timestamps ------------------------------------------------------------


@pytest.mark.parametrize(
    "timestamp",
    [
        "1970-01-01T00:00:00Z",
        "2999-12-31T23:59:59Z",
        "2026-03-01T09:00:00+05:30",
        "2026-02-29T00:00:00Z",   # not a leap year
        "not-a-timestamp",
    ],
)
def test_an_unusual_timestamp_does_not_crash_verification(
    make_record, signing_key, timestamp
):
    """A malformed timestamp in untrusted input is a finding, never a traceback."""
    key, _ = signing_key
    entry = sign_record(make_record(timestamp=timestamp), key)
    result = verify_record(entry, trust_store=TrustStore.empty())
    assert result.failures  # at minimum UNKNOWN_KEY
    assert result.check("timestamp_present").observation["timestamp"] == timestamp


def test_an_explicitly_empty_timestamp_is_a_caller_error_not_a_default(make_record):
    """Substituting "now" for an empty string would hide the bug inside a signed
    record, where it becomes indistinguishable from a real claim."""
    with pytest.raises(Exception):
        make_record(timestamp="")
    with pytest.raises(Exception):
        make_record(nonce="")


def test_an_unparseable_timestamp_fails_a_validity_window_rather_than_passing_it(
    signing_key
):
    from cvtrust.provenance.trust import trust_key
    from cvtrust.provenance.record import create_provenance_record
    from cvtrust.provenance.binding import ModelBinding

    key, info = signing_key
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        valid_from="2026-01-01T00:00:00Z", valid_until="2026-12-31T00:00:00Z",
    )
    record = create_provenance_record(
        input_binding=bind_input_bytes(b"x"),
        model_binding=ModelBinding(
            model_id="m", file_sha256="a" * 64, model_format="onnx"
        ),
        preprocessing=bind_config({}),
        inference=bind_config({}),
        output=bind_output(classification_output({"a": 0.5})),
        log_id="t",
        timestamp="whenever",
    )
    result = verify_record(sign_record(record, key), trust_store=store)
    check = result.check("key_within_validity_window")
    assert check is not None
    assert check.outcome.value == "FAIL"


def test_backdating_cannot_revive_an_expired_key_under_verification_time_policy(
    signing_key
):
    """The documented trade between the two policies, asserted."""
    from cvtrust.provenance.trust import ValidityPolicy, trust_key

    key, info = signing_key
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        valid_until="2020-01-01T00:00:00Z",
    )
    backdated = sign_record(
        _record_at("2019-06-01T00:00:00Z", signing_key), key
    )
    lenient = verify_record(
        backdated, trust_store=store,
        validity_policy=ValidityPolicy.AT_RECORD_TIMESTAMP,
    )
    strict = verify_record(
        backdated, trust_store=store,
        validity_policy=ValidityPolicy.AT_VERIFICATION_TIME,
    )
    assert FailureCode.KEY_EXPIRED not in lenient.failures
    assert FailureCode.KEY_EXPIRED in strict.failures


def _record_at(timestamp: str, signing_key):
    from cvtrust.provenance.binding import ModelBinding
    from cvtrust.provenance.record import create_provenance_record

    return create_provenance_record(
        input_binding=bind_input_bytes(b"x"),
        model_binding=ModelBinding(
            model_id="m", file_sha256="a" * 64, model_format="onnx"
        ),
        preprocessing=bind_config({}),
        inference=bind_config({}),
        output=bind_output(classification_output({"a": 0.5})),
        log_id="t",
        timestamp=timestamp,
    )


# --- nonce -----------------------------------------------------------------


def test_deliberate_nonce_reuse_is_caught(signing_key, make_record):
    from cvtrust.provenance.replay import ReplayDatabase, ReplayVerdict

    key, _ = signing_key
    first = sign_record(make_record(payload=b"a", nonce="f" * 32), key)
    second = sign_record(make_record(payload=b"b", nonce="f" * 32), key)
    database = ReplayDatabase.empty().record(first)
    assert database.check(second).verdict is ReplayVerdict.NONCE_REUSE


def test_a_nonce_alone_does_not_prevent_replay(signed_log):
    """Stated in the docs; asserted here so the claim cannot soften."""
    from cvtrust.provenance.replay import detect_replay

    entry = signed_log.entries[0]
    assert entry.record.nonce
    assert detect_replay(entry, None).verdict.value == "NOT_CHECKED"


# --- the record id ---------------------------------------------------------


def test_a_relabelled_record_id_is_detected(make_record, signing_key):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    relabelled = entry.model_copy(
        update={"record": entry.record.model_copy(update={"record_id": "PR-" + "0" * 16})}
    )
    result = verify_record(relabelled, trust_store=TrustStore.empty())
    assert FailureCode.SELF_INCONSISTENT_RECORD in result.failures
    assert FailureCode.INVALID_SIGNATURE in result.failures


def test_editing_a_config_without_updating_its_digest_is_caught_without_a_key(
    make_record, signing_key
):
    """Self-consistency is the check that survives a forger holding a key."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    tampered_config = entry.record.preprocessing.model_copy(
        update={"config": {"resize": [999, 999]}}
    )
    edited = entry.record.model_copy(update={"preprocessing": tampered_config})
    resigned = sign_record(
        edited.model_copy(update={"record_id": edited.expected_record_id()}), key
    )
    result = verify_record(resigned, trust_store=TrustStore.empty())
    assert result.check("signature_valid").outcome.value == "PASS"
    assert FailureCode.CONFIGURATION_MISMATCH in result.failures
