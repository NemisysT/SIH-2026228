"""Canonicalisation, digests and record identity.

These are the tests that have to hold before any of the others mean anything: a
signature over bytes that are not canonical is a signature over an accident.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from cvtrust.core.canonical import canonical_json, digest_safe, undigest_safe
from cvtrust.core.errors import CanonicalizationError, ProvenanceError
from cvtrust.provenance.binding import (
    ModelBinding,
    bind_config,
    bind_input,
    bind_input_bytes,
    bind_output,
    normalized_tensor_digest,
)
from cvtrust.provenance.output import (
    OUTPUT_QUANT_PLACES,
    OutputTask,
    classification_output,
    detection_output,
    embedding_output,
    keypoint_output,
    mask_digest,
    raw_output,
    segmentation_output,
)
from cvtrust.provenance.record import (
    PROVENANCE_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    SignedRecord,
    derive_record_id,
    new_nonce,
)


# --- canonical output ------------------------------------------------------


def test_equivalent_classification_outputs_produce_identical_bytes():
    """Key order in the caller's dict must not reach the digest."""
    first = classification_output({"defect": 0.91, "clean": 0.09})
    second = classification_output({"clean": 0.09, "defect": 0.91})
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest() == second.digest()


def test_detection_order_does_not_change_the_digest():
    """Detections are a set: an engine emitting them in another order agrees."""
    boxes = [
        {"label": "a", "score": 0.9, "box": (1.0, 2.0, 3.0, 4.0)},
        {"label": "b", "score": 0.5, "box": (5.0, 6.0, 7.0, 8.0)},
        {"label": "c", "score": 0.7, "box": (9.0, 10.0, 11.0, 12.0)},
    ]
    forward = detection_output(boxes)
    backward = detection_output(list(reversed(boxes)))
    assert forward.digest() == backward.digest()


def test_tied_scores_still_produce_a_total_order():
    """Sorting by score alone would leave ties in emission order."""
    tied = [
        {"label": "b", "score": 0.5, "box": (1.0, 1.0, 2.0, 2.0)},
        {"label": "a", "score": 0.5, "box": (3.0, 3.0, 4.0, 4.0)},
    ]
    assert detection_output(tied).digest() == detection_output(
        list(reversed(tied))
    ).digest()


def test_a_changed_score_changes_the_digest():
    base = classification_output({"defect": 0.910000, "clean": 0.09})
    moved = classification_output({"defect": 0.910001, "clean": 0.09})
    assert base.digest() != moved.digest()


def test_scores_below_the_quantisation_grid_are_indistinguishable_as_documented():
    """The grid is a stated limitation, not a hidden one."""
    base = classification_output({"defect": 0.9100000})
    nudged = classification_output({"defect": 0.91000000001})
    assert base.digest() == nudged.digest()
    assert base.quantization_places == OUTPUT_QUANT_PLACES


def test_keypoints_are_ordered_by_index_not_by_score():
    """A keypoint's index is semantic; index 0 is not interchangeable with 3."""
    output = keypoint_output(
        [
            {"index": 2, "name": "elbow", "x": 3.0, "y": 4.0, "score": 0.99},
            {"index": 0, "name": "nose", "x": 1.0, "y": 2.0, "score": 0.10},
        ]
    )
    payload = output.canonical_payload()
    assert [item["index"] for item in payload["keypoints"]] == [0, 2]


def test_duplicate_keypoint_indices_are_refused():
    with pytest.raises(ProvenanceError, match="duplicate keypoint indices"):
        keypoint_output(
            [{"index": 0, "x": 1.0, "y": 1.0}, {"index": 0, "x": 2.0, "y": 2.0}]
        )


def test_the_label_vocabulary_is_bound():
    """Swapping two vocabulary entries changes every prediction."""
    first = classification_output([0.9, 0.1], labels=("defect", "clean"))
    swapped = classification_output([0.9, 0.1], labels=("clean", "defect"))
    assert first.digest() != swapped.digest()


def test_a_mismatched_vocabulary_is_refused_rather_than_truncated():
    with pytest.raises(ProvenanceError, match="label vocabulary"):
        classification_output([0.9, 0.1, 0.0], labels=("a", "b"))


def test_a_mask_digest_binds_shape_and_label_map():
    mask = np.zeros((4, 4), dtype=np.uint8)
    plain = mask_digest(mask)
    reshaped = mask_digest(mask.reshape(2, 8))
    relabelled = mask_digest(mask, label_map=("background", "defect"))
    assert len({plain, reshaped, relabelled}) == 3


def test_segmentation_binds_the_mask_by_digest_not_by_value():
    mask = np.arange(16, dtype=np.uint8).reshape(4, 4)
    output = segmentation_output([{"name": "m", "array": mask}])
    assert output.task is OutputTask.SEGMENTATION
    assert output.masks[0].digest == mask_digest(mask)
    # The buffer itself is not in the record.
    assert b"AAAA" not in output.canonical_bytes()


def test_an_embedding_is_quantised_so_storage_dtype_does_not_matter():
    vector = np.array([0.125, 0.25, 0.5], dtype=np.float32)
    assert embedding_digest_equal(vector)


def embedding_digest_equal(vector: np.ndarray) -> bool:
    as32 = embedding_output(vector.astype(np.float32))
    as64 = embedding_output(vector.astype(np.float64))
    return as32.embedding_digest == as64.embedding_digest


def test_a_non_finite_embedding_is_refused_rather_than_hashed():
    with pytest.raises(ProvenanceError, match="non-finite"):
        embedding_output(np.array([1.0, np.nan]))


def test_a_raw_output_is_named_raw_so_the_verifier_knows_it_is_unstructured():
    output = raw_output({"anything": [1, 2, 3], "threshold": 0.5})
    assert output.task is OutputTask.RAW
    assert output.digest()


# --- configuration binding -------------------------------------------------


def test_configuration_binding_is_self_consistent():
    binding = bind_config({"resize": [640, 640], "mean": [0.485, 0.456, 0.406]})
    assert binding.self_consistent()
    assert binding.recompute_digest() == binding.digest


def test_configuration_is_stored_float_free_and_rebuilt_only_for_display():
    binding = bind_config({"threshold": 0.25})
    # Stored digest-safe, so the whole record canonicalises in reject mode.
    canonical_json(dict(binding.config))
    assert binding.readable() == {"threshold": 0.25}


def test_changing_any_bound_configuration_value_changes_the_digest():
    base = bind_config({"resize": [640, 640], "letterbox": True, "threshold": 0.25})
    for change in (
        {"resize": [640, 641], "letterbox": True, "threshold": 0.25},
        {"resize": [640, 640], "letterbox": False, "threshold": 0.25},
        {"resize": [640, 640], "letterbox": True, "threshold": 0.26},
    ):
        assert bind_config(change).digest != base.digest


def test_configuration_key_order_does_not_change_the_digest():
    first = bind_config({"a": 1, "b": 2, "c": 3})
    second = bind_config({"c": 3, "b": 2, "a": 1})
    assert first.digest == second.digest


def test_an_unrepresentable_configuration_value_is_refused_not_stringified():
    with pytest.raises(ProvenanceError, match="cannot be canonicalised"):
        bind_config({"callback": object()})


# --- input binding ---------------------------------------------------------


def test_raw_and_normalised_input_digests_are_distinct_fields():
    binding = bind_input_bytes(
        b"raw-bytes", normalized_digest="d" * 64, locator="x.png"
    )
    assert binding.raw_input_digest != binding.normalized_input_digest
    assert binding.normalized_input_digest == "d" * 64


def test_an_input_binding_uses_content_not_the_filename(tmp_path):
    first = tmp_path / "alpha.png"
    second = tmp_path / "beta.png"
    first.write_bytes(b"identical")
    second.write_bytes(b"identical")
    assert bind_input(first).raw_input_digest == bind_input(second).raw_input_digest


def test_a_missing_input_artifact_is_an_error_not_a_null_digest(tmp_path):
    with pytest.raises(ProvenanceError, match="input artifact not found"):
        bind_input(tmp_path / "absent.png")


def test_a_normalised_tensor_digest_is_independent_of_storage_dtype():
    tensor = np.array([[0.5, 0.25], [0.125, 1.0]])
    assert normalized_tensor_digest(
        tensor.astype(np.float32)
    ) == normalized_tensor_digest(tensor.astype(np.float64))


def test_a_normalised_tensor_digest_binds_shape():
    flat = np.arange(8, dtype=np.float64) / 8
    assert normalized_tensor_digest(flat) != normalized_tensor_digest(flat.reshape(2, 4))


# --- record identity -------------------------------------------------------


def test_a_record_id_is_derived_from_content(make_record):
    record = make_record()
    assert record.record_id == derive_record_id(record.record_digest())
    assert record.record_id_consistent()


def test_changing_any_bound_field_changes_the_record_id(make_record):
    base = make_record()
    for kwargs in (
        {"payload": b"different-image"},
        {"scores": {"defect": 0.8, "clean": 0.2}},
        {"preprocessing": {"resize": [64, 64]}},
        {"inference": {"threshold": 0.9}},
        {"log_id": "another-log"},
    ):
        assert make_record(**kwargs).record_id != base.record_id


def test_a_record_id_ignores_nothing_that_is_in_the_signature(make_record):
    """Everything in canonical_bytes is inside the signature, id included."""
    record = make_record()
    assert record.record_id.encode() in record.canonical_bytes()


def test_the_record_digest_surface_is_float_free(make_record):
    """A float anywhere on the digest path would be a signature bug later."""
    payload = make_record().digest_payload()
    canonical_json(payload)  # raises on float in reject mode

    def _walk(value):
        if isinstance(value, float):
            raise AssertionError("float on the digest surface")
        if isinstance(value, dict):
            for item in value.values():
                _walk(item)
        if isinstance(value, list):
            for item in value:
                _walk(item)

    _walk(payload)


def test_entry_digest_covers_the_signature_not_only_the_payload(
    make_record, signing_key
):
    from cvtrust.provenance.signing import sign_record

    key, _ = signing_key
    record = make_record()
    unsigned = SignedRecord(record=record)
    signed = sign_record(record, key)
    assert unsigned.entry_digest() != signed.entry_digest()


def test_two_supported_schema_versions_are_an_explicit_set():
    assert PROVENANCE_SCHEMA_VERSION in SUPPORTED_SCHEMA_VERSIONS
    assert "9.9" not in SUPPORTED_SCHEMA_VERSIONS


def test_a_subject_key_is_not_a_record_identity(make_record):
    """The same subject processed twice is two records, one subject."""
    first = make_record(sequence_number=0)
    second = make_record(sequence_number=1, previous_record_digest="a" * 64)
    assert first.subject_key() == second.subject_key()
    assert first.record_id != second.record_id


# --- nonce -----------------------------------------------------------------


def test_nonces_are_128_bit_and_do_not_repeat_across_a_large_draw():
    drawn = {new_nonce() for _ in range(2000)}
    assert len(drawn) == 2000
    assert all(len(nonce) == 32 for nonce in drawn)
    bytes.fromhex(next(iter(drawn)))


# --- the canonical helper Module 3 added -----------------------------------


def test_undigest_safe_inverts_digest_safe_for_display():
    original = {"threshold": 0.25, "nested": {"values": [0.5, 1.0]}, "flag": True}
    assert undigest_safe(digest_safe(original)) == original


def test_undigest_safe_leaves_a_lookalike_mapping_alone():
    """A user dict that happens to have the marker keys is not a number."""
    value = {"$q": "not-an-int", "p": 6}
    assert undigest_safe(value) == value


def test_canonical_json_still_rejects_floats_after_module_3():
    with pytest.raises(CanonicalizationError):
        canonical_json({"score": 0.5})


def test_a_signed_record_round_trips_through_json(make_record, signing_key):
    from cvtrust.provenance.signing import sign_record, verify_signature

    key, _ = signing_key
    entry = sign_record(make_record(), key)
    restored = SignedRecord.model_validate(json.loads(entry.model_dump_json()))
    assert restored.entry_digest() == entry.entry_digest()
    assert verify_signature(restored).valid


def test_binding_a_model_manifest_copies_module_2_identity_verbatim():
    """Module 3 must not form its own opinion about model identity."""
    from cvtrust.provenance.binding import bind_model_manifest

    class _Manifest:
        model_id = "M-abc"
        file_sha256 = "a" * 64
        graph_digest = "b" * 64
        parameter_digest = "c" * 64
        parameter_count = 42
        model_format = "onnx"
        architecture = "resnet18"
        declared_metadata = {"version": "3.1"}
        digest = "d" * 64

    binding = bind_model_manifest(_Manifest())
    assert binding.file_sha256 == "a" * 64
    assert binding.graph_digest == "b" * 64
    assert binding.parameter_digest == "c" * 64
    assert binding.manifest_digest == "d" * 64
    # The declared name travels, flagged untrusted, and is not the identity.
    assert binding.declared_name == "resnet18"


def test_the_output_binding_is_self_consistent():
    binding = bind_output(classification_output({"a": 0.5}))
    assert binding.self_consistent()
    tampered = binding.model_copy(update={"digest": "e" * 64})
    assert not tampered.self_consistent()


def test_a_model_binding_declared_name_is_not_an_identity():
    """A record claiming detector_v3 must not establish that it was detector_v3."""
    honest = ModelBinding(
        model_id="M-1", file_sha256="a" * 64, model_format="onnx",
        declared_name="detector_v3",
    )
    liar = ModelBinding(
        model_id="M-2", file_sha256="b" * 64, model_format="onnx",
        declared_name="detector_v3",
    )
    assert honest.declared_name == liar.declared_name
    assert honest.file_sha256 != liar.file_sha256
