"""Model manifest, identity digests and adapters.

The three-digest design is the foundation of every identity claim Module 2
makes, so these tests pin the property that makes it worth having: the digests
must move *independently*, each in response to its own kind of change.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from cvtrust.core.errors import AdapterError, VerificationError
from cvtrust.models.manifest import (
    PARAMETER_DIGEST_PLACES,
    build_model_manifest,
    compare_identity,
    diff_parameter_records,
    load_model_manifest,
    tensor_digest,
    verify_model_manifest,
)

pytestmark = pytest.mark.slow


# ---------------------------------------------------------------------------
# tensor_digest
# ---------------------------------------------------------------------------


def test_tensor_digest_is_stable_for_identical_values():
    values = np.array([[1.5, -2.25], [0.0, 3.125]], dtype=np.float32)
    assert tensor_digest(values, "float32", values.shape) == tensor_digest(
        values.copy(), "float32", values.shape
    )


def test_tensor_digest_changes_with_values():
    a = np.array([1.0, 2.0, 3.0], dtype=np.float32)
    b = np.array([1.0, 2.0, 3.001], dtype=np.float32)
    assert tensor_digest(a, "float32", a.shape) != tensor_digest(b, "float32", b.shape)


def test_tensor_digest_binds_the_shape():
    """A flattened and a reshaped view must not collide."""
    flat = np.arange(6, dtype=np.float32)
    assert tensor_digest(flat, "float32", (6,)) != tensor_digest(
        flat.reshape(2, 3), "float32", (2, 3)
    )


def test_tensor_digest_is_storage_dtype_independent_at_the_declared_precision():
    """The digest describes weight VALUES, not their container.

    A model exported once at float32 and once at float64 with the same values
    must not be reported as having different weights.
    """
    values = np.array([0.5, 0.25, -0.125], dtype=np.float32)
    as_double = values.astype(np.float64)
    assert tensor_digest(values, "float32", values.shape) == tensor_digest(
        as_double, "float32", as_double.shape
    )


def test_tensor_digest_survives_a_perturbation_below_its_precision():
    values = np.array([1.0], dtype=np.float64)
    tiny = np.array([1.0 + 10 ** -(PARAMETER_DIGEST_PLACES + 3)], dtype=np.float64)
    assert tensor_digest(values, "float64", (1,)) == tensor_digest(tiny, "float64", (1,))


def test_tensor_digest_encodes_non_finite_weights_distinctly():
    finite = np.array([1.0, 2.0], dtype=np.float64)
    with_nan = np.array([1.0, np.nan], dtype=np.float64)
    assert tensor_digest(finite, "float64", (2,)) != tensor_digest(
        with_nan, "float64", (2,)
    )


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------


def test_manifest_records_identity_and_is_self_consistent(reference_onnx):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)

    assert manifest.model_id.startswith("M-")
    assert manifest.manifest_id.startswith("MM-")
    assert len(manifest.file_sha256) == 64
    assert manifest.graph_digest and manifest.parameter_digest
    assert manifest.parameter_count and manifest.parameter_count > 0
    assert manifest.recompute_digest() == manifest.digest


def test_manifest_is_reproducible(reference_onnx):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    first = build_model_manifest(adapter.load(reference_onnx), adapter)
    second = build_model_manifest(adapter.load(reference_onnx), adapter)
    assert first.digest == second.digest
    assert first.manifest_id == second.manifest_id


def test_model_id_is_derived_from_content_not_from_the_filename(
    reference_onnx, tmp_path
):
    """A path is never an identity."""
    import shutil

    from cvtrust.models import detect_model_adapter

    renamed = tmp_path / "totally_different_name.onnx"
    shutil.copy2(reference_onnx, renamed)
    adapter = detect_model_adapter(reference_onnx)
    original = build_model_manifest(adapter.load(reference_onnx), adapter)
    copied = build_model_manifest(adapter.load(renamed), adapter)
    assert original.model_id == copied.model_id
    assert original.file_sha256 == copied.file_sha256


def test_reference_designation_does_not_change_the_digest(reference_onnx):
    """An operator label must not alter the identity of what was measured."""
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    handle = adapter.load(reference_onnx)
    plain = build_model_manifest(handle, adapter)
    labelled = build_model_manifest(
        handle, adapter, reference_designation="trusted reference"
    )
    assert plain.digest == labelled.digest


def test_manifest_records_access_mode_and_capabilities(reference_onnx):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)
    assert manifest.access_mode.value == "WHITE_BOX"
    assert "parameters" in manifest.capabilities
    assert "graph" in manifest.capabilities
    # ONNX Runtime gives no input gradients, and the manifest must say so
    # rather than leaving the reader to assume otherwise.
    assert "gradients" not in manifest.capabilities
    assert "gradients" in manifest.unavailable_fields


# ---------------------------------------------------------------------------
# The three digests move independently
# ---------------------------------------------------------------------------


def test_reserialisation_changes_the_file_digest_only(model_lab, reference_onnx):
    """The case the whole three-digest design exists to express."""
    from cvtrust.models import detect_model_adapter

    supplied = model_lab["scenarios"]["reserialised"].onnx_path
    adapter = detect_model_adapter(supplied)
    left = build_model_manifest(adapter.load(supplied), adapter)
    right = build_model_manifest(adapter.load(reference_onnx), adapter)

    comparison = compare_identity(left, right)
    assert comparison["identity_match"] is False
    assert comparison["graph_match"] is True
    assert comparison["parameter_match"] is True
    assert comparison["interpretation_code"] == "RESERIALISED"


def test_a_weight_change_moves_the_parameter_digest_but_not_the_graph_digest(
    model_lab, reference_onnx
):
    from cvtrust.models import detect_model_adapter

    supplied = model_lab["scenarios"]["parameter_tamper_large"].onnx_path
    adapter = detect_model_adapter(supplied)
    left = build_model_manifest(adapter.load(supplied), adapter)
    right = build_model_manifest(adapter.load(reference_onnx), adapter)

    comparison = compare_identity(left, right)
    assert comparison["identity_match"] is False
    assert comparison["graph_match"] is True, "the architecture did not change"
    assert comparison["parameter_match"] is False, "the weights did"
    assert comparison["interpretation_code"] == "SAME_ARCHITECTURE_DIFFERENT_WEIGHTS"


def test_a_different_architecture_moves_every_digest(model_lab, reference_onnx):
    from cvtrust.models import detect_model_adapter

    supplied = model_lab["scenarios"]["substitution_architecture"].onnx_path
    adapter = detect_model_adapter(supplied)
    left = build_model_manifest(adapter.load(supplied), adapter)
    right = build_model_manifest(adapter.load(reference_onnx), adapter)

    comparison = compare_identity(left, right)
    assert comparison["identity_match"] is False
    assert comparison["graph_match"] is False
    assert comparison["parameter_match"] is False
    assert comparison["interpretation_code"] == "DIFFERENT_MODEL"


def test_identical_artifacts_match_on_all_three_digests(reference_onnx):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)
    comparison = compare_identity(manifest, manifest)
    assert comparison["identity_match"] is True
    assert comparison["interpretation_code"] == "IDENTICAL"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def test_verification_passes_on_the_unmodified_artifact(reference_onnx):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)
    result = verify_model_manifest(manifest, reference_onnx)
    assert result.ok
    assert result.file_match and result.graph_match and result.parameter_match


def test_verification_detects_a_modified_artifact(
    model_lab, reference_onnx, tmp_path
):
    """A model swapped after assurance must be caught, and localised."""
    import shutil

    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)

    # Put a tampered artifact at the path the manifest describes.
    deployed = tmp_path / "deployed.onnx"
    shutil.copy2(model_lab["scenarios"]["parameter_tamper_large"].onnx_path, deployed)
    result = verify_model_manifest(manifest, deployed)

    assert not result.ok
    assert result.file_match is False
    assert result.parameter_match is False
    assert result.changed_parameters, "the changed tensors must be named"


def test_verification_detects_an_absent_artifact(reference_onnx, tmp_path):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)
    result = verify_model_manifest(manifest, tmp_path / "gone.onnx")
    assert not result.ok
    assert result.artifact_present is False


def test_a_tampered_manifest_is_rejected(reference_onnx, tmp_path):
    """An invalid manifest must be refused, not silently trusted."""
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)

    payload = json.loads(manifest.model_dump_json())
    payload["parameter_count"] = 1
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(VerificationError, match="not self-consistent"):
        load_model_manifest(path)


def test_a_valid_manifest_round_trips(reference_onnx, tmp_path):
    from cvtrust.models import detect_model_adapter

    adapter = detect_model_adapter(reference_onnx)
    manifest = build_model_manifest(adapter.load(reference_onnx), adapter)
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json(), encoding="utf-8")
    assert load_model_manifest(path).digest == manifest.digest


# ---------------------------------------------------------------------------
# Parameter diffing
# ---------------------------------------------------------------------------


def test_parameter_diff_separates_kinds_of_change():
    from cvtrust.models.manifest import ParameterRecord

    def record(name, shape, digest, dtype="float32"):
        count = int(np.prod(shape))
        return ParameterRecord(
            name=name, dtype=dtype, shape=tuple(shape), count=count, digest=digest
        )

    expected = [
        record("kept", (2, 2), "a"),
        record("changed", (2, 2), "b"),
        record("reshaped", (2, 2), "c"),
        record("removed", (2,), "d"),
    ]
    actual = [
        record("kept", (2, 2), "a"),
        record("changed", (2, 2), "B"),
        record("reshaped", (4, 1), "c"),
        record("added", (3,), "e"),
    ]
    changes = {entry["name"]: entry["change"] for entry in diff_parameter_records(expected, actual)}
    assert changes == {
        "changed": "content_changed",
        "reshaped": "respecified",
        "removed": "removed",
        "added": "added",
    }
    assert "kept" not in changes


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


def test_an_unrecognised_artifact_is_refused_rather_than_sniffed(tmp_path):
    from cvtrust.models import detect_model_adapter

    path = tmp_path / "model.unknown"
    path.write_bytes(b"not a model")
    with pytest.raises(AdapterError, match="no registered model adapter"):
        detect_model_adapter(path)


def test_adapter_detection_is_unambiguous_for_torchscript(reference_torchscript):
    """.pt is claimed by exactly one adapter, or detection is a guess."""
    from cvtrust.models import MODEL_ADAPTERS

    matches = [
        name for name, adapter in MODEL_ADAPTERS if adapter.detect(reference_torchscript)
    ]
    assert matches == ["torchscript"]


def test_onnx_and_torchscript_agree_on_parameter_count_within_format_differences(
    reference_onnx, reference_torchscript
):
    """Two exports of one model describe the same model, not the same bytes.

    Exporters differ — ONNX folds batch-norm statistics into initializers while
    torch keeps `num_batches_tracked` buffers — so the counts are close but not
    equal. The manifest records what each format actually exposes rather than
    normalising the difference away, and this test pins that they stay within a
    small margin rather than diverging.
    """
    from cvtrust.models import detect_model_adapter

    onnx_manifest = build_model_manifest(
        detect_model_adapter(reference_onnx).load(reference_onnx),
        detect_model_adapter(reference_onnx),
    )
    torch_manifest = build_model_manifest(
        detect_model_adapter(reference_torchscript).load(reference_torchscript),
        detect_model_adapter(reference_torchscript),
    )
    assert onnx_manifest.parameter_count and torch_manifest.parameter_count
    ratio = onnx_manifest.parameter_count / torch_manifest.parameter_count
    assert 0.95 < ratio < 1.05
    # The formats are distinct artifacts and must never share an identity.
    assert onnx_manifest.file_sha256 != torch_manifest.file_sha256


def test_the_shipped_default_config_matches_the_code_defaults():
    """A config file that drifts from the code is a threshold the analyst
    believes is active and is not."""
    from pathlib import Path

    from cvtrust.core.config import Config

    shipped = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
    assert Config.load(shipped).config_hash() == Config().config_hash()
