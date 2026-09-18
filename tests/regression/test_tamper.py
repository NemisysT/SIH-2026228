"""Tamper tests: verification must fail, precisely and informatively."""

from __future__ import annotations

import shutil

import pytest

from cvtrust.core.config import ContributorConfig
from cvtrust.datasets import (
    ADAPTERS,
    ContributorResolver,
    DatasetManifest,
    build_manifest,
    verify_manifest,
)


@pytest.fixture
def baseline(clean_root, tmp_path):
    root = tmp_path / "dataset"
    shutil.copytree(clean_root, root)
    dataset = ADAPTERS.get("folder").load(root)
    manifest, *_ = build_manifest(
        dataset, ContributorResolver(ContributorConfig(), root)
    )
    return manifest, root


def test_a_single_flipped_bit_is_detected(baseline):
    manifest, root = baseline
    victim = manifest.samples[3]
    path = root / victim.relpath
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))

    result = verify_manifest(manifest, root)
    assert not result.dataset_matches
    assert [m["relpath"] for m in result.modified] == [victim.relpath]
    assert result.modified[0]["expected_sha256"] == victim.file_sha256
    assert result.modified[0]["actual_sha256"] != victim.file_sha256


def test_a_deleted_sample_is_detected(baseline):
    manifest, root = baseline
    victim = manifest.samples[5]
    (root / victim.relpath).unlink()
    result = verify_manifest(manifest, root)
    assert not result.dataset_matches
    assert victim.relpath in result.missing


def test_an_injected_sample_is_detected(baseline):
    manifest, root = baseline
    source = root / manifest.samples[0].relpath
    shutil.copy2(source, source.with_name("injected.jpg"))
    result = verify_manifest(manifest, root)
    assert not result.dataset_matches
    assert any(p.endswith("injected.jpg") for p in result.added)


def test_a_same_size_content_swap_is_detected(baseline):
    """Swapping two images preserves every file size and the total count."""
    manifest, root = baseline
    a, b = root / manifest.samples[0].relpath, root / manifest.samples[1].relpath
    a_bytes, b_bytes = a.read_bytes(), b.read_bytes()
    a.write_bytes(b_bytes)
    b.write_bytes(a_bytes)

    result = verify_manifest(manifest, root)
    assert not result.dataset_matches
    assert len(result.modified) == 2


def test_tampering_with_the_manifest_itself_is_detected(baseline, tmp_path):
    manifest, root = baseline
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json(), encoding="utf-8")

    # An attacker edits a recorded digest so the modified file "verifies".
    document = path.read_text(encoding="utf-8")
    document = document.replace(manifest.samples[0].file_sha256, "0" * 64)
    path.write_text(document, encoding="utf-8")

    forged = DatasetManifest.model_validate_json(path.read_text(encoding="utf-8"))
    result = verify_manifest(forged, root)
    assert not result.manifest_self_consistent
    assert result.digest_recomputed != result.manifest_digest


def test_verification_passes_when_nothing_changed(baseline):
    manifest, root = baseline
    result = verify_manifest(manifest, root)
    assert result.manifest_self_consistent and result.dataset_matches
    assert not result.missing and not result.modified and not result.added
