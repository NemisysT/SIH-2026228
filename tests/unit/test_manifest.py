"""Manifest construction, identity and contributor attribution."""

from __future__ import annotations

import json

import numpy as np
import pytest
from PIL import Image

from cvtrust.core.config import ContributorConfig
from cvtrust.datasets import (
    ADAPTERS,
    AttributionSource,
    ContributorResolver,
    IssueCode,
    build_manifest,
    verify_manifest,
)


def _build(root, contributor_cfg=None):
    dataset = ADAPTERS.get("folder").load(root)
    resolver = ContributorResolver(contributor_cfg or ContributorConfig(), root)
    return build_manifest(dataset, resolver)


def test_manifest_digest_is_reproducible(clean_root):
    first, *_ = _build(clean_root)
    second, *_ = _build(clean_root)
    assert first.digest == second.digest
    assert first.manifest_id == second.manifest_id


def test_creation_time_is_excluded_from_the_digest(clean_root):
    manifest, *_ = _build(clean_root)
    assert "created_at" not in manifest.digest_payload()
    assert manifest.recompute_digest() == manifest.digest


def test_manifest_id_is_derived_from_the_digest(clean_root):
    manifest, *_ = _build(clean_root)
    assert manifest.digest.startswith(manifest.manifest_id)


def test_every_sample_carries_both_digests(clean_root):
    manifest, *_ = _build(clean_root)
    assert manifest.counts["samples"] > 0
    for record in manifest.samples:
        assert record.readable
        assert len(record.file_sha256) == 64
        assert len(record.pixel_sha256) == 64
        assert record.width and record.height


def test_attribution_comes_from_the_sidecar_and_says_so(clean_root):
    manifest, _, attributions, _ = _build(clean_root)
    assert set(manifest.contributors) >= {"alpha", "bravo", "charlie", "delta"}
    sample = manifest.samples[0]
    assert sample.attribution_source == AttributionSource.SIDECAR.value
    assert attributions[sample.sample_id].batch


def test_a_filename_is_never_an_identity_by_default(tmp_path):
    """Path-pattern attribution is opt-in; without it, attribution is 'none'."""
    for label in ("a", "b"):
        (tmp_path / label).mkdir(parents=True)
        for i in range(2):
            Image.fromarray(
                np.full((16, 16, 3), 10 * i + 30, dtype=np.uint8)
            ).save(tmp_path / label / f"mallory_{i}.jpg")
    manifest, *_ = _build(tmp_path)
    assert {r.contributor for r in manifest.samples} == {"unknown"}
    assert {r.attribution_source for r in manifest.samples} == {AttributionSource.NONE.value}


def test_path_pattern_attribution_works_when_explicitly_enabled(tmp_path):
    for label in ("a", "b"):
        (tmp_path / label).mkdir(parents=True)
        Image.fromarray(np.zeros((16, 16, 3), np.uint8)).save(tmp_path / label / "x.jpg")
    cfg = ContributorConfig(sidecar=None, path_pattern=r"^(?P<contributor>[^/]+)/")
    manifest, *_ = _build(tmp_path, cfg)
    assert {r.contributor for r in manifest.samples} == {"a", "b"}
    assert {r.attribution_source for r in manifest.samples} == {
        AttributionSource.PATH_PATTERN.value
    }


def test_sidecar_takes_precedence_over_a_path_pattern(clean_root):
    cfg = ContributorConfig(path_pattern=r"^(?P<contributor>[^/]+)/")
    manifest, *_ = _build(clean_root, cfg)
    # Labels are the directory names; the sidecar names real contributors.
    assert "alpha" in {r.contributor for r in manifest.samples}
    assert "vehicle" not in {r.contributor for r in manifest.samples}


def test_an_unreadable_file_is_recorded_not_dropped(tmp_path):
    for label in ("a", "b"):
        (tmp_path / label).mkdir(parents=True)
        Image.fromarray(np.zeros((16, 16, 3), np.uint8)).save(tmp_path / label / "ok.jpg")
    (tmp_path / "a" / "corrupt.jpg").write_bytes(b"\xff\xd8\xff\xe0 not an image")
    manifest, _, _, issues = _build(tmp_path)

    assert any(i.code is IssueCode.UNREADABLE_IMAGE for i in issues)
    corrupt = manifest.sample("a/corrupt.jpg")
    assert corrupt is not None and not corrupt.readable
    # The file digest still exists: we know exactly which bytes failed to decode.
    assert corrupt.file_sha256 and corrupt.pixel_sha256 is None
    assert manifest.counts["unreadable"] == 1


def test_an_empty_file_is_recorded(tmp_path):
    for label in ("a", "b"):
        (tmp_path / label).mkdir(parents=True)
        Image.fromarray(np.zeros((16, 16, 3), np.uint8)).save(tmp_path / label / "ok.jpg")
    (tmp_path / "a" / "empty.jpg").write_bytes(b"")
    _, _, _, issues = _build(tmp_path)
    assert any(i.code is IssueCode.EMPTY_FILE for i in issues)


def test_declared_dimensions_that_contradict_the_file_are_reported(tmp_path):
    (tmp_path / "images").mkdir(parents=True)
    Image.fromarray(np.zeros((30, 40, 3), np.uint8)).save(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 999, "height": 999}],
        "annotations": [], "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    _, _, _, issues = build_manifest(
        dataset, ContributorResolver(ContributorConfig(), tmp_path)
    )
    mismatch = [i for i in issues if i.code is IssueCode.DIMENSION_MISMATCH]
    assert mismatch
    assert mismatch[0].observation["declared"] == [999, 999]
    assert mismatch[0].observation["actual"] == [40, 30]


def test_out_of_bounds_boxes_are_reported(tmp_path):
    (tmp_path / "images").mkdir(parents=True)
    Image.fromarray(np.zeros((32, 32, 3), np.uint8)).save(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 32, "height": 32}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [10, 10, 500, 500]}],
        "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    _, _, _, issues = build_manifest(
        dataset, ContributorResolver(ContributorConfig(), tmp_path)
    )
    assert any(i.code is IssueCode.BBOX_OUT_OF_BOUNDS for i in issues)


def test_verification_passes_on_an_untouched_dataset(clean_root):
    manifest, *_ = _build(clean_root)
    result = verify_manifest(manifest, clean_root)
    assert result.manifest_self_consistent
    assert result.dataset_matches
    assert result.checked == manifest.counts["samples"]
