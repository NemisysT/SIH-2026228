"""Dataset adapters: parse what is there, and record what is wrong.

The recurring assertion is that malformed *content* never raises -- it becomes
an IngestIssue, because a malformed annotation is itself a supported threat and
must survive to the analyst as evidence.
"""

from __future__ import annotations

import json

import numpy as np
import pytest
from PIL import Image

from cvtrust.core.errors import AdapterError
from cvtrust.datasets import ADAPTERS, IssueCode, Task, detect_adapter


def _image(path, size=(32, 32)):
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(abs(hash(path.name)) % 1000)
    Image.fromarray(rng.integers(0, 255, (*size[::-1], 3), dtype=np.uint8)).save(path)


# -- detection ------------------------------------------------------------


def test_each_generated_layout_is_detected_as_its_own_format(clean_dir):
    assert detect_adapter(clean_dir / "dataset").name == "folder"
    assert detect_adapter(clean_dir / "coco").name == "coco"
    assert detect_adapter(clean_dir / "yolo").name == "yolo"


def test_an_unrecognisable_root_is_an_error_not_a_guess(tmp_path):
    (tmp_path / "loose.txt").write_text("hello")
    with pytest.raises(AdapterError, match="no registered adapter"):
        detect_adapter(tmp_path)


def test_the_contributor_sidecar_does_not_confuse_folder_detection(tmp_path):
    for label in ("a", "b"):
        _image(tmp_path / label / "x.jpg")
    (tmp_path / "contributors.json").write_text('{"samples": {}}')
    assert detect_adapter(tmp_path).name == "folder"


# -- folder ---------------------------------------------------------------


def test_folder_adapter_reads_labels_from_directory_names(clean_root):
    dataset = ADAPTERS.get("folder").load(clean_root)
    assert dataset.task is Task.CLASSIFICATION
    assert "vehicle" in dataset.classes
    assert all(len(s.labels) == 1 for s in dataset.samples)
    assert dataset.samples[0].labels[0] == dataset.samples[0].relpath.split("/")[0]


def test_samples_are_ordered_deterministically(clean_root):
    ids = [s.sample_id for s in ADAPTERS.get("folder").load(clean_root).samples]
    assert ids == sorted(ids)


def test_a_non_image_inside_a_class_directory_is_recorded_not_ignored(tmp_path):
    for label in ("a", "b"):
        _image(tmp_path / label / "x.jpg")
    (tmp_path / "a" / "notes.txt").write_text("x")
    dataset = ADAPTERS.get("folder").load(tmp_path)
    assert any(i.code is IssueCode.UNSUPPORTED_EXTENSION for i in dataset.issues)


# -- coco -----------------------------------------------------------------


def test_coco_adapter_reads_boxes_and_categories(clean_dir):
    dataset = ADAPTERS.get("coco").load(clean_dir / "coco")
    assert dataset.task is Task.DETECTION
    assert dataset.classes
    with_boxes = [s for s in dataset.samples if s.annotations]
    assert with_boxes
    x1, y1, x2, y2 = with_boxes[0].annotations[0].bbox
    assert x2 > x1 and y2 > y1


def test_coco_bbox_is_normalised_from_xywh_to_xyxy(tmp_path):
    _image(tmp_path / "images" / "a.jpg", (40, 30))
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 40, "height": 30}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [5, 6, 10, 12]}],
        "categories": [{"id": 1, "name": "thing"}],
    }))
    sample = ADAPTERS.get("coco").load(tmp_path).samples[0]
    assert sample.annotations[0].bbox == (5.0, 6.0, 15.0, 18.0)


def test_coco_orphan_annotation_becomes_an_issue(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 32, "height": 32}],
        "annotations": [{"id": 9, "image_id": 404, "category_id": 1, "bbox": [0, 0, 4, 4]}],
        "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    assert any(i.code is IssueCode.ORPHAN_ANNOTATION for i in dataset.issues)


def test_coco_undeclared_category_becomes_an_issue(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 32, "height": 32}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 77, "bbox": [0, 0, 4, 4]}],
        "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    assert any(i.code is IssueCode.UNKNOWN_CATEGORY for i in dataset.issues)


def test_coco_duplicate_image_ids_are_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    _image(tmp_path / "images" / "b.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [
            {"id": 1, "file_name": "a.jpg", "width": 32, "height": 32},
            {"id": 1, "file_name": "b.jpg", "width": 32, "height": 32},
        ],
        "annotations": [], "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    assert any(i.code is IssueCode.DUPLICATE_ID for i in dataset.issues)


def test_coco_malformed_records_do_not_abort_the_parse(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "a.jpg", "width": 32, "height": 32},
                   {"no_id": True}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": "not-a-box"}],
        "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    assert len(dataset.samples) == 1
    codes = {i.code for i in dataset.issues}
    assert IssueCode.MALFORMED_RECORD in codes
    assert IssueCode.INVALID_BBOX in codes


def test_coco_path_traversal_in_file_name_is_not_followed(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "annotations").mkdir(parents=True)
    (tmp_path / "annotations" / "i.json").write_text(json.dumps({
        "images": [{"id": 1, "file_name": "../../../../etc/hosts",
                    "width": 1, "height": 1}],
        "annotations": [], "categories": [{"id": 1, "name": "thing"}],
    }))
    dataset = ADAPTERS.get("coco").load(tmp_path)
    # Kept verbatim and left to fail as a missing file, never resolved outside
    # the dataset root.
    assert not (tmp_path / dataset.samples[0].relpath).resolve().is_file()


# -- yolo -----------------------------------------------------------------


def test_yolo_adapter_reads_classes_and_normalised_boxes(clean_dir):
    dataset = ADAPTERS.get("yolo").load(clean_dir / "yolo")
    assert dataset.task is Task.DETECTION
    assert "vehicle" in dataset.classes
    labelled = [s for s in dataset.samples if s.annotations]
    assert labelled
    norm = labelled[0].annotations[0].native["norm_bbox"]
    assert all(0.0 <= v <= 1.0 for v in norm)


def test_yolo_out_of_range_class_index_is_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "labels").mkdir(parents=True)
    (tmp_path / "labels" / "a.txt").write_text("42 0.5 0.5 0.2 0.2\n")
    (tmp_path / "classes.txt").write_text("thing\n")
    dataset = ADAPTERS.get("yolo").load(tmp_path)
    assert any(i.code is IssueCode.UNKNOWN_CATEGORY for i in dataset.issues)


def test_yolo_denormalised_box_is_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "labels").mkdir(parents=True)
    (tmp_path / "labels" / "a.txt").write_text("0 12.0 0.5 0.2 0.2\n")
    (tmp_path / "classes.txt").write_text("thing\n")
    dataset = ADAPTERS.get("yolo").load(tmp_path)
    assert any(i.code is IssueCode.INVALID_BBOX for i in dataset.issues)


def test_yolo_truncated_line_is_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "labels").mkdir(parents=True)
    (tmp_path / "labels" / "a.txt").write_text("0 0.5 0.5\n")
    (tmp_path / "classes.txt").write_text("thing\n")
    dataset = ADAPTERS.get("yolo").load(tmp_path)
    assert any(i.code is IssueCode.MALFORMED_RECORD for i in dataset.issues)


def test_yolo_label_without_an_image_is_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    (tmp_path / "labels").mkdir(parents=True)
    (tmp_path / "labels" / "a.txt").write_text("0 0.5 0.5 0.2 0.2\n")
    (tmp_path / "labels" / "ghost.txt").write_text("0 0.5 0.5 0.2 0.2\n")
    (tmp_path / "classes.txt").write_text("thing\n")
    dataset = ADAPTERS.get("yolo").load(tmp_path)
    assert any(i.code is IssueCode.ORPHAN_ANNOTATION for i in dataset.issues)


def test_yolo_image_without_a_label_is_reported(tmp_path):
    _image(tmp_path / "images" / "a.jpg")
    _image(tmp_path / "images" / "b.jpg")
    (tmp_path / "labels").mkdir(parents=True)
    (tmp_path / "labels" / "a.txt").write_text("0 0.5 0.5 0.2 0.2\n")
    (tmp_path / "classes.txt").write_text("thing\n")
    dataset = ADAPTERS.get("yolo").load(tmp_path)
    assert any(i.code is IssueCode.UNLABELLED_SAMPLE for i in dataset.issues)
