"""The graceful-degradation contract.

A component that cannot run must say why, in a machine-readable way, and the
pipeline must record NOT_ASSESSED rather than an implied clean result.  This is
the same contract Module 2 will use for ``NOT AVAILABLE — WHITE-BOX ACCESS
REQUIRED``, so it is pinned here, in Module 1, where it is first exercised.
"""

from __future__ import annotations

import pytest

from cvtrust.core.errors import ConfigError, DetectorUnavailable
from cvtrust.features.torch_backend import TorchFeatureExtractor


def test_the_optional_cnn_backend_refuses_clearly_without_local_weights():
    extractor = TorchFeatureExtractor(weights_path=None)
    with pytest.raises(DetectorUnavailable) as excinfo:
        extractor._ensure()
    message = str(excinfo.value)
    assert "unavailable" in message
    # The refusal must say what to do, and must promise not to fetch anything.
    assert "never downloaded" in message or "not installed" in message


def test_the_optional_cnn_backend_refuses_a_missing_weight_file(tmp_path):
    extractor = TorchFeatureExtractor(weights_path=tmp_path / "absent.pth")
    with pytest.raises(DetectorUnavailable):
        extractor._ensure()


def test_the_cnn_backend_describes_itself_without_being_loaded():
    described = TorchFeatureExtractor(weights_path=None).describe()
    assert described["requires_pretrained_weights"] is True
    assert described["weights_sha256"] is None


def test_an_unavailable_detector_yields_not_assessed_not_zero_findings(
    clean_root, config, monkeypatch
):
    from cvtrust.core.evidence import Coverage
    from cvtrust.detectors import DETECTORS
    from cvtrust.pipeline import analyse

    detector = DETECTORS.get("ood")
    monkeypatch.setattr(
        detector, "run",
        lambda ctx: (_ for _ in ()).throw(
            DetectorUnavailable("reference distribution unavailable in this test")
        ),
    )
    report, _, _ = analyse(clean_root, config)
    entry = next(e for e in report.coverage.entries if e.attack_class == "ood_insertion")
    assert entry.coverage is Coverage.NOT_ASSESSED
    assert "reference distribution unavailable" in (entry.reason or "")
    assert not [f for f in report.findings if f.method == "ood"]


def test_an_unassessed_class_still_reaches_the_report(clean_root, config):
    from cvtrust.pipeline import analyse

    report, _, _ = analyse(clean_root, config, detectors=("integrity",))
    classes = {e.attack_class: e for e in report.coverage.entries}
    assert classes["metadata_inconsistency"].coverage.value == "SUPPORTED"
    assert classes["label_flip"].coverage.value == "NOT_ASSESSED"
    assert classes["duplicate_flood"].coverage.value == "NOT_ASSESSED"


def test_a_missing_calibration_file_is_an_explained_error_not_a_silent_default():
    from cvtrust.risk.calibration import CalibrationSet

    with pytest.raises(ConfigError, match="calibration table not found"):
        CalibrationSet.load("/nonexistent/calibration.json")


def test_a_malformed_config_is_rejected_rather_than_partially_applied(tmp_path):
    from cvtrust.core.config import Config

    path = tmp_path / "bad.yaml"
    path.write_text("near_duplicate:\n  phash_hamming_max: 999\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid configuration"):
        Config.load(path)


def test_an_unknown_config_key_is_rejected_rather_than_ignored(tmp_path):
    """A silently-ignored threshold is a threshold the analyst thinks is active."""
    from cvtrust.core.config import Config

    path = tmp_path / "typo.yaml"
    path.write_text("near_duplciate:\n  phash_hamming_max: 4\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.load(path)


def test_an_unregistered_component_name_names_the_alternatives():
    from cvtrust.datasets import ADAPTERS

    with pytest.raises(ConfigError) as excinfo:
        ADAPTERS.get("parquet")
    assert "coco" in str(excinfo.value) and "yolo" in str(excinfo.value)
