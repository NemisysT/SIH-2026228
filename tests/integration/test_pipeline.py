"""End-to-end pipeline behaviour on clean and attacked datasets."""

from __future__ import annotations

from pathlib import Path

import pytest

from cvtrust.attack_lab import attacks
from cvtrust.attack_lab.evaluate import evaluate_scenario
from cvtrust.core.evidence import AssetType, Coverage, Disposition, Severity
from cvtrust.pipeline import analyse

pytestmark = pytest.mark.slow


# -- negative tests: clean data must not be accused -----------------------


def test_clean_dataset_produces_no_high_severity_findings(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    severe = [
        f for f in report.findings
        if f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    assert severe == [], [f.title for f in severe]


def test_clean_dataset_is_never_quarantined(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    assert report.summary.overall != "QUARANTINE REQUIRED"
    assert report.summary.by_disposition["QUARANTINE"] == 0


def test_clean_false_alarm_rate_stays_within_the_declared_bound(clean_root, config):
    """The only findings expected on clean data are OOD tail samples, and their
    rate must stay near the configured family-wise false-positive rate."""
    report, _, _ = analyse(clean_root, config)
    total = report.dataset["counts"]["samples"]
    flagged = {f.asset.id for f in report.findings if f.asset.type is AssetType.SAMPLE}
    # Generous ceiling relative to target_fpr=1%, to keep the test about
    # behaviour rather than about a specific corpus draw.
    assert len(flagged) / total <= 0.05, sorted(flagged)


def test_no_label_or_duplicate_findings_on_clean_data(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    classes = set(report.summary.by_attack_class)
    assert "label_flip" not in classes
    assert "duplicate_flood" not in classes
    assert "systematic_mislabel" not in classes


# -- the pipeline's own contracts -----------------------------------------


def test_every_finding_carries_recomputable_evidence(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    for finding in report.findings:
        assert finding.evidence
        for item in finding.evidence:
            assert item.statement.strip()
            assert item.observation


def test_every_finding_declares_a_disposition_rule(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    rules = {f.disposition_rule for f in report.findings}
    published = {r["id"] for r in report.disposition_policy["rules"]}
    assert rules <= published


def test_coverage_names_every_known_attack_class(clean_root, config):
    from cvtrust.risk.coverage import ATTACK_CLASS_REGISTRY

    report, _, _ = analyse(clean_root, config)
    reported = {e.attack_class for e in report.coverage.entries}
    assert reported == set(ATTACK_CLASS_REGISTRY)


def test_later_module_classes_are_declared_not_assessed(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    for entry in report.coverage.entries:
        if entry.owning_module > 1:
            assert entry.coverage is Coverage.NOT_ASSESSED
            assert entry.reason and "Module" in entry.reason


def test_uncalibrated_findings_cannot_quarantine(clean_root, config):
    report, _, _ = analyse(clean_root, config)
    assert config.calibration_path is None
    for finding in report.findings:
        if finding.confidence_basis.value == "HEURISTIC_UNCALIBRATED":
            assert finding.disposition is not Disposition.QUARANTINE


def test_all_three_adapters_reach_the_same_findings_pipeline(clean_dir, config):
    for subdir, adapter in (("dataset", "folder"), ("coco", "coco"), ("yolo", "yolo")):
        report, _, _ = analyse(clean_dir / subdir, config, adapter_name=adapter)
        assert report.dataset["adapter"] == adapter
        assert report.dataset["counts"]["samples"] > 0
        assert report.report_id.startswith("R-")


# -- attacked datasets ----------------------------------------------------


@pytest.fixture(scope="module")
def scenarios(clean_root, tmp_path_factory):
    lab = tmp_path_factory.mktemp("lab")
    built = {}
    for name, builder in attacks.SCENARIOS.items():
        built[name] = builder(clean_root, lab / name)
    return lab, built


#: Per-detector floors, not one blanket number, because the detectors make
#: claims of different strength and pretending otherwise would hide that.
#:
#: These are floors for the *small* test corpus (8 samples per class per
#: contributor), which is deliberately harder than the demo corpus: fewer
#: neighbours per class means weaker neighbourhood evidence.  Measured numbers
#: on the full corpus are reported by `cvtrust lab evaluate` and recorded in
#: docs/testing.md.
DETECTION_FLOORS: dict[str, dict[str, float]] = {
    # Cryptographic equality: nothing to miss and nothing to over-claim.
    "duplicate_flood": {"recall": 1.0, "precision": 1.0},
    # Two-stage confirmation; the injected variants are within the stated
    # invariance envelope, so recall should be complete.
    "near_duplicate_flood": {"recall": 0.95, "precision": 0.8},
    # Neighbourhood screening; a flipped label that lands near a class boundary
    # is genuinely ambiguous and may be missed.
    "label_flip": {"recall": 0.80, "precision": 0.8},
    # Sample-level attribution here is a screening signal. The claim this
    # detector actually makes is the contributor-level one, asserted exactly in
    # test_systematic_mislabelling_is_attributed_to_its_contributor.
    "systematic_mislabel": {"recall": 0.50, "precision": 0.9},
    # Reference-relative distance with a Bonferroni-corrected threshold.
    "ood_insertion": {"recall": 0.90, "precision": 0.5},
}


@pytest.mark.parametrize("scenario", list(DETECTION_FLOORS))
def test_each_attack_is_detected(scenarios, config, scenario):
    lab, built = scenarios
    result, _ = evaluate_scenario(lab / scenario, config)
    metric = next(m for m in result.metrics if m.attack_class == scenario)
    floors = DETECTION_FLOORS[scenario]
    assert metric.recall >= floors["recall"], metric
    assert metric.precision >= floors["precision"], metric


def test_the_detector_that_owns_a_class_is_the_one_that_reports_it(scenarios, config):
    expected = {
        "duplicate_flood": "exact_duplicate",
        "near_duplicate_flood": "near_duplicate",
        "label_flip": "label_consistency",
        "systematic_mislabel": "systematic_mislabel",
        "ood_insertion": "ood",
    }
    lab, _ = scenarios
    for scenario, detector in expected.items():
        result, _ = evaluate_scenario(lab / scenario, config)
        metric = next(m for m in result.metrics if m.attack_class == scenario)
        assert metric.detector == detector, (scenario, metric.detector)


@pytest.mark.parametrize("scenario", list(attacks.SCENARIOS))
def test_no_attack_scenario_accuses_untouched_samples_wholesale(
    scenarios, config, scenario
):
    lab, _ = scenarios
    result, _ = evaluate_scenario(lab / scenario, config)
    for metric in result.metrics:
        assert metric.fpr_clean <= 0.05, (scenario, metric)


def test_exact_duplicates_are_found_with_certainty(scenarios, config):
    lab, _ = scenarios
    report, _, _ = analyse(lab / "duplicate_flood" / "dataset", config)
    duplicates = [f for f in report.findings if f.attack_class == "duplicate_flood"]
    assert duplicates
    assert all(f.confidence == 1.0 for f in duplicates)
    assert all(f.confidence_basis.value == "DETERMINISTIC" for f in duplicates)


def test_re_encoded_copies_are_caught_by_content_digest(scenarios, config):
    """The file-digest check alone would miss these."""
    lab, _ = scenarios
    report, _, _ = analyse(lab / "duplicate_flood" / "dataset", config)
    content = [
        f for f in report.findings
        for e in f.evidence
        if e.kind == "content_digest_collision"
    ]
    assert content, "re-encoded pixel-identical copies were not reported"
    observation = content[0].evidence[0].observation
    assert observation["distinct_file_digests"] > 1


def test_systematic_mislabelling_is_attributed_to_its_contributor(scenarios, config):
    lab, _ = scenarios
    report, _, _ = analyse(lab / "systematic_mislabel" / "dataset", config)
    findings = [f for f in report.findings if f.attack_class == "systematic_mislabel"]
    assert findings
    finding = findings[0]
    assert finding.asset.type is AssetType.CONTRIBUTOR
    assert finding.contributor == "charlie"
    assert finding.confidence_basis.value == "STATISTICAL"

    test_evidence = next(e for e in finding.evidence if e.kind == "binomial_test")
    assert test_evidence.observation["q_value"] < config.systematic_mislabel.alpha
    concentration = next(
        e for e in finding.evidence if e.kind == "directional_label_concentration"
    )
    assert concentration.observation["declared_label"] == "building"
    assert concentration.observation["suggested_label"] == "vehicle"


def test_contributor_aggregation_produces_lineage_to_sample_findings(scenarios, config):
    lab, built = scenarios
    report, _, _ = analyse(
        lab / "combined" / "dataset", config,
        reference_sample_ids=set(built["combined"].ground_truth["clean"]),
    )
    contributor_findings = [
        f for f in report.findings
        if f.method == "contributor_aggregation"
    ]
    assert contributor_findings, "no contributor-level aggregation was produced"

    sample_ids = {
        f.finding_id for f in report.findings if f.asset.type is AssetType.SAMPLE
    }
    for finding in contributor_findings:
        lineage = next(e for e in finding.evidence if e.kind == "evidence_lineage")
        children = set(lineage.observation["child_finding_ids"])
        assert children and children <= sample_ids


def test_contributor_confidence_never_exceeds_its_evidence(scenarios, config):
    lab, built = scenarios
    report, _, _ = analyse(
        lab / "combined" / "dataset", config,
        reference_sample_ids=set(built["combined"].ground_truth["clean"]),
    )
    for finding in report.findings:
        if finding.method != "contributor_aggregation":
            continue
        lineage = next(e for e in finding.evidence if e.kind == "evidence_lineage")
        assert finding.confidence <= lineage.observation["mean_child_confidence"] + 1e-9


def test_ood_findings_never_assert_malice(scenarios, config):
    lab, built = scenarios
    report, _, _ = analyse(
        lab / "ood_insertion" / "dataset", config,
        reference_sample_ids=set(built["ood_insertion"].ground_truth["clean"]),
    )
    findings = [
        f for f in report.findings
        if f.attack_class == "ood_insertion" and f.method == "ood"
    ]
    assert findings
    for finding in findings:
        # Severity is capped at MEDIUM for OOD by design: "different from the
        # reference" is not, on this evidence alone, a high-severity claim.
        assert finding.severity in (Severity.LOW, Severity.MEDIUM)
        assert any("NOT evidence of malicious" in l for l in finding.limitations)
        assert any("Module 4" in l for l in finding.limitations)

    # Contributor-level roll-ups of OOD evidence must not escalate the claim
    # into one about intent either.
    for finding in report.findings:
        if finding.attack_class == "ood_insertion" and finding.method != "ood":
            assert any("not proof of intent" in l for l in finding.limitations)


def test_declared_reference_is_recorded_as_such(scenarios, config):
    lab, built = scenarios
    report, _, _ = analyse(
        lab / "ood_insertion" / "dataset", config,
        reference_sample_ids=set(built["ood_insertion"].ground_truth["clean"]),
    )
    finding = next(
        f for f in report.findings
        if f.attack_class == "ood_insertion" and f.method == "ood"
    )
    distance = next(e for e in finding.evidence if e.kind == "ood_distance")
    assert distance.observation["reference_mode"] == "declared"


def test_self_reference_is_declared_as_the_weaker_claim(scenarios, config):
    lab, _ = scenarios
    report, _, _ = analyse(lab / "ood_insertion" / "dataset", config)
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "ood_insertion"
    )
    assert entry.reason and "no reference distribution was declared" in entry.reason
