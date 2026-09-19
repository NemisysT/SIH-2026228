"""Attacks on the assurance layer itself.

Module 4 has a threat surface the first three do not.  It consumes JSON
produced elsewhere, in a multi-contributor pipeline, and turns it into a
disposition an analyst will act on.  The interesting attacker is therefore not
one who poisons a dataset — that is Module 1's problem — but one who edits the
*report* about the dataset, or withholds one, or floods the engine with
correlated evidence until a real finding is lost.

The defences tested here are of three kinds, and it is worth being clear about
what each can and cannot do.

**Schema enforcement is real.**  A finding that violates the frozen evidence
contract cannot enter the graph.  A ``DETERMINISTIC`` finding at confidence
0.4, an unknown field, a report with no findings array: all refused loudly.

**Absence is visible.**  Withholding a report is the cheapest attack available
and the one the disposition vocabulary exists to defeat: a scope with no input
is ``NOT_ASSESSED``, and an overall ``ACCEPT`` requires every scope assessed.

**Upstream authenticity is NOT re-established here, and is not claimed to be.**
Module 4 does not re-verify signatures, re-hash models or re-scan corpora.  A
forged Module 3 report that is internally well-formed will be fused as written.
What the system does instead is cite the report it fused, by id and by content,
so the forgery is attributable — and say so in its limitations rather than
implying a check it does not perform.
"""

from __future__ import annotations

import json

import pytest

from cvtrust.assurance.policy import AssuranceDisposition, Scope
from cvtrust.assurance_pipeline import assess_pipeline, load_module_input
from cvtrust.core.config import Config
from cvtrust.core.errors import ConfigError

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def reports(tmp_path_factory, clean_root, provenance_lab):
    """A real Module 1 report and two real Module 3 reports."""
    from cvtrust.pipeline import analyse
    from cvtrust.provenance.chain import build_anchor
    from cvtrust.provenance.log import ProvenanceLog
    from cvtrust.provenance.replay import ReplayDatabase
    from cvtrust.provenance.trust import TrustStore
    from cvtrust.provenance_pipeline import verify_log

    out = tmp_path_factory.mktemp("attack-reports")
    paths = {}

    dataset, _, _ = analyse(clean_root, Config())
    paths["dataset"] = out / "dataset.json"
    paths["dataset"].write_text(dataset.model_dump_json(indent=2), encoding="utf-8")

    clean = provenance_lab["clean"]
    report, _, _ = verify_log(
        clean.log,
        Config(),
        trust_store=clean.trust_store,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(clean.log.entries),
    )
    paths["provenance_clean"] = out / "prov-clean.json"
    paths["provenance_clean"].write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )

    scenario = provenance_lab["scenarios"]["modified_output"]
    report, _, _ = verify_log(
        ProvenanceLog.load(scenario.log_path),
        Config(),
        trust_store=TrustStore.load(scenario.trust_store_path),
        replay_database=ReplayDatabase.empty(),
    )
    paths["provenance_tampered"] = out / "prov-tampered.json"
    paths["provenance_tampered"].write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )
    return paths


def edited(path, mutate, tmp_path, name="edited.json"):
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    out = tmp_path / name
    out.write_text(json.dumps(payload), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# 1. Tampered findings
# ---------------------------------------------------------------------------


def test_a_downgraded_deterministic_finding_is_refused(reports, tmp_path):
    """The canonical forgery: keep the basis, soften the number.

    A DETERMINISTIC finding at confidence 0.4 would read as 'the signature
    check is 40% sure', which is not a statement the system is allowed to make
    (ADR-006). The schema refuses it before fusion sees it.
    """
    def _soften(payload):
        for finding in payload["findings"]:
            if finding["confidence_basis"] == "DETERMINISTIC":
                finding["confidence"] = 0.4
                return
        pytest.skip("no deterministic finding in this report")

    path = edited(reports["provenance_tampered"], _soften, tmp_path)
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        load_module_input(path, module=3, expect_module="3")


def test_an_out_of_range_confidence_is_refused(reports, tmp_path):
    def _inflate(payload):
        payload["findings"][0]["confidence"] = 1.7

    path = edited(reports["provenance_tampered"], _inflate, tmp_path)
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        load_module_input(path, module=3, expect_module="3")


def test_an_invented_severity_is_refused(reports, tmp_path):
    def _invent(payload):
        payload["findings"][0]["severity"] = "CATASTROPHIC"

    path = edited(reports["provenance_tampered"], _invent, tmp_path)
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        load_module_input(path, module=3, expect_module="3")


def test_an_invented_confidence_basis_is_refused(reports, tmp_path):
    """The four bases are a closed vocabulary; a fifth would mean nothing."""
    def _invent(payload):
        payload["findings"][0]["confidence_basis"] = "EXPERT_JUDGEMENT"

    path = edited(reports["provenance_tampered"], _invent, tmp_path)
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        load_module_input(path, module=3, expect_module="3")


def test_a_smuggled_field_is_refused(reports, tmp_path):
    """``extra='forbid'`` is the reason a trust score cannot be injected."""
    def _smuggle(payload):
        payload["findings"][0]["trust_score"] = 12

    path = edited(reports["provenance_tampered"], _smuggle, tmp_path)
    with pytest.raises(ConfigError, match="does not satisfy the evidence schema"):
        load_module_input(path, module=3, expect_module="3")


def test_a_deleted_finding_changes_the_disposition_and_stays_attributable(
    reports, tmp_path
):
    """The attack the schema CANNOT stop, and what is done about it instead.

    Deleting a well-formed finding produces a well-formed report. Module 4
    fuses what it is given, so the disposition moves. The defence is not
    detection -- it is that the fused report is cited by id and by content, so
    the edited report is identifiable afterwards.
    """
    honest, _ = assess_pipeline(
        Config(), provenance_report=reports["provenance_tampered"]
    )
    assert honest.provenance_assurance.disposition == "QUARANTINE"

    path = edited(
        reports["provenance_tampered"],
        lambda payload: payload.update({"findings": []}),
        tmp_path,
        name="hollowed.json",
    )
    hollowed, _ = assess_pipeline(Config(), provenance_report=path)
    assert hollowed.provenance_assurance.disposition == "ACCEPT"
    assert hollowed.provenance_assurance.source_report_id is not None
    assert (
        hollowed.provenance_assurance.source_report_id
        == honest.provenance_assurance.source_report_id
    )
    assert hollowed.stable_digest() != honest.stable_digest()


def test_the_report_says_it_does_not_re_verify_its_inputs(reports):
    """Never imply a check that was not performed."""
    report, _ = assess_pipeline(
        Config(), provenance_report=reports["provenance_clean"]
    )
    text = " ".join(report.limitations)
    assert "bounded by its own coverage statement" in text
    assert "never a statement that" in text


# ---------------------------------------------------------------------------
# 2. Malformed input
# ---------------------------------------------------------------------------


def test_a_report_with_no_findings_array_is_refused(tmp_path):
    path = tmp_path / "not-a-report.json"
    path.write_text(json.dumps({"module": "1", "hello": "world"}), encoding="utf-8")
    with pytest.raises(ConfigError, match="does not look like a cvtrust"):
        load_module_input(path, module=1, expect_module="1")


def test_a_findings_object_that_is_not_an_array_is_refused(tmp_path):
    path = tmp_path / "wrong-shape.json"
    path.write_text(
        json.dumps({"module": "1", "findings": {"0": {}}}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="must be an array"):
        load_module_input(path, module=1, expect_module="1")


def test_a_json_scalar_is_refused(tmp_path):
    path = tmp_path / "scalar.json"
    path.write_text("42", encoding="utf-8")
    with pytest.raises(ConfigError, match="not a JSON object"):
        load_module_input(path, module=1, expect_module="1")


def test_broken_json_is_refused_rather_than_ignored(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"module": "1", "findings": [', encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_module_input(path, module=1, expect_module="1")


def test_a_model_report_in_the_dataset_slot_is_refused(reports):
    """A scope silently assessed by the wrong evidence is the worst outcome."""
    with pytest.raises(ConfigError, match="is not the module"):
        load_module_input(reports["provenance_clean"], module=1, expect_module="1")


# ---------------------------------------------------------------------------
# 3. Withheld evidence
# ---------------------------------------------------------------------------


def test_withholding_every_report_does_not_produce_accept():
    """The cheapest attack in a multi-contributor pipeline."""
    report, _ = assess_pipeline(Config())
    assert report.decision.disposition is AssuranceDisposition.NOT_ASSESSED
    scopes = [a for a in report.decision.unassessed_areas if a.kind == "scope"]
    assert {a.area for a in scopes} == {
        "dataset", "model", "provenance", "distribution"
    }
    # The gap is named at attack-class granularity too, so the report cannot be
    # read as 'four small holes' when it is in fact everything.
    assert any(a.kind == "attack_class" for a in report.decision.unassessed_areas)


def test_withholding_one_report_cannot_be_hidden_by_the_others(reports):
    """Three green scopes must not average away the fourth's absence."""
    report, _ = assess_pipeline(
        Config(),
        dataset_report=reports["dataset"],
        provenance_report=reports["provenance_clean"],
    )
    assert report.decision.disposition is AssuranceDisposition.NOT_ASSESSED
    named = {
        area.area
        for area in report.decision.unassessed_areas
        if area.kind == "scope"
    }
    assert named == {"model", "distribution"}
    assert report.model_assurance.disposition == "NOT_ASSESSED"


def test_an_unassessed_scope_carries_a_remedy_not_an_excuse(reports):
    report, _ = assess_pipeline(Config(), dataset_report=reports["dataset"])
    model_gap = next(
        area
        for area in report.decision.unassessed_areas
        if area.kind == "scope" and area.area == "model"
    )
    assert "cvtrust model assess" in model_gap.remedy
    assert "no model assessment was supplied" in model_gap.reason
    # and the attack classes that gap leaves open are named individually
    assert any(
        area.kind == "attack_class" and "backdoor" in area.area
        for area in report.decision.unassessed_areas
    )


def test_a_supplied_but_empty_report_is_not_the_same_as_no_report(reports, tmp_path):
    """'The detector ran and found nothing' vs 'the detector never ran'."""
    empty = edited(
        reports["dataset"],
        lambda payload: payload.update({"findings": []}),
        tmp_path,
        name="empty-dataset.json",
    )
    supplied, _ = assess_pipeline(Config(), dataset_report=empty)
    withheld, _ = assess_pipeline(Config())
    assert supplied.dataset_assurance.disposition == "ACCEPT"
    assert withheld.dataset_assurance.disposition == "NOT_ASSESSED"


# ---------------------------------------------------------------------------
# 4. Contradictory evidence
# ---------------------------------------------------------------------------


def test_a_valid_record_over_a_tampered_one_keeps_both_facts(reports):
    """Provenance and dataset are separate facts and stay separate."""
    report, _ = assess_pipeline(
        Config(),
        dataset_report=reports["dataset"],
        provenance_report=reports["provenance_tampered"],
    )
    assert report.dataset_assurance.disposition == "ACCEPT"
    assert report.provenance_assurance.disposition == "QUARANTINE"
    assert report.decision.disposition is AssuranceDisposition.QUARANTINE


def test_contradicting_evidence_is_listed_not_reconciled(reports):
    report, _ = assess_pipeline(
        Config(),
        dataset_report=reports["dataset"],
        provenance_report=reports["provenance_tampered"],
    )
    assert report.decision.contradicting_evidence or report.decision.conflicts


# ---------------------------------------------------------------------------
# 5. Configuration and policy manipulation
# ---------------------------------------------------------------------------


def test_an_impossible_alpha_is_refused():
    from pydantic import ValidationError

    from cvtrust.core.config import ShiftConfig

    with pytest.raises(ValidationError):
        ShiftConfig(alpha=0.0)
    with pytest.raises(ValidationError):
        ShiftConfig(alpha=0.9)


def test_a_sample_floor_cannot_be_lowered_to_nothing():
    """Setting the floor to 1 would let three samples produce a verdict."""
    from pydantic import ValidationError

    from cvtrust.core.config import ShiftConfig

    with pytest.raises(ValidationError):
        ShiftConfig(min_current_samples=1)
    with pytest.raises(ValidationError):
        ShiftConfig(min_reference_samples=2)


def test_a_permutation_budget_cannot_be_set_below_the_resolution_floor():
    from pydantic import ValidationError

    from cvtrust.core.config import ShiftConfig

    with pytest.raises(ValidationError):
        ShiftConfig(permutations=9)


def test_the_corroboration_floor_is_bounded():
    from pydantic import ValidationError

    from cvtrust.core.config import AssuranceConfig

    with pytest.raises(ValidationError):
        AssuranceConfig(corroboration_min_confidence=1.4)


def test_an_unknown_configuration_key_is_refused():
    """Config forbids extras, so a policy knob cannot be smuggled in."""
    from pydantic import ValidationError

    from cvtrust.core.config import AssuranceConfig

    with pytest.raises(ValidationError):
        AssuranceConfig(quarantine_on_shift=True)


def test_loosening_the_configuration_changes_the_recorded_configuration(reports):
    """A relaxed run must be identifiable as one."""
    loose = Config()
    loose = loose.model_copy(
        update={
            "assurance": loose.assurance.model_copy(
                update={"corroboration_min_confidence": 0.95}
            )
        }
    )
    strict_report, _ = assess_pipeline(
        Config(), provenance_report=reports["provenance_tampered"]
    )
    loose_report, _ = assess_pipeline(
        loose, provenance_report=reports["provenance_tampered"]
    )
    assert loose_report.configuration["assurance"]["corroboration_min_confidence"] == 0.95
    assert loose_report.configuration["config_hash"] != strict_report.configuration["config_hash"]


def test_a_deterministic_failure_survives_every_configuration_loosening(reports):
    """The floor exists for statistical evidence and must not reach the crypto.

    An operator who raises the corroboration floor to 0.95 is saying 'ignore
    weak statistical evidence'. If that also silenced a failed signature check,
    the knob would be a switch for turning off the cryptography.
    """
    loose = Config()
    loose = loose.model_copy(
        update={
            "assurance": loose.assurance.model_copy(
                update={
                    "corroboration_min_confidence": 0.99,
                    "corroboration_min_severity": "CRITICAL",
                }
            )
        }
    )
    report, _ = assess_pipeline(
        loose, provenance_report=reports["provenance_tampered"]
    )
    assert report.provenance_assurance.disposition == "QUARANTINE"


def test_the_rule_table_is_published_in_full(reports):
    """A policy an analyst cannot read is a policy they cannot challenge."""
    report, _ = assess_pipeline(Config(), dataset_report=reports["dataset"])
    rules = report.policy["rules"]
    assert len(rules) >= 20
    for rule in rules:
        assert rule["id"]
        assert rule["scope"]
        assert rule["if"], rule["id"]
        assert rule["then"], rule["id"]
        assert rule["rationale"], rule["id"]


def test_the_policy_version_is_bound_into_the_decision(reports):
    report, _ = assess_pipeline(Config(), dataset_report=reports["dataset"])
    assert report.decision.policy_version == report.policy["policy_version"]
    assert report.run.detector_versions["assurance_policy"] == (
        report.decision.policy_version
    )


def test_every_fired_rule_is_one_of_the_published_rules(reports):
    """No rule may fire that the report did not declare."""
    report, _ = assess_pipeline(
        Config(),
        dataset_report=reports["dataset"],
        provenance_report=reports["provenance_tampered"],
    )
    published = {rule["id"] for rule in report.policy["rules"]}
    fired = {rule.rule_id for rule in report.decision.fired_rules}
    assert fired
    assert fired <= published


def test_a_decision_cannot_be_reached_with_no_governing_rule(reports):
    report, _ = assess_pipeline(
        Config(),
        dataset_report=reports["dataset"],
        provenance_report=reports["provenance_clean"],
    )
    for scope in report.scopes():
        assert scope.governing_rule, scope.scope


def test_an_evidence_item_cannot_cite_a_finding_that_was_not_supplied(reports):
    """Lineage must terminate in a real upstream finding."""
    report, result = assess_pipeline(
        Config(), provenance_report=reports["provenance_tampered"]
    )
    supplied = {finding.finding_id for finding in report.source_findings}
    for evidence in result.graph.evidence:
        assert evidence.finding_id in supplied
    for reference in report.decision.supporting_evidence:
        assert reference.finding_id in supplied
