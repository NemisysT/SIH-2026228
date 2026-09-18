"""Every provenance attack the lab models, verified against ground truth.

This file is the security case for Module 3.  It runs the whole scenario matrix
through the real verifier and asserts **exact** agreement with each scenario's
declared expectations — an extra failure is as much a bug as a missed one — and
then asserts a handful of properties the scenario matrix cannot express as a
per-position failure set.
"""

from __future__ import annotations

import json

import pytest

from cvtrust.attack_lab.provenance_attacks import SCENARIOS
from cvtrust.attack_lab.provenance_evaluate import evaluate_lab, evaluate_scenario
from cvtrust.core.config import Config
from cvtrust.provenance import (
    ExpectedBinding,
    FailureCode,
    ReplayDatabase,
    TrustStore,
    sign_record,
    trust_key,
    verify_chain,
    verify_record,
)
from cvtrust.provenance.log import ProvenanceLog
from cvtrust.provenance_pipeline import verify_log


@pytest.fixture
def config():
    return Config()


# --- the scenario matrix ---------------------------------------------------


def test_the_lab_covers_at_least_twenty_scenarios():
    assert len(SCENARIOS) >= 20


def test_every_scenario_was_built(provenance_lab):
    assert set(provenance_lab["scenarios"]) == set(SCENARIOS)


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_each_scenario_reproduces_its_declared_outcome_exactly(
    provenance_lab, config, scenario
):
    result = evaluate_scenario(
        provenance_lab["root"] / scenario, config, lab_root=provenance_lab["root"]
    )
    assert result.passed, (
        f"{scenario} did not reproduce its ground truth: "
        + "; ".join(result.mismatches)
    )


def test_the_whole_lab_evaluates_green(provenance_lab, config):
    report = evaluate_lab(provenance_lab["root"], config)
    assert report.all_passed
    assert report.scenarios_total == len(SCENARIOS)


def test_ground_truth_lives_outside_the_verified_artifacts(provenance_lab):
    """A detector that can read the answer key measures nothing."""
    for scenario in provenance_lab["scenarios"].values():
        contents = scenario.log_path.read_text()
        assert "ground_truth" not in contents
        assert "expected_failures_by_position" not in contents
        assert (scenario.out_dir / "ground_truth.json").is_file()


def test_the_clean_scenario_produces_no_findings(provenance_lab, config):
    """The false-positive guard: a lab of only attacks measures nothing."""
    result = evaluate_scenario(
        provenance_lab["root"] / "clean", config, lab_root=provenance_lab["root"]
    )
    assert result.findings_total == 0
    assert result.overall.startswith("PROVENANCE VERIFIED")


def test_key_rotation_is_not_treated_as_an_attack(provenance_lab, config):
    result = evaluate_scenario(
        provenance_lab["root"] / "key_rotation", config, lab_root=provenance_lab["root"]
    )
    assert result.findings_total == 0


def test_legitimate_reprocessing_is_not_treated_as_replay(provenance_lab, config):
    """Case B of the brief, as a security test rather than only a unit test."""
    result = evaluate_scenario(
        provenance_lab["root"] / "legitimate_reprocess", config,
        lab_root=provenance_lab["root"],
    )
    assert result.findings_total == 0
    assert all(p.observed_replay == "DUPLICATE_SUBJECT" for p in result.positions)


# --- properties the per-position matrix cannot express --------------------


def test_an_adversary_with_a_key_is_caught_only_by_trust_and_expectation(
    provenance_lab, config
):
    """The most instructive case: perfect cryptography, wrong facts."""
    directory = provenance_lab["root"] / "modified_model_digest"
    report, _, _ = verify_log(
        ProvenanceLog.load(directory / "log.jsonl"),
        config,
        trust_store=TrustStore.load(directory / "trust_store.json"),
        expected=_lab_expectation(provenance_lab),
    )
    forged = report.verifications[1]
    outcomes = {c["name"]: c["outcome"] for c in forged["checks"]}
    assert outcomes["signature_valid"] == "PASS"
    assert outcomes["record_id_matches_content"] == "PASS"
    assert outcomes["key_trusted"] == "FAIL"
    assert outcomes["model_digest_match"] == "FAIL"


def test_a_deleted_record_is_invisible_without_the_chain(provenance_lab, config):
    """The case that justifies the chain: every surviving record verifies."""
    directory = provenance_lab["root"] / "deleted_record"
    entries = ProvenanceLog.load(directory / "log.jsonl").entries
    store = TrustStore.load(directory / "trust_store.json")
    # Record by record, with no chain context, the log looks clean.
    assert all(verify_record(entry, trust_store=store).valid for entry in entries)
    # With the chain, it does not.
    assert not verify_chain(entries).intact


def test_a_truncated_log_is_invisible_without_an_anchor(provenance_lab, config):
    """The honest negative result, asserted."""
    directory = provenance_lab["root"] / "truncated_log"
    provenance_log = ProvenanceLog.load(directory / "log.jsonl")
    store = TrustStore.load(directory / "trust_store.json")

    without, _, _ = verify_log(provenance_log, config, trust_store=store)
    assert without.summary.overall.startswith("PROVENANCE VERIFIED")
    assert without.summary.truncation_status == "NOT_DETECTABLE"

    anchor_payload = json.loads(
        (provenance_lab["root"] / "_clean" / "anchor.json").read_text()
    )
    from cvtrust.provenance.chain import LogAnchor

    with_anchor, _, _ = verify_log(
        provenance_log, config, trust_store=store,
        anchor=LogAnchor.model_validate(anchor_payload),
    )
    assert with_anchor.summary.truncation_status == "TRUNCATION_DETECTED"
    assert with_anchor.summary.findings_total > 0


def test_a_malformed_line_does_not_suppress_the_rest_of_the_log(
    provenance_lab, config
):
    directory = provenance_lab["root"] / "malformed_record"
    provenance_log = ProvenanceLog.load(directory / "log.jsonl")
    report, _, _ = verify_log(
        provenance_log, config,
        trust_store=TrustStore.load(directory / "trust_store.json"),
    )
    assert report.summary.malformed_lines == 1
    assert report.summary.records_valid == len(provenance_log.entries)
    assert any(
        f.title == "Provenance log line is not a valid record" for f in report.findings
    )


def test_a_key_id_forgery_does_not_borrow_a_trusted_key_s_status(
    provenance_lab, config
):
    directory = provenance_lab["root"] / "key_id_forgery"
    report, _, _ = verify_log(
        ProvenanceLog.load(directory / "log.jsonl"), config,
        trust_store=TrustStore.load(directory / "trust_store.json"),
    )
    forged = report.verifications[2]
    outcomes = {c["name"]: c["outcome"] for c in forged["checks"]}
    assert outcomes["key_trusted"] == "NOT_APPLICABLE"
    assert report.records[2].key_status == "UNKNOWN"


# --- input binding against a real artifact --------------------------------


def test_swapping_the_input_artifact_is_detected(tmp_path, signing_key, make_record):
    """Bound to content, so replacing the file contradicts the record."""
    from cvtrust.core.hashing import sha256_file
    from cvtrust.provenance.binding import bind_input

    key, info = signing_key
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    image = tmp_path / "input.png"
    image.write_bytes(b"the-original-image")

    from cvtrust.provenance.binding import bind_config, bind_output
    from cvtrust.provenance.output import classification_output
    from cvtrust.provenance.record import create_provenance_record

    record = create_provenance_record(
        input_binding=bind_input(image),
        model_binding=make_record().model,
        preprocessing=bind_config({"resize": [8, 8]}),
        inference=bind_config({"top_k": 1}),
        output=bind_output(classification_output({"a": 0.9})),
        log_id="artifact-test",
    )
    entry = sign_record(record, key)

    assert verify_record(
        entry, trust_store=store,
        expected=ExpectedBinding(raw_input_digest=sha256_file(image), source="disk"),
    ).valid

    image.write_bytes(b"a-different-image")
    swapped = verify_record(
        entry, trust_store=store,
        expected=ExpectedBinding(raw_input_digest=sha256_file(image), source="disk"),
    )
    assert FailureCode.INPUT_MISMATCH in swapped.failures
    # The record itself is untouched: this is a deployment fact, not a forgery.
    assert swapped.check("signature_valid").outcome.value == "PASS"


# --- replay semantics, all three cases ------------------------------------


def test_case_a_the_same_signed_record_submitted_twice(signed_log, config, trust_store_with):
    database = ReplayDatabase.empty()
    first, _, database = verify_log(
        signed_log, config, trust_store=trust_store_with, replay_database=database
    )
    assert first.summary.replay_detected == 0

    second, _, _ = verify_log(
        signed_log, config, trust_store=trust_store_with, replay_database=database
    )
    assert second.summary.replay_detected == len(signed_log)
    assert all(r.replay_verdict == "REPLAY_EXACT" for r in second.records)

    # Both facts survive, separately. The records are byte-identical to the
    # originals, so their integrity is untouched -- replay is an objection to
    # the context, not to the record -- and the verdict still fails.
    assert all(r.cryptographically_intact for r in second.records)
    assert not any(r.valid for r in second.records)
    for verification in second.verifications:
        outcomes = {c["name"]: c["outcome"] for c in verification["checks"]}
        assert outcomes["signature_valid"] == "PASS"
        assert outcomes["replay_detected"] == "FAIL"


def test_case_b_the_same_image_processed_twice_is_not_replay(
    signing_key, trust_store_with, config, make_record
):
    key, _ = signing_key
    first = ProvenanceLog.new("run-1")
    first.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            log_id="run-1", sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )
    second = ProvenanceLog.new("run-2")
    second.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            log_id="run-2", sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )

    database = ReplayDatabase.empty()
    _, _, database = verify_log(
        first, config, trust_store=trust_store_with, replay_database=database
    )
    report, _, _ = verify_log(
        second, config, trust_store=trust_store_with, replay_database=database
    )
    assert report.summary.replay_detected == 0
    assert report.records[0].replay_verdict == "DUPLICATE_SUBJECT"
    assert report.records[0].valid


def test_case_c_an_old_record_spliced_into_a_later_chain(
    signing_key, trust_store_with, config, make_record
):
    """Two independent mechanisms fire, and neither depends on the other."""
    key, _ = signing_key
    original = ProvenanceLog.new("main")
    for index in range(3):
        original.append_signed(
            lambda sequence_number, previous_record_digest, index=index: make_record(
                payload=f"img-{index}".encode(), log_id="main",
                sequence_number=sequence_number,
                previous_record_digest=previous_record_digest,
            ),
            key,
        )

    database = ReplayDatabase.empty()
    _, _, database = verify_log(
        original, config, trust_store=trust_store_with, replay_database=database
    )

    spliced = list(original.entries) + [original.entries[1]]
    report, _, _ = verify_log(
        spliced, config, trust_store=trust_store_with, replay_database=database
    )
    assert report.records[3].replay_verdict == "REPLAY_EXACT"
    assert FailureCode.CHAIN_BREAK.value in report.records[3].failures
    assert FailureCode.REPLAY.value in report.records[3].failures


def test_a_replay_verdict_and_a_signature_verdict_are_independent(
    signed_log, trust_store_with, config
):
    """A replayed record is still correctly signed, and the report says both."""
    database = ReplayDatabase.empty()
    for entry in signed_log.entries:
        database = database.record(entry)
    report, _, _ = verify_log(
        signed_log, config, trust_store=trust_store_with, replay_database=database
    )
    for verification in report.verifications:
        outcomes = {c["name"]: c["outcome"] for c in verification["checks"]}
        assert outcomes["signature_valid"] == "PASS"
        assert outcomes["replay_detected"] == "FAIL"


# --- the taxonomy ----------------------------------------------------------


def test_every_failure_code_except_valid_has_a_policy():
    from cvtrust.provenance.findings import FAILURE_POLICY, FAILURE_TITLE

    codes = {code for code in FailureCode if code is not FailureCode.VALID}
    assert set(FAILURE_POLICY) == codes
    assert set(FAILURE_TITLE) == codes


def test_verification_never_stops_at_the_first_failure(signing_key, make_record):
    """A record with several defects reports all of them."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    broken = entry.model_copy(
        update={
            "record": entry.record.model_copy(
                update={"schema_version": "9.9", "nonce": "   "}
            )
        }
    )
    failures = set(verify_record(broken, trust_store=TrustStore.empty()).failures)
    assert {
        FailureCode.UNSUPPORTED_SCHEMA,
        FailureCode.MISSING_FIELD,
        FailureCode.INVALID_SIGNATURE,
        FailureCode.SELF_INCONSISTENT_RECORD,
        FailureCode.UNKNOWN_KEY,
    } <= failures


def test_valid_is_never_reported_alongside_a_failure(signed_log):
    for entry in signed_log.entries:
        failures = verify_record(entry, trust_store=TrustStore.empty()).failures
        assert FailureCode.VALID not in failures


def _lab_expectation(provenance_lab) -> ExpectedBinding:
    manifest = json.loads(
        (provenance_lab["root"] / "lab_manifest.json").read_text()
    )
    return ExpectedBinding.model_validate(manifest["expected_source"])
