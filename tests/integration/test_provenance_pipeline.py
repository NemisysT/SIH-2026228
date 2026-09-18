"""End-to-end provenance: create, sign, verify, report.

Also the place where Module 3's one hard architectural rule is asserted: a
cryptographic verification failure and an ML detector output are different kinds
of evidence, and nothing in this pipeline may turn one into the other.
"""

from __future__ import annotations

import pytest

from cvtrust.core.config import Config
from cvtrust.core.evidence import Category, ConfidenceBasis, Coverage
from cvtrust.provenance import (
    ExpectedBinding,
    FailureCode,
    ProvenanceLog,
    ReplayDatabase,
    TrustStore,
    build_anchor,
    generate_keypair,
    sign_record,
    trust_key,
    verify_record,
)
from cvtrust.provenance.trust import KeyPurpose, ValidityPolicy, revoke_key
from cvtrust.provenance_pipeline import verify_log, verify_single_record
from cvtrust.reporting.provenance_render import (
    render_provenance_markdown,
    render_provenance_report,
)


@pytest.fixture
def config():
    return Config()


# --- the happy path --------------------------------------------------------


def test_create_sign_verify_round_trip(make_record, signing_key, trust_store_with, config):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    verification = verify_record(entry, trust_store=trust_store_with)
    assert verification.valid
    assert verification.failures == (FailureCode.VALID,)


def test_a_clean_log_verifies_end_to_end(signed_log, trust_store_with, config):
    report, run, database = verify_log(
        signed_log, config,
        trust_store=trust_store_with,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(signed_log.entries),
    )
    assert report.summary.overall == "PROVENANCE VERIFIED"
    assert report.summary.records_valid == len(signed_log)
    assert report.summary.findings_total == 0
    assert report.summary.chain_status == "INTACT"
    assert report.summary.truncation_status == "VERIFIED_COMPLETE"
    assert run.run_id
    assert database is not None and len(database) == len(signed_log)


def test_the_report_renders_to_console_and_markdown(signed_log, trust_store_with, config):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    render_provenance_report(report, full=True)
    markdown = render_provenance_markdown(report)
    for heading in ("What was verified", "Chain status", "Verification matrix",
                    "Records", "Findings", "Coverage", "Limitations"):
        assert heading in markdown


def test_the_report_id_is_derived_from_its_content(signed_log, trust_store_with, config):
    """Content-addressed, like Module 1 and 2's report ids.

    The id is the digest of the report as built, so two verifications of the
    same log under the same configuration produce the same id and a reviewer can
    diff them. As in the other two modules, the id is folded into the report
    after the digest is taken, so re-digesting a finished report does not
    reproduce its own id -- the property under test is reproducibility across
    runs, not self-reference.
    """
    first, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    second, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    assert first.report_id.startswith("PR-")
    assert len(first.report_id) == 19
    assert first.report_id == second.report_id


# --- what a missing input does to the report ------------------------------


def test_no_trust_store_is_reported_as_unassessed_not_as_clean(signed_log, config):
    report, _, _ = verify_log(signed_log, config, trust_store=None)
    assert all(FailureCode.UNKNOWN_KEY.value in r.failures for r in report.records)
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "provenance_key_trust"
    )
    assert entry.coverage is Coverage.NOT_ASSESSED
    assert "no trust store was supplied" in (entry.reason or "")


def test_no_replay_database_is_reported_as_unassessed(signed_log, trust_store_with, config):
    report, _, database = verify_log(
        signed_log, config, trust_store=trust_store_with, replay_database=None
    )
    assert database is None
    assert all(r.replay_verdict == "NOT_CHECKED" for r in report.records)
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "inference_replay"
    )
    assert entry.coverage is Coverage.NOT_ASSESSED


def test_no_anchor_means_truncation_is_not_detectable(signed_log, trust_store_with, config):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    assert report.summary.truncation_status == "NOT_DETECTABLE"
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "chain_truncation"
    )
    assert entry.coverage is Coverage.NOT_ASSESSED


def test_no_expectation_degrades_tampering_coverage_to_partial(
    signed_log, trust_store_with, config
):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    entry = next(
        e for e in report.coverage.entries if e.attack_class == "inference_tampering"
    )
    assert entry.coverage is Coverage.PARTIAL
    assert "no independent expectation" in (entry.reason or "")


def test_unchecked_checks_are_visible_in_the_matrix(signed_log, trust_store_with, config):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    assert "model_digest_match" in report.matrix.never_checked()
    assert report.matrix.checks["model_digest_match"]["NOT_CHECKED"] == len(signed_log)


# --- verifying one record outside a log -----------------------------------


def test_a_lone_record_reports_its_position_as_unchecked(
    make_record, signing_key, trust_store_with, config
):
    """A record that verifies alone can still have been deleted from a log."""
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    report, _, _ = verify_single_record(entry, config, trust_store=trust_store_with)
    verification = report.verifications[0]
    positions = {c["name"]: c["outcome"] for c in verification["checks"]}
    assert positions["previous_record_valid"] == "NOT_CHECKED"
    assert positions["sequence_valid"] == "NOT_CHECKED"
    assert report.chain["status"] == "NOT_ASSESSED"
    assert report.records[0].valid


def test_a_record_lifted_from_mid_log_is_not_accused_of_breaking_a_chain(
    signed_log, trust_store_with, config
):
    """The false alarm that separating the two questions exists to prevent.

    A record from the middle of a log carries a non-null back-pointer and a
    non-zero sequence number — which is exactly what a *log* missing its
    beginning looks like. Verified as a one-entry log it would be reported
    front-truncated and chain-broken. It is neither: it is a perfectly good
    record, and where it sat is simply a question nobody asked.
    """
    middle = signed_log.entries[2]
    assert middle.record.sequence.previous_record_digest is not None
    assert middle.record.sequence.sequence_number == 2

    report, _, _ = verify_single_record(middle, config, trust_store=trust_store_with)
    assert report.records[0].valid
    assert FailureCode.CHAIN_BREAK.value not in report.records[0].failures
    assert report.summary.overall.startswith("PROVENANCE VERIFIED")
    assert report.chain["truncation_status"] == "NOT_ASSESSED"

    # And ordering is declared unassessed rather than left looking supported.
    ordering = next(
        e for e in report.coverage.entries if e.attack_class == "record_reordering"
    )
    assert ordering.coverage is Coverage.NOT_ASSESSED

    # The same record inside its log verifies its position too.
    in_log, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    assert in_log.records[2].valid
    assert in_log.chain["status"] == "INTACT"


def test_verifying_a_record_outside_any_log_is_still_meaningful(
    make_record, signing_key, trust_store_with
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    verification = verify_record(entry, trust_store=trust_store_with)
    chain_check = verification.check("previous_record_valid")
    assert chain_check is not None
    assert chain_check.outcome.value == "NOT_CHECKED"
    assert "not as part of a log" in chain_check.detail


# --- expectations ----------------------------------------------------------


def test_a_matching_expectation_passes(make_record, signing_key, trust_store_with):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    expected = ExpectedBinding(
        raw_input_digest=entry.record.input.raw_input_digest,
        model_file_sha256=entry.record.model.file_sha256,
        output_digest=entry.record.output.digest,
        source="test",
    )
    assert verify_record(entry, trust_store=trust_store_with, expected=expected).valid


def test_a_mismatched_model_expectation_is_a_model_mismatch(
    make_record, signing_key, trust_store_with
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    verification = verify_record(
        entry,
        trust_store=trust_store_with,
        expected=ExpectedBinding(model_file_sha256="f" * 64, source="test"),
    )
    assert FailureCode.MODEL_MISMATCH in verification.failures
    # The signature is untouched, so the record is NOT cryptographically broken.
    assert verification.check("signature_valid").outcome.value == "PASS"


def test_a_mismatched_input_expectation_is_an_input_mismatch(
    make_record, signing_key, trust_store_with
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    verification = verify_record(
        entry,
        trust_store=trust_store_with,
        expected=ExpectedBinding(raw_input_digest="f" * 64, source="test"),
    )
    assert FailureCode.INPUT_MISMATCH in verification.failures


def test_an_expectation_for_a_field_the_record_omits_fails(
    make_record, signing_key, trust_store_with
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    verification = verify_record(
        entry,
        trust_store=trust_store_with,
        expected=ExpectedBinding(normalized_input_digest="a" * 64, source="test"),
    )
    assert FailureCode.MISSING_FIELD in verification.failures


# --- key lifecycle ---------------------------------------------------------


def test_key_rotation_lets_both_keys_verify(make_record, signing_key, config):
    old_key, old_info = signing_key
    new_key, new_info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=old_info.public_key_hex, label="old")
    store = trust_key(store, public_key=new_info.public_key_hex, label="new")

    provenance_log = ProvenanceLog.new("rotating")
    for index in range(4):
        provenance_log.append_signed(
            lambda sequence_number, previous_record_digest, index=index: make_record(
                payload=f"img-{index}".encode(),
                log_id="rotating",
                sequence_number=sequence_number,
                previous_record_digest=previous_record_digest,
            ),
            old_key if index < 2 else new_key,
        )
    report, _, _ = verify_log(provenance_log, config, trust_store=store)
    assert report.summary.records_valid == 4
    assert len({r.signing_key_id for r in report.records}) == 2


def test_a_revoked_key_is_distinguished_from_an_unknown_one(
    make_record, signing_key, trust_store_with
):
    key, info = signing_key
    entry = sign_record(make_record(), key)
    revoked = revoke_key(trust_store_with, info.key_id, reason="rotated out")

    unknown_store = TrustStore.empty()
    assert FailureCode.UNKNOWN_KEY in verify_record(
        entry, trust_store=unknown_store
    ).failures
    revoked_result = verify_record(entry, trust_store=revoked)
    assert FailureCode.REVOKED_KEY in revoked_result.failures
    assert FailureCode.UNKNOWN_KEY not in revoked_result.failures


def test_a_revoked_key_reports_whether_the_record_claims_to_predate_it(
    make_record, signing_key, trust_store_with
):
    key, info = signing_key
    entry = sign_record(make_record(timestamp="2026-01-01T00:00:00Z"), key)
    revoked = revoke_key(
        trust_store_with, info.key_id, reason="compromised",
        revoked_at="2026-06-01T00:00:00Z",
    )
    check = verify_record(entry, trust_store=revoked).check("signed_before_revocation")
    assert check is not None
    assert check.observation["claims_to_predate_revocation"] is True
    assert check.observation["timestamp_is_self_asserted"] is True


def test_the_validity_policy_is_recorded_in_the_result(
    make_record, signing_key, trust_store_with
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    at_record = verify_record(
        entry, trust_store=trust_store_with,
        validity_policy=ValidityPolicy.AT_RECORD_TIMESTAMP,
    )
    at_now = verify_record(
        entry, trust_store=trust_store_with,
        validity_policy=ValidityPolicy.AT_VERIFICATION_TIME,
    )
    assert at_record.validity_policy is ValidityPolicy.AT_RECORD_TIMESTAMP
    assert at_now.validity_policy is ValidityPolicy.AT_VERIFICATION_TIME


def test_an_expired_window_fails_under_the_record_timestamp_policy(
    make_record, signing_key
):
    key, info = signing_key
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        valid_until="2026-01-01T00:00:00Z",
    )
    entry = sign_record(make_record(timestamp="2026-06-01T00:00:00Z"), key)
    assert FailureCode.KEY_EXPIRED in verify_record(entry, trust_store=store).failures


def test_a_key_authorised_for_anchors_cannot_sign_inference_records(
    make_record, signing_key
):
    key, info = signing_key
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        purpose=KeyPurpose.LOG_ANCHOR,
    )
    entry = sign_record(make_record(), key)
    assert FailureCode.KEY_PURPOSE_MISMATCH in verify_record(
        entry, trust_store=store
    ).failures


# --- the architectural rule (§27) -----------------------------------------


def test_every_provenance_finding_is_deterministic(signed_log, config):
    """No ML confidence may ever enter a cryptographic verdict, or vice versa."""
    report, _, _ = verify_log(signed_log, config, trust_store=None)
    assert report.findings
    for finding in report.findings:
        assert finding.confidence_basis is ConfidenceBasis.DETERMINISTIC
        assert finding.confidence == 1.0
        assert finding.category is Category.INFERENCE


def test_the_provenance_report_schema_has_no_aggregate_score(
    signed_log, trust_store_with, config
):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    payload = report.model_dump(mode="json")
    forbidden = ("integrity_score", "trust_score", "overall_score", "trust_percentage")
    for name in forbidden:
        assert name not in payload
        assert name not in payload["summary"]


def test_no_provenance_report_field_says_a_pipeline_is_safe(
    signed_log, trust_store_with, config
):
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    assert "safe" not in report.summary.overall.lower()
    assert any("not about the inference" in line for line in report.limitations)


def test_a_valid_provenance_chain_says_nothing_about_model_quality(
    signed_log, trust_store_with, config
):
    """The rule stated positively: a perfect chain over a bad model is possible."""
    report, _, _ = verify_log(
        signed_log, config, trust_store=trust_store_with,
        anchor=build_anchor(signed_log.entries),
    )
    assert report.summary.overall.startswith("PROVENANCE VERIFIED")
    model_classes = {
        e.attack_class for e in report.coverage.entries if e.owning_module == 2
    }
    for attack_class in model_classes:
        entry = next(
            e for e in report.coverage.entries if e.attack_class == attack_class
        )
        assert entry.coverage is Coverage.NOT_ASSESSED


# --- integration with Module 2 --------------------------------------------


@pytest.mark.slow
def test_a_record_binds_a_real_module_2_model_manifest(
    reference_onnx, signing_key, config, make_record
):
    """Module 3 consumes Module 2's identity rather than recomputing it."""
    from cvtrust.model_pipeline import load_model
    from cvtrust.models.manifest import build_model_manifest
    from cvtrust.provenance.binding import (
        bind_config,
        bind_input_bytes,
        bind_model_manifest,
        bind_output,
    )
    from cvtrust.provenance.output import classification_output
    from cvtrust.provenance.record import create_provenance_record

    handle, adapter = load_model(reference_onnx, config, None)
    manifest = build_model_manifest(handle, adapter)
    binding = bind_model_manifest(manifest)
    assert binding.file_sha256 == manifest.file_sha256
    assert binding.graph_digest == manifest.graph_digest
    assert binding.parameter_digest == manifest.parameter_digest

    key, info = signing_key
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    record = create_provenance_record(
        input_binding=bind_input_bytes(b"real-image"),
        model_binding=binding,
        preprocessing=bind_config({"resize": [32, 32]}),
        inference=bind_config({"top_k": 1}),
        output=bind_output(classification_output({"class_0": 0.9})),
        log_id="module-2-integration",
    )
    entry = sign_record(record, key)

    matching = ExpectedBinding.from_model_manifest(manifest)
    assert verify_record(entry, trust_store=store, expected=matching).valid

    # And a different model's manifest must contradict it.
    wrong = matching.model_copy(update={"model_file_sha256": "f" * 64})
    assert FailureCode.MODEL_MISMATCH in verify_record(
        entry, trust_store=store, expected=wrong
    ).failures


@pytest.mark.slow
def test_a_record_binds_a_real_dataset_sample_digest(clean_root, signing_key):
    """Input binding over a real image from the Module 1 corpus."""
    from cvtrust.core.hashing import sha256_file
    from cvtrust.provenance.binding import bind_input

    image = next(iter(sorted(clean_root.rglob("*.jpg"))))
    binding = bind_input(image)
    assert binding.raw_input_digest == sha256_file(image)
    assert binding.raw_input_size_bytes == image.stat().st_size
    # The path is recorded but is not the identity.
    assert binding.locator == str(image)
