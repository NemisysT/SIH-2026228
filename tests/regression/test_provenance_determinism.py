"""Determinism of the provenance machinery.

Two properties, and the second is unusual enough to be worth naming.

**Canonicalisation is reproducible**, so a record built twice from the same
inputs produces the same bytes, the same digest and the same id. Without that,
nothing else in the module means anything.

**Signing is reproducible too.** Ed25519 signatures are deterministic (RFC
8032), so two independently produced logs over the same inputs are byte-identical
down to the signature. That is why the lab can be regenerated and diffed rather
than merely re-run, and it is one of the reasons Ed25519 was chosen over ECDSA,
whose per-signature nonce would make every regeneration differ.
"""

from __future__ import annotations

import json

from cvtrust.attack_lab.provenance_attacks import (
    build_clean,
    build_lab,
    lab_nonce,
    lab_signing_key,
)
from cvtrust.attack_lab.provenance_evaluate import evaluate_lab
from cvtrust.core.config import Config
from cvtrust.provenance import (
    ReplayDatabase,
    build_anchor,
    sign_record,
)
from cvtrust.provenance_pipeline import verify_log


def test_a_record_built_twice_is_byte_identical(make_record):
    fixed = {"timestamp": "2026-03-01T09:00:00Z", "nonce": "a" * 32}
    first = make_record(**fixed)
    second = make_record(**fixed)
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.record_id == second.record_id


def test_signing_the_same_record_twice_gives_the_same_signature(
    make_record, signing_key
):
    key, _ = signing_key
    record = make_record(timestamp="2026-03-01T09:00:00Z", nonce="a" * 32)
    assert (
        sign_record(record, key).model_dump_json()
        == sign_record(record, key).model_dump_json()
    )


def test_a_lab_signing_key_is_reproducible_from_its_seed():
    """Test-only, and that is exactly why it must be reproducible."""
    from cvtrust.provenance.keys import export_public_key

    first = export_public_key(lab_signing_key(7, "signer-a"))
    second = export_public_key(lab_signing_key(7, "signer-a"))
    other = export_public_key(lab_signing_key(7, "signer-b"))
    assert first == second
    assert first != other


def test_lab_nonces_are_reproducible_and_distinct():
    assert lab_nonce(1, "log", 0) == lab_nonce(1, "log", 0)
    assert lab_nonce(1, "log", 0) != lab_nonce(1, "log", 1)
    assert lab_nonce(1, "log", 0) != lab_nonce(2, "log", 0)


def test_the_clean_baseline_is_reproducible(tmp_path):
    """Two builds from the same seed produce byte-identical logs."""
    first = build_clean(tmp_path / "a", seed=99, record_count=6)
    second = build_clean(tmp_path / "b", seed=99, record_count=6)
    assert first.log.serialise() == second.log.serialise()
    assert first.anchor.head_entry_digest == second.anchor.head_entry_digest
    assert first.trust_store.digest() == second.trust_store.digest()


def test_the_whole_lab_is_reproducible(tmp_path):
    build_lab(tmp_path / "a", seed=101, record_count=6)
    build_lab(tmp_path / "b", seed=101, record_count=6)
    for scenario in sorted(p.name for p in (tmp_path / "a").iterdir() if p.is_dir()):
        first = (tmp_path / "a" / scenario / "log.jsonl").read_bytes()
        second = (tmp_path / "b" / scenario / "log.jsonl").read_bytes()
        assert first == second, f"{scenario} is not reproducible"


def test_verification_is_reproducible(signed_log, trust_store_with):
    """Two verifications of the same log agree on everything but the clock."""
    config = Config()
    first, _, _ = verify_log(
        signed_log, config, trust_store=trust_store_with,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(signed_log.entries),
    )
    second, _, _ = verify_log(
        signed_log, config, trust_store=trust_store_with,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(signed_log.entries),
    )
    assert first.stable_digest() == second.stable_digest()
    assert first.report_id == second.report_id


def test_the_report_digest_excludes_only_timings_and_location(
    signed_log, trust_store_with
):
    config = Config()
    report, _, _ = verify_log(signed_log, config, trust_store=trust_store_with)
    restamped = report.model_copy(update={"generated_at": "2030-01-01T00:00:00Z"})
    assert restamped.stable_digest() == report.stable_digest()


def test_a_changed_configuration_changes_the_run_id(signed_log, trust_store_with):
    strict = Config().merged({"provenance": {"validity_policy": "at_verification_time"}})
    first, run_a, _ = verify_log(signed_log, Config(), trust_store=trust_store_with)
    second, run_b, _ = verify_log(signed_log, strict, trust_store=trust_store_with)
    assert run_a.run_id != run_b.run_id
    assert first.stable_digest() != second.stable_digest()


def test_evaluating_the_lab_twice_gives_the_same_verdicts(tmp_path):
    build_lab(tmp_path / "lab", seed=55, record_count=6)
    config = Config()
    first = evaluate_lab(tmp_path / "lab", config)
    second = evaluate_lab(tmp_path / "lab", config)
    assert [r.report_id for r in first.results] == [r.report_id for r in second.results]
    assert first.all_passed and second.all_passed


def test_the_log_serialisation_is_canonical(signed_log, tmp_path):
    """Every line is canonical JSON, so a diff over two logs is meaningful."""
    from cvtrust.core.canonical import canonical_json

    path = signed_log.save(tmp_path / "log.jsonl")
    for line in path.read_text().splitlines():
        payload = json.loads(line)
        assert canonical_json(payload).decode("utf-8") == line


def test_the_report_digest_does_not_depend_on_the_verifiers_clock(
    signed_log, trust_store_with
):
    """The general form of a bug this suite hit three times.

    A wall-clock value from the *verifier* — when a record was checked, when the
    replay database first saw something, when a validity window was evaluated —
    is not part of what was verified, and must not reach the report digest.
    Three separate fields leaked in during development and each was found only
    by a determinism test failing on a second boundary, which is to say by luck.

    This test removes the luck: it runs two verifications whose only difference
    is the verifier's clock, made large and explicit, and requires the digests
    to agree. It also catches the half of the problem that excluding a field
    name does not — a human-readable ``detail`` or ``statement`` string that
    *quotes* one of those values smuggles it straight back in.
    """
    from cvtrust.provenance.replay import ReplayDatabase

    config = Config()

    def verify_with(seen_at: str):
        database = ReplayDatabase.empty()
        for entry in signed_log.entries:
            database = database.record(entry, seen_at=seen_at)
        # Every record is now a replay, which is the path that carries the
        # database's timestamps into the report.
        report, _, _ = verify_log(
            signed_log, config,
            trust_store=trust_store_with,
            replay_database=database,
            anchor=build_anchor(signed_log.entries),
        )
        return report

    early = verify_with("2020-01-01T00:00:00Z")
    late = verify_with("2031-12-31T23:59:59Z")

    assert early.summary.replay_detected == len(signed_log)
    assert early.stable_digest() == late.stable_digest()
    assert early.report_id == late.report_id


def test_no_volatile_value_is_quoted_in_an_analyst_facing_string(
    signed_log, trust_store_with
):
    """Excluding a field name only works if nothing restates its value.

    ``statement`` and ``detail`` are for the analyst; ``observation`` is for the
    reviewer who does not believe the statement. A timestamp belongs in the
    second, and putting it in the first both breaks report diffing and
    duplicates a value that is already there.
    """
    from cvtrust.provenance.replay import ReplayDatabase

    database = ReplayDatabase.empty()
    for entry in signed_log.entries:
        database = database.record(entry, seen_at="2020-06-15T12:34:56Z")
    report, _, _ = verify_log(
        signed_log, Config(), trust_store=trust_store_with, replay_database=database
    )

    needle = "2020-06-15T12:34:56Z"
    for verification in report.verifications:
        for check in verification["checks"]:
            assert needle not in check["detail"], check["name"]
    for finding in report.findings:
        for item in finding.evidence:
            assert needle not in item.statement
