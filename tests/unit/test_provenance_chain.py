"""The hash chain, the anchor, the replay database and the log store.

The chain tests are written as a table of structural attacks, because the value
of the construction is not "it detects tampering" but *which* tampering it
detects and which it provably cannot.
"""

from __future__ import annotations

import pytest

from cvtrust.core.errors import ProvenanceError
from cvtrust.provenance.chain import (
    ChainStatus,
    LinkStatus,
    TruncationStatus,
    build_anchor,
    verify_chain,
)
from cvtrust.provenance.log import ProvenanceLog
from cvtrust.provenance.record import SignedRecord
from cvtrust.provenance.replay import (
    REPLAY_VERDICTS,
    ReplayDatabase,
    ReplayVerdict,
    detect_replay,
)
from cvtrust.provenance.signing import sign_record


# --- the chain -------------------------------------------------------------


def test_a_clean_chain_is_intact(signed_log):
    result = verify_chain(signed_log.entries)
    assert result.status is ChainStatus.INTACT
    assert result.intact
    assert result.first_break_position is None
    assert result.links[0].link_status is LinkStatus.GENESIS


def test_modifying_an_entry_breaks_exactly_its_successor_link(signed_log):
    """Localisation is the point: one break names the edited position."""
    entries = list(signed_log.entries)
    target = entries[1]
    entries[1] = target.model_copy(
        update={"record": target.record.model_copy(update={"producer": "tampered"})}
    )
    result = verify_chain(entries)
    assert result.status is ChainStatus.BROKEN
    assert result.broken_positions() == (2,)


def test_deleting_an_entry_breaks_the_link_and_the_sequence(signed_log):
    entries = [e for index, e in enumerate(signed_log.entries) if index != 1]
    result = verify_chain(entries)
    assert result.status is ChainStatus.BROKEN
    assert result.links[1].link_status is LinkStatus.BROKEN
    # Everything after the gap is displaced, so the sequence rule fires too.
    assert not result.links[2].sequence_valid


def test_reordering_entries_is_detected(signed_log):
    entries = list(signed_log.entries)
    entries[1], entries[2] = entries[2], entries[1]
    assert verify_chain(entries).status is ChainStatus.BROKEN


def test_duplicating_an_entry_is_detected(signed_log):
    entries = list(signed_log.entries)
    entries.insert(2, entries[1])
    result = verify_chain(entries)
    assert result.status is ChainStatus.BROKEN
    assert not result.links[2].sequence_valid


def test_replacing_a_signature_breaks_the_chain(signed_log, signing_key):
    """The chained digest covers the envelope; a payload-only chain would not."""
    from cvtrust.provenance.keys import generate_keypair

    other_key, _ = generate_keypair()
    entries = list(signed_log.entries)
    entries[1] = sign_record(entries[1].record, other_key)
    assert verify_chain(entries).status is ChainStatus.BROKEN


def test_stripping_a_signature_breaks_the_chain(signed_log):
    entries = list(signed_log.entries)
    entries[1] = SignedRecord(record=entries[1].record, signature=None)
    assert verify_chain(entries).status is ChainStatus.BROKEN


def test_front_truncation_is_self_detectable(signed_log):
    result = verify_chain(signed_log.entries[1:])
    assert result.truncation_status is TruncationStatus.FRONT_TRUNCATION_DETECTED
    assert result.links[0].link_status is LinkStatus.ORPHANED


def test_tail_truncation_is_not_self_detectable(signed_log):
    """The honest negative result. A truncated chain is internally perfect."""
    result = verify_chain(signed_log.entries[:2])
    assert result.status is ChainStatus.INTACT
    assert result.truncation_status is TruncationStatus.NOT_DETECTABLE
    assert "cannot be distinguished" in result.truncation_detail


def test_tail_truncation_is_detected_against_an_anchor(signed_log):
    anchor = build_anchor(signed_log.entries)
    result = verify_chain(signed_log.entries[:2], anchor=anchor)
    assert result.status is ChainStatus.INTACT
    assert result.truncation_status is TruncationStatus.TRUNCATION_DETECTED


def test_a_complete_log_matches_its_anchor(signed_log):
    result = verify_chain(signed_log.entries, anchor=build_anchor(signed_log.entries))
    assert result.truncation_status is TruncationStatus.VERIFIED_COMPLETE


def test_an_anchor_from_a_different_log_is_detected(signed_log, signing_key, make_record):
    key, _ = signing_key
    other = ProvenanceLog.new("other-log")
    other.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            log_id="other-log",
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )
    result = verify_chain(signed_log.entries, anchor=build_anchor(other.entries))
    assert result.truncation_status is TruncationStatus.TRUNCATION_DETECTED
    assert "appears nowhere" in result.truncation_detail


def test_an_empty_log_against_an_anchor_is_a_deletion(signed_log):
    result = verify_chain([], anchor=build_anchor(signed_log.entries))
    assert result.status is ChainStatus.EMPTY
    assert result.truncation_status is TruncationStatus.TRUNCATION_DETECTED


def test_an_empty_log_with_no_anchor_says_it_cannot_tell():
    result = verify_chain([])
    assert result.truncation_status is TruncationStatus.NOT_DETECTABLE


def test_interleaved_logs_are_reported_rather_than_chained(signed_log, signing_key, make_record):
    key, _ = signing_key
    foreign = sign_record(make_record(log_id="other-log"), key)
    result = verify_chain(list(signed_log.entries) + [foreign])
    assert result.mixed_log_ids
    assert result.log_id is None


def test_the_guarantee_table_names_the_one_thing_it_cannot_do(signed_log):
    guarantees = verify_chain(signed_log.entries).guarantees()
    assert guarantees["tail_truncation"].startswith("NOT DETECTABLE")
    assert guarantees["modification"].startswith("DETECTED")
    assert "NOT ESTABLISHED HERE" in guarantees["authenticity"]


def test_an_anchor_over_an_empty_log_is_refused():
    with pytest.raises(ValueError, match="cannot anchor an empty log"):
        build_anchor([])


# --- the replay database ---------------------------------------------------


def test_a_first_observation_is_not_a_replay(signed_log):
    database = ReplayDatabase.empty()
    result = database.check(signed_log.entries[0])
    assert result.verdict is ReplayVerdict.FIRST_OBSERVATION
    assert not result.is_replay


def test_the_same_signed_record_twice_is_an_exact_replay(signed_log):
    """Case A of the brief: cryptographically valid AND replayed."""
    database = ReplayDatabase.empty()
    first, database = database.check_and_record(signed_log.entries[0])
    second, _ = database.check_and_record(signed_log.entries[0])
    assert first.verdict is ReplayVerdict.FIRST_OBSERVATION
    assert second.verdict is ReplayVerdict.REPLAY_EXACT
    assert second.is_replay


def test_the_same_subject_with_a_fresh_nonce_is_not_a_replay(
    signing_key, make_record
):
    """Case B of the brief: the same image legitimately processed twice."""
    key, _ = signing_key
    first = sign_record(make_record(log_id="log-a"), key)
    second = sign_record(
        make_record(log_id="log-b", nonce="b" * 32, timestamp="2026-05-05T00:00:00Z"),
        key,
    )
    database = ReplayDatabase.empty().record(first)
    result = database.check(second)
    assert result.verdict is ReplayVerdict.DUPLICATE_SUBJECT
    assert not result.is_replay
    assert result.observation["is_replay"] is False
    assert first.record.subject_key() == second.record.subject_key()


def test_nonce_reuse_by_the_same_key_is_a_replay(signing_key, make_record):
    key, _ = signing_key
    first = sign_record(make_record(payload=b"one", nonce="a" * 32), key)
    second = sign_record(make_record(payload=b"two", nonce="a" * 32), key)
    database = ReplayDatabase.empty().record(first)
    assert database.check(second).verdict is ReplayVerdict.NONCE_REUSE


def test_two_records_claiming_one_sequence_slot_is_a_fork(signing_key, make_record):
    key, _ = signing_key
    first = sign_record(make_record(payload=b"one", nonce="a" * 32), key)
    second = sign_record(make_record(payload=b"two", nonce="b" * 32), key)
    database = ReplayDatabase.empty().record(first)
    assert database.check(second).verdict is ReplayVerdict.SEQUENCE_COLLISION


def test_an_absent_database_reports_not_checked_never_first_observation(signed_log):
    """Reporting 'not seen before' when nothing was consulted is the same error
    as reporting an unrun detector as clean."""
    result = detect_replay(signed_log.entries[0], None)
    assert result.verdict is ReplayVerdict.NOT_CHECKED
    assert not result.is_replay
    assert "was not assessed" in result.detail


def test_duplicate_subject_is_excluded_from_the_replay_verdicts():
    assert ReplayVerdict.DUPLICATE_SUBJECT not in REPLAY_VERDICTS
    assert ReplayVerdict.REPLAY_EXACT in REPLAY_VERDICTS


def test_re_recording_an_observation_is_idempotent(signed_log):
    database = ReplayDatabase.empty().record(signed_log.entries[0])
    assert len(database.record(signed_log.entries[0])) == 1


def test_pruning_reports_what_it_discarded(signed_log):
    database = ReplayDatabase.empty()
    for entry in signed_log.entries:
        database = database.record(entry, seen_at="2026-01-01T00:00:00Z")
    pruned, removed = database.prune_before("2027-01-01T00:00:00Z")
    assert removed == len(signed_log.entries)
    assert len(pruned) == 0


def test_a_pruned_database_cannot_detect_an_older_replay(signed_log):
    """The stated retention limitation, asserted rather than only documented."""
    database = ReplayDatabase.empty().record(
        signed_log.entries[0], seen_at="2026-01-01T00:00:00Z"
    )
    assert database.check(signed_log.entries[0]).verdict is ReplayVerdict.REPLAY_EXACT
    pruned, _ = database.prune_before("2027-01-01T00:00:00Z")
    assert pruned.check(signed_log.entries[0]).verdict is ReplayVerdict.FIRST_OBSERVATION


def test_a_database_round_trips_through_disk(signed_log, tmp_path):
    database = ReplayDatabase.empty()
    for entry in signed_log.entries:
        database = database.record(entry)
    database.save(tmp_path / "replay.json")
    loaded = ReplayDatabase.load(tmp_path / "replay.json")
    assert len(loaded) == len(database)
    assert loaded.check(signed_log.entries[0]).verdict is ReplayVerdict.REPLAY_EXACT


def test_database_statistics_report_retention(signed_log):
    database = ReplayDatabase.empty()
    for entry in signed_log.entries:
        database = database.record(entry)
    stats = database.stats()
    assert stats["observations"] == len(signed_log.entries)
    assert stats["distinct_logs"] == 1
    assert stats["earliest_observation"] is not None


# --- the log store ---------------------------------------------------------


def test_a_log_round_trips_through_jsonl(signed_log, tmp_path):
    path = signed_log.save(tmp_path / "log.jsonl")
    loaded = ProvenanceLog.load(path)
    assert len(loaded) == len(signed_log)
    assert loaded.head_digest() == signed_log.head_digest()
    assert not loaded.malformed


def test_an_unparseable_line_becomes_a_finding_not_an_abort(signed_log, tmp_path):
    """One bad byte must not hide every finding in the rest of the log."""
    path = tmp_path / "log.jsonl"
    signed_log.save(path)
    lines = path.read_text().splitlines()
    lines.insert(2, "{not json")
    path.write_text("\n".join(lines) + "\n")

    loaded = ProvenanceLog.load(path)
    assert len(loaded) == len(signed_log)
    assert len(loaded.malformed) == 1
    assert loaded.malformed[0].line_number == 3
    assert "not valid JSON" in loaded.malformed[0].error


def test_a_schema_violating_line_is_kept_with_its_reason(signed_log, tmp_path):
    path = tmp_path / "log.jsonl"
    signed_log.save(path)
    with open(path, "a") as handle:
        handle.write('{"record": {"schema_version": "1.0"}}\n')
    loaded = ProvenanceLog.load(path)
    assert len(loaded.malformed) == 1
    assert "provenance schema" in loaded.malformed[0].error


def test_appending_out_of_sequence_is_refused(signed_log, signing_key, make_record):
    key, _ = signing_key
    stray = sign_record(make_record(sequence_number=99), key)
    with pytest.raises(ProvenanceError, match="claims sequence"):
        signed_log.append(stray)


def test_appending_with_a_wrong_back_pointer_is_refused(
    signed_log, signing_key, make_record
):
    key, _ = signing_key
    stray = sign_record(
        make_record(
            sequence_number=signed_log.next_sequence(),
            previous_record_digest="f" * 64,
        ),
        key,
    )
    with pytest.raises(ProvenanceError, match="previous_record_digest"):
        signed_log.append(stray)


def test_appending_a_foreign_log_id_is_refused(signed_log, signing_key, make_record):
    key, _ = signing_key
    stray = sign_record(
        make_record(
            log_id="other",
            sequence_number=signed_log.next_sequence(),
            previous_record_digest=signed_log.head_digest(),
        ),
        key,
    )
    with pytest.raises(ProvenanceError, match="belongs to log"):
        signed_log.append(stray)


def test_appending_to_file_does_not_rewrite_history(signed_log, signing_key, make_record, tmp_path):
    key, _ = signing_key
    path = signed_log.save(tmp_path / "log.jsonl")
    before = path.read_bytes()
    entry = signed_log.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            payload=b"new",
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )
    signed_log.append_to_file(entry, path)
    assert path.read_bytes().startswith(before)
    assert verify_chain(ProvenanceLog.load(path).entries).intact


def test_a_missing_log_is_an_explained_refusal(tmp_path):
    with pytest.raises(ProvenanceError, match="provenance log not found"):
        ProvenanceLog.load(tmp_path / "absent.jsonl")


def test_appending_to_an_anchored_log_is_not_reported_as_truncation(
    signed_log, signing_key, make_record
):
    """The false alarm this vocabulary exists to prevent.

    Anchor a log, append to it, verify. Nothing was truncated — the operator did
    the most ordinary thing there is — and reporting `TRUNCATION_DETECTED` would
    teach them to stop taking anchors.
    """

    key, _ = signing_key
    anchor = build_anchor(signed_log.entries)
    signed_log.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            payload=b"appended-later",
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )

    result = verify_chain(signed_log.entries, anchor=anchor)
    assert result.status is ChainStatus.INTACT
    assert result.truncation_status is TruncationStatus.ANCHOR_STALE
    assert result.anchor_is_satisfied()
    # But the honest half: the newer entry is not attested by this anchor.
    assert "outside this anchor's scope" in result.truncation_detail


def test_a_stale_anchor_raises_no_finding(signed_log, signing_key, make_record):
    from cvtrust.core.config import Config
    from cvtrust.provenance.findings import findings_for_chain

    key, _ = signing_key
    anchor = build_anchor(signed_log.entries)
    signed_log.append_signed(
        lambda sequence_number, previous_record_digest: make_record(
            payload=b"later",
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
        ),
        key,
    )
    result = verify_chain(signed_log.entries, anchor=anchor)
    assert findings_for_chain(result, config=Config()) == []


def test_entries_removed_before_an_unchanged_head_are_not_called_truncation(
    signed_log
):
    """The tail is where the anchor says it is; the chain says what happened."""
    anchor = build_anchor(signed_log.entries)
    without_middle = [e for i, e in enumerate(signed_log.entries) if i != 1]
    result = verify_chain(without_middle, anchor=anchor)
    assert result.truncation_status is TruncationStatus.ANCHOR_MISMATCH
    assert not result.anchor_is_satisfied()
    assert "removed" in result.truncation_detail
    assert not result.intact  # the chain is what localises it


def test_removing_entries_from_the_end_is_still_called_truncation(signed_log):
    anchor = build_anchor(signed_log.entries)
    result = verify_chain(signed_log.entries[:2], anchor=anchor)
    assert result.truncation_status is TruncationStatus.TRUNCATION_DETECTED
    assert "removed from the end" in result.truncation_detail
