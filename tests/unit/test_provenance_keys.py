"""Key material, fingerprints, the trust store and its lifecycle.

The theme running through this file: **cryptographic validity and trust are
different claims**, and the code has to keep them apart even when it would be
convenient not to.
"""

from __future__ import annotations

import json
import stat

import pytest

from cvtrust.core.errors import KeyMaterialError, ProvenanceError
from cvtrust.provenance.keys import (
    PUBLIC_KEY_BYTES,
    export_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    read_public_key_file,
)
from cvtrust.provenance.signing import sign_record, verify_signature
from cvtrust.provenance.trust import (
    KeyPurpose,
    KeyStatus,
    TrustStore,
    ValidityPolicy,
    build_store,
    revoke_key,
    trust_key,
    untrust_key,
)


# --- generation and fingerprints -------------------------------------------


def test_a_key_id_is_the_fingerprint_of_the_key_material():
    key, info = generate_keypair()
    recomputed, public_hex = export_public_key(key)
    assert info.key_id == recomputed
    assert info.public_key_hex == public_hex
    assert len(bytes.fromhex(public_hex)) == PUBLIC_KEY_BYTES


def test_two_generated_keys_differ():
    _, first = generate_keypair()
    _, second = generate_keypair()
    assert first.key_id != second.key_id


def test_a_public_key_of_the_wrong_length_is_refused():
    with pytest.raises(KeyMaterialError, match="32 bytes"):
        public_key_fingerprint(b"\x00" * 16)


def test_writing_an_unencrypted_key_requires_an_explicit_opt_in(tmp_path):
    with pytest.raises(KeyMaterialError, match="refusing to write an unencrypted"):
        generate_keypair(private_path=tmp_path / "k.pem")


def test_an_unencrypted_key_is_written_owner_only(tmp_path):
    _, info = generate_keypair(private_path=tmp_path / "k.pem", allow_unencrypted=True)
    mode = stat.S_IMODE((tmp_path / "k.pem").stat().st_mode)
    assert mode == 0o600
    assert info.encrypted is False


def test_an_encrypted_key_round_trips_through_its_passphrase(tmp_path):
    _, info = generate_keypair(private_path=tmp_path / "e.pem", passphrase="hunter2")
    loaded = load_private_key(tmp_path / "e.pem", "hunter2")
    assert export_public_key(loaded)[0] == info.key_id


def test_the_wrong_passphrase_is_an_explained_refusal(tmp_path):
    generate_keypair(private_path=tmp_path / "e.pem", passphrase="correct")
    with pytest.raises(KeyMaterialError, match="cannot load private key"):
        load_private_key(tmp_path / "e.pem", "wrong")


def test_an_encrypted_key_without_a_passphrase_says_so(tmp_path):
    generate_keypair(private_path=tmp_path / "e.pem", passphrase="pw")
    with pytest.raises(KeyMaterialError, match="encrypted and no passphrase"):
        load_private_key(tmp_path / "e.pem")


def test_a_missing_private_key_is_an_explained_refusal(tmp_path):
    with pytest.raises(KeyMaterialError, match="private key not found"):
        load_private_key(tmp_path / "absent.pem")


def test_the_public_half_records_whether_the_private_half_is_encrypted(tmp_path):
    generate_keypair(private_path=tmp_path / "e.pem", passphrase="pw", label="ops")
    payload = json.loads((tmp_path / "e.pub.json").read_text())
    assert payload["private_key_encrypted"] is True
    assert payload["label"] == "ops"


def test_a_public_key_file_whose_id_contradicts_its_material_is_refused(tmp_path):
    _, info = generate_keypair(
        private_path=tmp_path / "k.pem", allow_unencrypted=True
    )
    path = tmp_path / "k.pub.json"
    payload = json.loads(path.read_text())
    payload["key_id"] = "f" * 64
    path.write_text(json.dumps(payload))
    with pytest.raises(KeyMaterialError, match="fingerprints to"):
        read_public_key_file(path)


def test_a_public_key_loads_from_hex_bytes_or_a_file(tmp_path):
    key, info = generate_keypair(private_path=tmp_path / "k.pem", allow_unencrypted=True)
    from_hex = load_public_key(info.public_key_hex)
    from_bytes = load_public_key(bytes.fromhex(info.public_key_hex))
    from_file = load_public_key(tmp_path / "k.pub.json")
    ids = {public_key_fingerprint(k) for k in (from_hex, from_bytes, from_file)}
    assert ids == {info.key_id}


# --- the trust store -------------------------------------------------------


def test_an_unknown_key_is_unknown_not_absent():
    store = TrustStore.empty()
    assert store.status_of("a" * 64) is KeyStatus.UNKNOWN
    assert store.get("a" * 64) is None


def test_trusting_a_key_records_the_operator_decision():
    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        label="signer", provenance="courier",
    )
    entry = store.get(info.key_id)
    assert entry is not None
    assert entry.status is KeyStatus.TRUSTED
    assert entry.provenance == "courier"
    assert store.trusted_ids() == (info.key_id,)


def test_a_key_id_that_contradicts_the_key_material_is_refused():
    _, info = generate_keypair()
    with pytest.raises(ProvenanceError, match="does not fingerprint"):
        trust_key(
            TrustStore.empty(), public_key=info.public_key_hex, key_id="f" * 64
        )


def test_revocation_preserves_the_original_entry_and_records_why():
    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex, label="signer",
        valid_from="2026-01-01T00:00:00Z",
    )
    revoked = revoke_key(store, info.key_id, reason="host compromised")
    entry = revoked.get(info.key_id)
    assert entry is not None
    assert entry.status is KeyStatus.REVOKED
    assert entry.revocation_reason == "host compromised"
    assert entry.revoked_at is not None
    assert entry.label == "signer"
    assert entry.valid_from == "2026-01-01T00:00:00Z"


def test_revoking_an_unknown_key_is_refused_rather_than_silently_inserted():
    with pytest.raises(ProvenanceError, match="not in this trust store"):
        revoke_key(TrustStore.empty(), "a" * 64, reason="typo")


def test_revocation_requires_a_reason_because_it_is_an_audit_record():
    _, info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    with pytest.raises(ProvenanceError, match="requires a reason"):
        revoke_key(store, info.key_id, reason="   ")


def test_untrusting_is_distinct_from_revoking():
    """Revocation claims history; untrusting claims only present doubt."""
    _, info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    untrusted = untrust_key(store, info.key_id, reason="provenance unclear")
    entry = untrusted.get(info.key_id)
    assert entry is not None
    assert entry.status is KeyStatus.UNKNOWN
    assert entry.revoked_at is None


def test_a_store_holds_many_keys_so_rotation_is_an_ordinary_state():
    _, old = generate_keypair()
    _, new = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=old.public_key_hex, label="old")
    store = trust_key(store, public_key=new.public_key_hex, label="new")
    assert set(store.trusted_ids()) == {old.key_id, new.key_id}


def test_a_validity_window_is_evaluated_against_a_supplied_moment():
    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        valid_from="2026-01-01T00:00:00Z", valid_until="2026-06-01T00:00:00Z",
    )
    entry = store.get(info.key_id)
    assert entry is not None
    assert entry.window_contains("2026-03-01T00:00:00Z") is True
    assert entry.window_contains("2025-12-31T00:00:00Z") is False
    assert entry.window_contains("2026-07-01T00:00:00Z") is False


def test_an_unparseable_moment_does_not_silently_satisfy_a_window():
    """None means 'could not answer', and the caller must not read it as yes."""
    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex,
        valid_until="2026-06-01T00:00:00Z",
    )
    entry = store.get(info.key_id)
    assert entry is not None
    assert entry.window_contains("not-a-timestamp") is None
    assert entry.window_contains(None) is None


def test_a_key_with_no_window_is_always_inside_it():
    _, info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    entry = store.get(info.key_id)
    assert entry is not None
    assert entry.window_contains("1999-01-01T00:00:00Z") is True


def test_a_store_round_trips_through_disk(tmp_path):
    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex, label="signer",
        purpose=KeyPurpose.LOG_ANCHOR,
    )
    store.save(tmp_path / "trust.json")
    loaded = TrustStore.load(tmp_path / "trust.json")
    assert loaded.digest() == store.digest()
    entry = loaded.get(info.key_id)
    assert entry is not None and entry.purpose is KeyPurpose.LOG_ANCHOR


def test_a_tampered_store_is_refused_at_load(tmp_path):
    """A store whose ids do not fingerprint its keys would authorise the wrong
    signatures, so it is rejected rather than used."""
    _, info = generate_keypair()
    _, other = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    path = tmp_path / "trust.json"
    store.save(path)
    payload = json.loads(path.read_text())
    payload["keys"][0]["public_key"] = other.public_key_hex
    path.write_text(json.dumps(payload))
    with pytest.raises(ProvenanceError, match="has been altered"):
        TrustStore.load(path)


def test_a_missing_store_file_is_distinguishable_from_an_empty_one(tmp_path):
    assert len(TrustStore.load_or_empty(tmp_path / "absent.json").keys) == 0
    with pytest.raises(ProvenanceError, match="not found"):
        TrustStore.load(tmp_path / "absent.json")


def test_the_store_digest_ignores_its_own_volatile_fields():
    _, info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex)
    restamped = store.model_copy(update={"updated_at": "2030-01-01T00:00:00Z"})
    assert restamped.digest() == store.digest()


def test_build_store_orders_keys_deterministically():
    keys = [generate_keypair()[1] for _ in range(4)]
    entries = [
        trust_key(TrustStore.empty(), public_key=info.public_key_hex).keys[0]
        for info in keys
    ]
    assert build_store(entries).digest() == build_store(reversed(entries)).digest()


# --- signing: the three failure modes, kept apart --------------------------


def test_a_valid_signature_verifies(make_record, signing_key):
    key, _ = signing_key
    check = verify_signature(sign_record(make_record(), key))
    assert check.valid
    assert "not that the key is authorised" in check.detail


def test_ed25519_signatures_are_deterministic(make_record, signing_key):
    key, _ = signing_key
    record = make_record()
    assert (
        sign_record(record, key).signature.signature
        == sign_record(record, key).signature.signature
    )


def test_an_altered_record_fails_verification(make_record, signing_key):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    altered = entry.model_copy(
        update={"record": entry.record.model_copy(update={"producer": "someone-else"})}
    )
    assert verify_signature(altered).outcome.value == "INVALID"


def test_a_missing_signature_is_not_an_invalid_signature(make_record):
    from cvtrust.provenance.record import SignedRecord

    check = verify_signature(SignedRecord(record=make_record()))
    assert check.outcome.value == "MISSING"
    assert "asserts no authenticity" in check.detail


def test_a_malformed_signature_is_not_an_invalid_signature(make_record, signing_key):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    assert entry.signature is not None
    broken = entry.model_copy(
        update={"signature": entry.signature.model_copy(update={"signature": "zz" * 64})}
    )
    assert verify_signature(broken).outcome.value == "MALFORMED"


def test_an_envelope_naming_a_key_it_does_not_carry_is_malformed(
    make_record, signing_key
):
    key, _ = signing_key
    _, other = generate_keypair()
    entry = sign_record(make_record(), key)
    assert entry.signature is not None
    forged = entry.model_copy(
        update={"signature": entry.signature.model_copy(update={"key_id": other.key_id})}
    )
    check = verify_signature(forged)
    assert check.outcome.value == "MALFORMED"
    assert check.key_id_consistent is False


def test_an_unsupported_algorithm_is_refused_rather_than_attempted(
    make_record, signing_key
):
    key, _ = signing_key
    entry = sign_record(make_record(), key)
    assert entry.signature is not None
    other = entry.model_copy(
        update={"signature": entry.signature.model_copy(update={"algorithm": "rsa"})}
    )
    assert verify_signature(other).outcome.value == "UNSUPPORTED_ALGORITHM"


def test_a_signature_from_a_different_key_does_not_verify(make_record, signing_key):
    """The record carries its own key, so this is the 'swapped envelope' case."""
    key, _ = signing_key
    other_key, other_info = generate_keypair()
    entry = sign_record(make_record(), key)
    assert entry.signature is not None
    swapped = entry.model_copy(
        update={
            "signature": entry.signature.model_copy(
                update={
                    "key_id": other_info.key_id,
                    "public_key": other_info.public_key_hex,
                }
            )
        }
    )
    assert verify_signature(swapped).outcome.value == "INVALID"


def test_validity_policies_are_a_closed_set():
    assert {p.value for p in ValidityPolicy} == {
        "at_record_timestamp", "at_verification_time"
    }
