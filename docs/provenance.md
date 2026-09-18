# Inference provenance (Module 3)

## 1. What this module answers

One question, and only one:

> Did **this** model, under **this** configuration, produce **this** output from
> **this** input — and who says so?

It does not answer whether the model is sound (Module 2), whether the input was
in-distribution (Modules 1 and 4), or whether the output is correct. Those are
different kinds of evidence and this module never mixes its verdicts with
theirs. ADR-014 states the rule; §11 below says why it matters in both
directions.

## 2. The record

`ProvenanceRecord`, schema **1.0**, defined in
[`src/cvtrust/provenance/record.py`](../src/cvtrust/provenance/record.py).

| Field | Binds | Notes |
|---|---|---|
| `input.raw_input_digest` | SHA-256 of the input bytes | Identity of the artifact |
| `input.normalized_input_digest` | SHA-256 of the preprocessed tensor | Optional, and **never** a substitute for the raw digest |
| `model.file_sha256` | Module 2's artifact digest | Consumed, not recomputed |
| `model.graph_digest` | Module 2's architecture digest | |
| `model.parameter_digest` | Module 2's weight digest | |
| `model.model_id` | Content-addressed model id | |
| `model.declared_name` / `declared_version` | — | **UNTRUSTED.** A label, carried so it can be shown *not* to establish anything |
| `preprocessing.digest` + `preprocessing.config` | Canonical preprocessing configuration | Configuration carried inline, in digest-safe form |
| `inference.digest` + `inference.config` | Canonical inference configuration | Same |
| `output.digest` + `output.output` | Canonical output | Same |
| `execution` | Runtime, adapter, host, device | Signed, so unalterable — but all of it self-asserted |
| `sequence.log_id` / `sequence_number` / `previous_record_digest` | Position in the log | |
| `timestamp` | Producer's clock | A **claim**, see §6 |
| `nonce` | 128 bits from the OS CSPRNG | See §7 |
| `schema_version` | `"1.0"` | An unsupported version is refused, never guessed |
| `record_id` | `PR-<16 hex>` of the record's own content | Derived, never supplied |

### Two digests, two jobs

**`record_digest`** — SHA-256 over the payload's canonical bytes with
`record_id` removed. The record's content identity; `record_id` is derived from
it, so a record cannot claim an id its content does not produce.

**`entry_digest`** — SHA-256 over `{"record": …, "signature": …}`: payload **and**
signature. This is what the hash chain links, so replacing a signature on an
already-chained record breaks the chain rather than only failing that record's
own signature check. A payload-only chain would report itself intact over an
entry whose signature had been swapped, and a chain that reports itself intact
over a tampered entry is worse than no chain.

### Configuration carried inline

Both configuration bindings and the output binding carry their content *and*
their digest. That makes a record **self-verifying**: a verifier recomputes the
digest from the record alone, with no external reference, and catches a forger
who edited a field and re-signed with their own key but did not recompute the
derived value. It costs a few hundred bytes per record (§10).

The inline copies are stored in digest-safe form — `0.25` becomes
`{"$q": 250000, "p": 6}` — so the whole record canonicalises in the strict
float-free mode (ADR-004). `undigest_safe()` rebuilds floats for display only;
nothing re-derives a digest from its output.

## 3. Canonicalisation

Canonical JSON per `core/canonical.py`: UTF-8, keys sorted by code point, no
insignificant whitespace, `NaN`/`Infinity` rejected, integers confined to the
IEEE-754 safe range, and **floats rejected outright** on the digest path.

Real-valued quantities are quantised onto a fixed decimal grid (6 places) and
carried as integers. The number of places is recorded *in the record*, so the
grid is part of what was signed rather than a convention two implementations
might disagree about. Changing it produces a visibly different record rather
than a silently incompatible one.

**Ordering.** Detections and classification scores are *sets* — an engine that
emits the same three boxes in a different order produced the same output — so
they are sorted into a total order: descending quantised score first, then the
item's own canonical bytes as a tiebreaker. The tiebreaker is what makes the
order total; sorting by score alone would leave ties in emission order and let
two byte-identical inferences produce two different digests. Keypoints are
**not** sorted by score: their index is semantic, so they are ordered by index.

**Masks** are bound by digest over the buffer plus its shape, dtype and label
map — never embedded. The consequence is stated rather than hidden: the record
establishes *which* mask was produced, and a verifier needs the mask artifact
itself to re-derive that digest.

**Unicode is not normalised.** `"défaut"` in NFC and NFD are different byte
strings and get different digests. Silently normalising would mean the digest
covers something other than what the producer emitted; a deployment that needs
them unified normalises before binding, where the choice is visible.

## 4. Verification: structured evidence, never a boolean

`PASS`/`FAIL` is the wrong shape for this answer. "The signature is valid, the
key is unknown, the output matches the artifact on disk and the model digest
does not" is four facts, and an analyst acts on *which* one failed.

**Every check runs.** Nothing short-circuits: an adversary who could make
verification stop early could hide every later fact, and a single-failure report
does not distinguish "the rest was clean" from "the rest was never examined".

Three independent sources of truth:

1. **The record itself.** Does the stored configuration hash to the stored
   configuration digest? Does the record id match its content? Needs nothing
   external; catches a forger who edited a field and re-signed.
2. **The signature and the trust store.** Did someone with a private key produce
   these bytes, *and* is that key one the operator authorised? Two questions,
   two checks, and the second is never implied by the first.
3. **The expectation.** Does the record's input digest match the image the
   analyst actually holds? Its model digest, the model they assured? An absent
   expectation reports `NOT_CHECKED`, never a pass.

The third is what makes substitution detectable when the cryptography is
flawless, because an attacker who controls a signing key emits perfectly valid
records about the wrong artifacts.

### Verifying one record, versus verifying a log

These are different questions and the API keeps them apart. `verify_record` (and
`verify_single_record`, and `cvtrust provenance verify`) assess a record on its
own: every binding, the signature, key trust and replay are checked, and the
position checks report `NOT_CHECKED` because no sequence was presented.
`record_reordering` and `chain_truncation` are then declared `NOT_ASSESSED`
rather than left looking supported.

That is not a weakness of the single-record path, it is the truth about it — and
conflating the two produces a false alarm, because a record taken from the middle
of a log carries a non-null back-pointer and a non-zero sequence number, which is
exactly what a *log* missing its beginning looks like.

### The checks

`signature_valid` · `key_known` · `key_trusted` · `key_within_validity_window` ·
`key_purpose_permitted` · `signed_before_revocation` · `schema_supported` ·
`record_id_matches_content` · `required_fields_present` · `timestamp_present` ·
`nonce_present` · `preprocessing_digest_self_consistent` ·
`inference_config_digest_self_consistent` · `output_digest_self_consistent` ·
`input_digest_match` · `normalized_input_digest_match` · `model_digest_match` ·
`model_graph_digest_match` · `model_parameter_digest_match` · `model_id_match` ·
`preprocessing_digest_match` · `inference_config_digest_match` ·
`output_digest_match` · `log_id_match` · `replay_detected` ·
`previous_record_valid` · `sequence_valid`

Outcomes are `PASS`, `FAIL`, `NOT_APPLICABLE`, `NOT_CHECKED` and `OBSERVED`.
`NOT_CHECKED` is a first-class, visible outcome and the report's verification
matrix lists every check that produced neither a pass nor a fail on any record —
the run's blind spots, printed rather than implied.

### The failure taxonomy

```
VALID
INVALID_SIGNATURE   MISSING_SIGNATURE   MALFORMED_SIGNATURE
UNKNOWN_KEY   REVOKED_KEY   KEY_EXPIRED   KEY_NOT_YET_VALID   KEY_PURPOSE_MISMATCH
INPUT_MISMATCH   MODEL_MISMATCH   CONFIGURATION_MISMATCH   OUTPUT_MISMATCH
SELF_INCONSISTENT_RECORD
CHAIN_BREAK   REPLAY
MALFORMED_RECORD   MISSING_FIELD   UNSUPPORTED_SCHEMA
```

One record may carry several. `VALID` is the absence of the others and is never
reported alongside one.

The codes are grouped three ways, because the remedy differs:

- **Integrity** — the record changed. Go looking for an edit.
- **Trust** (`TRUST_FAILURES`) — the record is intact; the operator has not
  authorised the signer. Provision, revoke or rotate a key.
- **Context** (`CONTEXT_FAILURES`) — the record is intact and properly signed,
  and the objection is to something outside it. Currently `REPLAY`: a replayed
  record has a perfect signature over unaltered bytes, and folding it in with
  integrity would send an analyst looking for an edit that never happened.

`cryptographically_intact` is blind to the second and third groups; `valid` is
the conjunction of all three.

## 5. Keys and trust

**Ed25519** (RFC 8032), via `cryptography`. No primitive is invented here.
Chosen over ECDSA because its signatures are deterministic — no per-signature
nonce whose reuse has cost real deployments their private keys, and the same
property is what lets the attack lab be regenerated and diffed byte for byte.
Chosen over RSA because a 32-byte public key and a 64-byte signature fit in a
record without ceremony, for no loss of security at this level.

`key_id` is the full SHA-256 of the raw 32-byte public key. Never a filename,
never an operator label — the same rule Modules 1 and 2 already enforce.

### The public key travels inside the record

A deliberate, documented trade:

- it lets a verifier distinguish **invalid signature** from **valid signature by
  an unknown key**, which the taxonomy requires and which is impossible if the
  key is only discoverable through the trust store;
- **it means a cryptographically valid signature, on its own, proves nothing.**
  Anyone can mint a key. Trust comes from the trust store and nowhere else.

An envelope that names one key while carrying another is rejected as
`MALFORMED_SIGNATURE`, and the trust lookup is **not** performed on the declared
id — reporting the named key's status for a record it did not sign is precisely
the confusion such a forgery is attempting.

### The trust store

Local, offline, operator-administered. No CA, no PKI, no OCSP, no CRL fetch.

```
key_id · public_key · status · valid_from · valid_until · purpose ·
label · provenance · added_at · revoked_at · revocation_reason · metadata
```

Statuses: `TRUSTED`, `REVOKED`, `UNKNOWN`. `UNKNOWN` is both a storable status
("seen and deliberately not trusted") and the result of a lookup miss ("never
seen"); the verification distinguishes them by `present_in_store`.

Purposes separate inference signing from log anchoring, because letting a log's
producer mint its own completeness attestation would remove the only thing that
makes truncation detectable (§8).

**The assumption the whole model rests on** is that each key was obtained
through a channel independent of the one that supplied the records. A store
populated from the same source as the records establishes nothing. That is why
`provenance` is a field, why the CLI warns when it is left empty, and why it is
printed in every finding's assumptions.

### Rotation, and when a window is evaluated

A store holds many keys at once, each with an optional validity window, so
rotation is an ordinary state rather than an outage.

*When* to evaluate the window is a genuine problem offline, because the only
time a record carries is its own self-asserted clock. Both answers are wrong in
different ways, so both are implemented and the choice is recorded in every
verification:

| Policy | Honours rotation | Weakness |
|---|---|---|
| `at_record_timestamp` (default) | Yes — a record signed last year by a key retired since still verifies | A forger with a retired key also chooses the timestamp, so an expired key can be revived by backdating |
| `at_verification_time` | No | Immune to backdating; invalidates the entire history of every key that has ever expired |

Revocation is absolute under both. The store records `revoked_at` so the
verifier can *also* report whether the record claims to predate the revocation —
reported as a claim, not a fact, and never averaged into the verdict.

## 6. Timestamp semantics

A locally supplied timestamp establishes exactly one thing:

> this timestamp was included in the signed record.

It does not establish when the inference happened. There is no timestamp
authority in an air-gapped deployment, and a holder of the signing key controls
the clock too. The check is therefore reported as `OBSERVED`, never as a pass,
and its observation says so in as many words.

What *does* constrain time, weakly: a record's **position in the chain**. Entry
*n* binds entry *n−1*'s digest, so it cannot have been written before entry
*n−1* existed. That gives a partial order over the log, not a wall clock. A
sequence number adds no cryptographic guarantee at all — it is a semantic rule
that turns "link 7 does not match" into "an entry was deleted between 6 and 8".

## 7. Nonce semantics

128 bits from `secrets.token_hex(16)`, which is the OS CSPRNG
(`getrandom(2)` / `/dev/urandom`). No network, no seeding.

- **Uniqueness** rests on the OS CSPRNG, not on this code. At 2^64 records the
  birthday bound gives a ~50% chance of one collision; a deployment producing a
  million records a day would need roughly fifty million years to get there.
- **Storage**: ~443 bytes per observation in the replay database (§10).
- **A nonce does not prevent replay.** It makes two legitimately distinct
  inferences over the same input distinguishable. Detecting a second
  presentation needs a record of what has been seen — §8.

## 8. Replay and the chain

### Replay

A valid signature does **not** establish that an inference happened once. A
signed record is a static artifact; anyone who can read one can present it
again, and it will verify again, because verifying is all a signature does.

| Verdict | Meaning | Failure? |
|---|---|---|
| `REPLAY_EXACT` | The same `entry_digest` seen before: byte-identical record, presented twice | **Yes** |
| `NONCE_REUSE` | A *different* record reusing a nonce already seen from the same key | **Yes** |
| `SEQUENCE_COLLISION` | A different record claiming an occupied `(log_id, sequence)` slot: a forked log | **Yes** |
| `DUPLICATE_SUBJECT` | Same input, model and configuration; fresh nonce, fresh sequence, distinct signature | **No** — reported as an observation |
| `FIRST_OBSERVATION` | Not seen before, within retention | No |
| `NOT_CHECKED` | No database supplied | No — and never reported as `FIRST_OBSERVATION` |

The last distinction is the one that makes the detector usable. The same image
legitimately processed twice is something every real pipeline does; calling it a
replay would get the system switched off within a day.

**Limitations, stated rather than implied:**

- **The database is the trust anchor.** Delete it and every record becomes
  first-seen again. It must be protected at least as well as the log it guards.
- **It is local.** Two verifiers with separate databases will each accept a
  replay the other would catch. There is no shared state — a shared ledger is
  what ADR-009 declined.
- **Retention bounds detection.** A pruned database cannot detect the replay of
  a record older than its window. `prune_before` records what it removed and the
  report carries the window.
- **First observation is indistinguishable from the original.** A verifier that
  sees the replayed copy before the genuine one records the replay as original.
  Presentation order is not locally establishable.

### The chain

Entry *n* binds `previous_record_digest = entry_digest(entry n−1)`. Entry 0
binds `None` and carries `sequence_number = 0`.

| Attack | Detected | By what |
|---|---|---|
| Modify an entry | **Yes** | Its digest changes; the *successor's* back-pointer fails |
| Delete a middle entry | **Yes** | Link at the gap, plus a run of off-by-one sequences |
| Insert an entry | **Yes** | Displaced sequences; a forged entry can carry a correct back-pointer but cannot make its successors' match |
| Reorder entries | **Yes** | Back-pointers follow content, not position |
| Duplicate an entry | **Yes** | Repeated sequence; the replay database fires independently |
| Replace a signature | **Yes** | `entry_digest` covers the envelope |
| Strip a signature | **Yes** | Same |
| **Front** truncation | **Yes** | Genesis must carry a null back-pointer and sequence 0 |
| **Tail** truncation | **No — see below** | |

Breaks **localise**. An in-place edit at position *n* breaks exactly one link,
at *n+1*: entry *n+2* stores entry *n+1*'s digest, which nobody touched. That
is a feature — the position of the single break is the position of the edit —
and it is encoded in the attack lab rather than assumed.

**Tail truncation is not detectable from the log.** Removing entries from the
end leaves a chain that is internally perfect, and so does deleting the whole
log. No self-contained structure can detect its own absence.

The offline remedy is an **anchor**: the analyst records the head `entry_digest`
and the entry count out of band. Verification against a held anchor detects
truncation; verification without one reports `NOT_DETECTABLE`, never clean.
An anchor is only as good as where it is kept — one stored inside the log
directory protects against nothing, which is why `cvtrust provenance anchor`
writes it elsewhere and says so.

The anchor result has a finer vocabulary than "truncated / not truncated",
because otherwise the most ordinary operation there is — appending a record to a
log you anchored yesterday — would raise a critical alarm, and operators who see
that once stop taking anchors:

| Status | Meaning | A finding? |
|---|---|---|
| `VERIFIED_COMPLETE` | Head and count both match | No |
| `ANCHOR_STALE` | The anchored head is present but *interior*: the log has grown past the anchor. **Not an attack** — this is what an appended log looks like. Entries up to the anchored head are attested; the ones after it are outside its scope | **No.** Reported, not flagged |
| `ANCHOR_MISMATCH` | The anchored head *is* the current head, so the tail is where the anchor says, but the counts disagree: entries were added or removed before it. The chain localises which | Yes |
| `TRUNCATION_DETECTED` | Entries removed from the end, or this is not the anchored log at all | Yes |
| `FRONT_TRUNCATION_DETECTED` | The log does not begin at genesis | Yes |
| `NOT_DETECTABLE` | No anchor supplied | No — but coverage is `NOT_ASSESSED` |

Note what the anchor does *not* cover: the interior. An edit in the middle of a
log leaves the head and the count unchanged, so the anchor still reports
`VERIFIED_COMPLETE` and the *chain* is what catches it. The two mechanisms cover
different things and the report keeps them as separate fields for that reason.

**This is not a blockchain.** See ADR-009: a distributed ledger buys Byzantine
agreement among mutually distrusting writers, and an air-gapped single analyst
authority has one writer, no network to gossip over, and no second party whose
disagreement about ordering needs resolving. What it needs is tamper-evidence,
which a hash chain provides with no consensus layer.

## 9. The attack lab

28 reproducible scenarios in
[`src/cvtrust/attack_lab/provenance_attacks.py`](../src/cvtrust/attack_lab/provenance_attacks.py),
built by `cvtrust lab provenance-build` and checked by
`cvtrust lab provenance-evaluate`.

Ground truth lives **outside** the artifacts under verification, exactly as in
Modules 1 and 2, so the verifier cannot read the answer key.

```
clean                        modified_input_digest        modified_model_digest
modified_model_artifact      modified_preprocessing_config modified_inference_config
modified_output              modified_timestamp           modified_nonce
modified_sequence            modified_previous_digest     deleted_record
inserted_record              reordered_records            duplicated_record
unknown_key                  revoked_key                  malformed_record
schema_version_mismatch      key_rotation                 truncated_log
front_truncated_log          missing_signature            replay_exact
legitimate_reprocess         expired_key_window           wrong_key_purpose
key_id_forgery
```

Four of them are **not** attacks, and their presence is the point: `clean`,
`key_rotation` and `legitimate_reprocess` must produce zero findings, and
`modified_model_artifact` is the case where the cryptography is flawless and the
deployment is not.

### Scoring is exact, not statistical

Modules 1 and 2 measure precision and recall, because their detectors produce
scores and a score needs a measured relationship to reality. Module 3 produces
neither: a signature verifies or it does not. So the harness asserts **exact set
equality** between expected and observed failure codes, per record, per
position. A verifier that raises an *extra* failure fails as hard as one that
misses a failure — a spurious `CHAIN_BREAK` on a clean log is as damaging to an
analyst as a missed one on a forged log. No threshold can be tuned to make this
pass.

**No calibration table is produced for Module 3**, and that absence is
deliberate: every finding is `DETERMINISTIC` at confidence 1.0, and a
calibration table for an equality test would be a number pretending to be a
measurement.

Two constructions in the lab are test-only and used nowhere else: signing keys
derived from a published seed, and deterministic nonces. A key derived from a
published seed is a key every reader of the source already has. A test asserts
that `from_private_bytes` appears in no shipped module but the lab.

## 10. Performance and storage

Measured with `cvtrust provenance benchmark --records 200` on the development
host (Python 3.13, macOS, single-threaded). Orders of magnitude, not a
specification.

| Operation | Mean | p95 | Per second |
|---|---|---|---|
| Record creation | 0.092 ms | 0.098 ms | ~10,900 |
| Signing | 0.117 ms | 0.128 ms | ~8,600 |
| Signature verification | 0.194 ms | 0.209 ms | ~5,100 |
| Full record verification (27 checks) | 0.492 ms | 0.560 ms | ~2,000 |
| Chain verification, 200 entries | 8.8 ms | 8.9 ms | — |
| Replay lookup, 200-observation DB | 0.050 ms | 0.059 ms | ~20,100 |

| Storage | |
|---|---|
| Mean record | ~2.8 KB |
| Record range | 2.5–3.1 KB |
| 200-entry log | ~561 KB |
| Replay database | ~443 bytes per observation |

Signing and verifying every inference costs well under a millisecond, which is
negligible beside any CV forward pass. Record size is dominated by the inline
canonical output — the detection records here carry five boxes each — and that
is the price of a self-verifying record (§2).

**Chain verification is O(n) and re-hashes every entry**, so a log that grows
without bound verifies proportionally more slowly. That is inherent to the
construction; the mitigation, if a deployment needs one, is to anchor and rotate
logs, not to verify less.

## 11. What this module does not establish

- **That the inference was executed.** Binding proves the record describes these
  artifacts. A producer able to sign can sign a record for an inference it never
  ran. Detecting that requires trusted execution, which this build does not
  implement and does not claim.
- **That the model is sound.** A cryptographically perfect chain over a
  backdoored model is entirely possible. So is a forged record of a clean one.
  Both facts survive to the final report because they are carried by separate
  findings with separate attack classes, and nothing averages them.
- **That the key holder was authorised in the world**, only that the operator
  recorded a decision to trust them.
- **When anything happened** (§6).
- **That the log is complete**, without an anchor (§8).
- **That a private key is safe on a compromised host.** See
  [`cryptographic-model.md`](cryptographic-model.md) §5.

## 12. Commands

```bash
cvtrust provenance keygen --out keys/signer.pem --passphrase "$PASSPHRASE"
cvtrust provenance trust add keys/signer.pub.json --store trust_store.json \
    --provenance "hand-carried from the signing enclave, fingerprint read aloud"
cvtrust provenance record image.png output.json \
    --key keys/signer.pem --log provenance.jsonl --model-manifest model-manifest.json
cvtrust provenance anchor provenance.jsonl --out /separate/media/anchor.json
cvtrust provenance verify-log provenance.jsonl \
    --store trust_store.json --anchor /separate/media/anchor.json \
    --replay-db replay.json --model-manifest model-manifest.json \
    --out report.json --markdown-out report.md
cvtrust provenance trust revoke <key_id> --store trust_store.json --reason "…"
cvtrust provenance benchmark --records 200
cvtrust lab provenance-build --out provenance_lab
cvtrust lab provenance-evaluate provenance_lab
```

Exit codes follow the same convention as `dataset scan` and `model assess`:
**0** verified, **1** review required, **3** compromised.
