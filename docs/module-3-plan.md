# Module 3 — the design this was built to

Recorded after the fact, as Modules 1 and 2 were, so that a reviewer can see
what was intended, what changed under measurement, and why.

## 1. Objective

Establish and verify the cryptographic relationship between an input, a model
identity, a model content digest, a preprocessing configuration, an inference
configuration, an output, execution metadata, a sequence position, and a
signature.

**Not** to decide whether any of those things is intrinsically trustworthy.
That distinction is the module's organising principle and it is enforced
structurally, not by convention — see §6.

## 2. Constraints taken as given

| Constraint | How it shaped the design |
|---|---|
| Fully offline | No CA, OCSP, CRL, key server, timestamp authority or ledger. Trust became a local administrative record; truncation detection became an out-of-band anchor rather than a witness network |
| Standard cryptography only | SHA-256 and Ed25519 through `cryptography`. Nothing implemented, and a test asserts no other crypto library is imported |
| Deterministic canonical serialisation | Inherited Module 1's `canonical_json` and ADR-004's float-free digest surface unchanged. Module 3 is the module that would have paid for RFC 8785 number canonicalisation, and it did not have to |
| Identity separate from metadata | Every untrusted label — filename, declared model name, producer, host — is carried and flagged, and plays no part in any decision |
| No blockchain | ADR-009, decided in Module 1 and unchanged. A hash chain with one writer needs no consensus |
| Preserve Modules 1 and 2 | Same `Finding` schema, same `FindingFactory`, same `DispositionPolicy`, same `CoverageStatement`. No second confidence system |

## 3. What was planned, and built

- Versioned canonical record schema binding all nine required fields ✔
- Deterministic canonical serialisation, float-free ✔
- SHA-256 content binding for input, model, configuration and output ✔
- Ed25519 signing and verification ✔
- Local offline trust store with rotation and revocation ✔
- Unknown / revoked / expired / wrong-purpose keys distinguished ✔
- Replay detection with an explicit non-replay verdict ✔
- Append-only hash-chained log, with truncation scoped honestly ✔
- ≥20 reproducible attack scenarios (28 built) ✔
- Structured verification evidence, never a boolean ✔
- JSON and Markdown/console reports ✔
- Coverage matrix extended, conditioned on supplied inputs ✔
- Offline security tests extended ✔
- Performance measured ✔

## 4. Four decisions taken during implementation

### The chained digest covers the signature (ADR-015)

The obvious design chains the record payload. It has a hole: swapping a
signature on an already-linked record leaves every back-pointer matching, so the
chain reports itself **intact** while carrying an entry whose authenticity has
changed. The entry's own signature check would still fail, but the chain status
is the field an operator reads first. `entry_digest` therefore covers payload
and envelope together, and `missing_signature` in the lab asserts it.

### Configuration and output are carried inline, not only by digest

A record that carries only digests can be verified against an external
reference. A record that carries the content *and* its digest can be verified
against itself — which is what catches a forger who holds a signing key, edits a
field, and re-signs without recomputing the derived value. The cost is about
2.8 KB per record instead of a few hundred bytes, and it is worth it.

### Verification takes an explicit `ExpectedBinding`

The first design had verification check the record's internal consistency and
its signature. That is not enough, and the gap is exactly the interesting attack:
an adversary holding a signing key emits a perfectly consistent, perfectly signed
record *about the wrong artifacts*. Nothing internal contradicts it. So the
verifier takes the analyst's independently held truth as a third source, every
absent expectation reports `NOT_CHECKED` rather than passing, and coverage for
`inference_tampering` degrades to `PARTIAL` when none is supplied.

### Failure codes carry a precondition

Discovered by a CLI test: verifying with no trust store produced `UNKNOWN_KEY`
at `SUPPORTED` coverage, which the disposition policy turned into `QUARANTINE`.
Quarantining a pipeline because the operator did not pass `--store` is
indefensible. Failure codes that depend on a supplied input now carry that
dependency (`FAILURE_PRECONDITION`), the coverage becomes `NOT_ASSESSED`, and
rule `D-000-not-assessed` makes the finding `REVIEW` — an open question, neither
clean nor actionable.

## 5. Measured corrections — things the evaluation harness caught

The provenance lab is scored by exact set equality, so every disagreement
between the expectations and reality is a defect in one or the other. The first
run disagreed on **fifteen of twenty-eight scenarios**.

1. **Chain breaks localise; they do not propagate.** The expectations assumed
   an edit at position *n* broke every link after it. It breaks exactly one —
   the successor's — because entry *n+2* stores entry *n+1*'s digest, which
   nobody touched. The code was right and better than the assumption: the
   position of the single break is the position of the edit. Encoded as
   `_successor_break` so the reasoning is in the lab rather than in a reviewer's
   head.
2. **An anchor does not cover the interior.** The expectations assumed any
   mutation broke the anchor. An interior edit leaves the head digest and the
   entry count unchanged, so the anchor verifies and the *chain* catches the
   edit. The two mechanisms cover different things, and the report keeps them as
   separate fields for that reason.
3. **A swap breaks three links, not two.** Swapping positions 2 and 3 also
   breaks position 4, whose back-pointer names the record now at position 2.
   Position 5 is untouched — the damage is bounded by the swap's extent, which
   is what makes break positions readable as a diagnosis.
4. **An insertion is caught twice, independently.** The displaced original
   claims the sequence slot the forgery took, so the replay database reports a
   fork *and* the chain reports displaced sequences. Neither mechanism depends on
   the other being correct.
5. **A key-id forgery was borrowing a trusted key's status.** An envelope
   naming a trusted `key_id` while carrying the adversary's key resolved the
   declared id and reported `key_trusted: PASS` for a record that key did not
   sign — precisely the confusion the forgery attempts. The trust lookup is now
   skipped entirely when the id does not fingerprint the carried key.
6. **The normalised-tensor digest contradicted its own docstring.** It promised
   independence from storage dtype and then bound the dtype. The dtype a pipeline
   preprocesses *to* is already part of its preprocessing configuration and bound
   there; binding it twice made the two disagree. Caught by a unit test written
   from the docstring.
7. **An empty timestamp was silently replaced by "now."** `timestamp or now()`
   turned a caller's bug into a plausible-looking signed claim. Changed to
   `is None`, so only an omitted value gets a default.
8. **`signed_at` defaulted to wall-clock**, making logs irreproducible — and it
   was a second, *unsigned* timestamp sitting beside the signed one in
   `record.timestamp`, inviting a reader to treat the weaker of the two as
   authoritative. Now omitted by default.
9. **Four verifier-clock values leaked into the report digest**, found three
   times over as intermittent determinism failures — which is to say, found by
   luck. `verified_at`, `first_seen_at`, `earliest_observation` and
   `evaluated_at` are all the *verifier's* clock, not properties of what was
   verified, and belong in `VOLATILE_FIELDS` beside `observed_at`.

   The second half of that fix matters more than the first: excluding a field
   name does nothing if a human-readable string quotes its value, and two
   `detail` strings did. The values now live only in `observation` — the
   reviewer's field — and never in `statement` or `detail`, which are the
   analyst's. Two tests now assert the general property rather than tripping
   over instances of it: one verifies the same log under clocks eleven years
   apart and requires identical digests, the other greps every analyst-facing
   string for the timestamp.

10. **Appending to an anchored log was reported as `TRUNCATION_DETECTED`.**
    Found by re-reading the branch rather than by a test, which is the one
    defect here no test would have caught, because the lab had no scenario for
    the most ordinary operation there is. Nothing was truncated: the log grew,
    and the anchor is simply older than the head. An operator who sees a
    critical alarm for appending a record stops taking anchors, and the
    mechanism that makes truncation detectable at all is then gone.

    `TruncationStatus` now distinguishes `ANCHOR_STALE` (the anchored head is
    interior — the log grew; **no finding**, and the entries after the anchor
    are reported as unattested) from `ANCHOR_MISMATCH` (the anchored head is the
    current head but the counts disagree — entries were added or removed before
    it) from `TRUNCATION_DETECTED` (entries removed from the end). Four tests
    pin the distinction, including one that anchors, appends and verifies.

11. **Verifying a single record treated it as a complete one-entry log.**
    `verify_single_record` routed through `verify_log`, so a record lifted out
    of the middle of a log — carrying a non-null back-pointer and a non-zero
    sequence number — was reported as front-truncated and chain-broken. It is
    neither: it is a perfectly good record, and where it sat is a question
    nobody asked. `verify_log` now takes `as_log`, and with it false the chain
    is not assessed at all, position checks report `NOT_CHECKED`, and
    `record_reordering` and `chain_truncation` are declared `NOT_ASSESSED`
    rather than standing at `SUPPORTED` on the strength of a check that never
    ran.

    The existing test had asserted `previous_record_valid == "PASS"` on a
    *genesis* record, which is the one case where the bug is invisible. The
    replacement uses a mid-log record.

Items 6–9 were all found by tests written from the documentation rather than
from the code, which is the argument for writing them that way. Item 9 is the
argument for writing a test for the *class* of bug once you have seen the same
one three times. Items 10 and 11 are the argument for still reading the code: a
lab full of attacks will not tell you that you have broken the ordinary case,
because a lab full of attacks does not contain the ordinary case — and a test
written against the easiest input will not either.

## 6. The rule the module exists to protect

```
model looks clean      + provenance valid    → the ordinary case
model looks clean      + provenance INVALID  → someone rewrote the account of it
model looks suspicious + provenance valid    → a genuine record of a bad model
model looks suspicious + provenance INVALID  → nothing here can be relied on
```

Rows 2 and 3 call for opposite actions and any single score would map them onto
the same value. So Module 3 has its own attack classes, its own report schema
with no aggregate field, `DETERMINISTIC` confidence enforced by the `Finding`
validator, and tests asserting all of it (ADR-014).

## 7. Explicitly out of scope, and still out of scope

- Module 4 fusion, Module 5 UI, and any universal assurance score.
- Trusted execution — proving a forward pass actually happened.
- Hardware-backed key storage.
- Merkle inclusion proofs (not needed at this volume; see ADR-009).
- Signing dataset and model manifests by default. Module 3 makes it *possible*
  and the join exists (`ExpectedBinding.from_model_manifest`), but
  `dataset manifest` and `model manifest` still write plain JSON. Wiring it in
  would be scope drift under a provenance brief, and it is recorded as an open
  item in `docs/limitations.md` §8 rather than quietly done or quietly dropped.
