# Security design

## Cryptographic policy

| Rule | Where enforced |
|---|---|
| SHA-256 is the only digest used for identity or integrity | `core/hashing.py`; `HASH_ALGORITHM` recorded in every manifest |
| **MD5 and SHA-1 appear nowhere**, including for "convenience" keys | A convenience key becomes an identity eventually; there are none to promote |
| No invented cryptography | Only `hashlib`, `secrets` and `cryptography`'s Ed25519. Asserted by a test that scans every `provenance/` module for any other crypto import |
| Ed25519 for signatures, nothing else | `provenance/signing.py`; an envelope declaring another algorithm is refused rather than attempted |
| A signature establishes authorship, never authority | The public key travels in the envelope, so validity alone proves nothing. Trust comes from the trust store — see `docs/cryptographic-model.md` §4 |
| No online verification of anything | No CA, OCSP, CRL, key server or RFC 3161 timestamp authority. Asserted statically and dynamically |
| Canonical serialisation before hashing | `core/canonical.py` |
| Digest-bearing structures are float-free | `canonical_json` raises on `float` by default (ADR-004) |
| Truncated digests are labels, never proofs | `short()` is used for display and finding IDs only; every integrity comparison uses the full 64 hex characters |
| A path is never an identity | Contributor attribution precedence is explicit and recorded; path-pattern attribution is opt-in and off by default |
| Untrusted timestamps are never trusted silently | Module 1 records no contributor-supplied time as authoritative; `observed_at` is the analyst machine's own clock, and is excluded from every digest |

## Canonical serialisation

Anything hashed — and, from Module 3, signed — must have exactly one byte
representation on every machine and Python version. `canonical_json` guarantees:

- UTF-8, no BOM, no escaping of non-ASCII
- object keys sorted by Unicode code point
- no insignificant whitespace (`,` / `:` separators)
- `NaN` / `Infinity` always rejected
- integers outside the IEEE-754 safe range rejected
- only `dict` / `list` / `tuple` / `str` / `int` / `bool` / `None` accepted —
  anything else is an error rather than a silent `str()`

**Floats are rejected on the digest path.** RFC 8785 number canonicalisation is
implementable but subtle, and every subtlety would have become a
signature-verification bug once Module 3 signed these structures. Module 3 now
does sign them, and the decision held: no float has ever reached a signature.
Confidences, box coordinates and configuration values are quantised onto a fixed
decimal grid and carried as integers, with the number of places recorded inside
the signed structure so the grid is part of what was signed rather than a
convention two implementations might disagree about. Configuration and reports, which
legitimately contain thresholds and scores, are hashed through `digest_safe()`,
which rewrites floats as fixed-unit integers. Sixteen tests in
`tests/unit/test_canonical.py` pin this behaviour.

## Two digests per image, and why

| Digest | Answers | Defeated by |
|---|---|---|
| `file_sha256` — over bytes on disk | "Is this the same *artifact*?" | any re-encode, metadata strip, container change |
| `pixel_sha256` — over decoded RGB pixels, with shape/dtype/mode bound in | "Is this the same *content*?" | any pixel change |

The same split runs through Module 3: `raw_input_digest` over the input bytes and
`normalized_input_digest` over the preprocessed tensor answer different
questions, are separate fields, and one is never silently substituted for the
other. The raw digest changes when a JPEG is re-encoded and the pixels do not;
the normalised digest changes when the preprocessing changes and the file does
not.

An adversary who knows only byte hashing is used will re-encode. The file digest
then reports nothing while the training set is just as skewed. Content digests
close that gap deterministically, with no threshold to argue about. Tested with
an explicit evasion attempt.

## Input handling

The dataset root is untrusted input and is treated as such:

- **Path traversal.** A COCO `file_name` that escapes the dataset root is kept
  verbatim rather than resolved, so it surfaces as a `missing_image_file`
  finding. The adapter never follows it. Tested.
- **Decompression bombs.** Pillow's guard is retained with a raised ceiling;
  a `DecompressionBombError` becomes an `unreadable_image` finding.
- **Truncated and corrupt images.** Full decode is forced (`Image.open` is lazy
  and a truncated file only fails on decode). Failure becomes a finding, and the
  file digest is still recorded — we know exactly which bytes failed.
- **Malformed annotations.** Never raise; they become `IngestIssue` values,
  because a malformed annotation is itself a supported threat and must reach the
  analyst as evidence.
- **Unbounded work.** Above `near_duplicate.max_pairwise_samples` the
  near-duplicate detector **refuses and reports `NOT_ASSESSED`** rather than
  silently subsampling. A partial scan reported as a full one is the quiet
  coverage gap this system exists to prevent.
- **Unknown configuration keys are rejected** (`extra="forbid"`). A
  silently-ignored threshold is a threshold the analyst believes is active.

## The air gap

| Property | Status |
|---|---|
| Network access at runtime | **None.** No HTTP client is imported by any runtime path. |
| Cloud inference / external API | None. No OpenAI, Anthropic, or any hosted service. |
| Pretrained weight downloads | **None.** The default feature space needs no weights. The optional CNN backend requires a locally vendored file, records its SHA-256 in the report, and raises `DetectorUnavailable` with a message that explicitly states weights are never downloaded. Tested. |
| Remote database | None. No database at all; artifacts are files. |
| Authentication service | None. |
| Telemetry | None. |
| Certificate authority / PKI / OCSP / CRL | **None.** Trust is a local administrative record. Asserted by a test that scans the provenance modules for those APIs. |
| Remote timestamp authority (RFC 3161) | **None.** A timestamp is reported as a producer's claim, never as proof of time. |
| Key server or key directory | **None.** Keys are generated locally and provisioned by the operator out of band. |
| Blockchain / distributed ledger | **None**, by decision (ADR-009), not by omission. |

Installation requires a package index. Runtime does not. See
`docs/deployment.md`.

## Conservative-by-default policy decisions

Each of these makes the tool *less* likely to act, on purpose:

1. **Uncalibrated evidence cannot quarantine.** Rule
   `D-110-severe-but-uncalibrated` downgrades to `REVIEW`. Quarantine is
   expensive and reversing it costs credibility.
2. **An unassessed class never drives an irreversible action.** Rule
   `D-000-not-assessed` returns `REVIEW`, not `QUARANTINE` — an open question is
   neither a clean result nor grounds for action.
3. **Calibrated confidence is a lower bound**, not a point estimate (Wilson 95%).
4. **Statistical confidence is capped at 0.99.** A p-value of 1e-40 means the
   null model is wrong, which is not the same claim as certainty.
5. **OOD severity is capped at MEDIUM.** "Different from the reference" is never,
   on that evidence alone, a high-severity security claim.
6. **Contributor severity never exceeds the worst underlying sample severity.**
   Aggregation concentrates evidence; it does not manufacture a worse threat.
7. **Contributor confidence is the minimum** of the statistical confidence and
   the mean confidence of its children, so multiplicity cannot launder weak
   evidence into a confident verdict. Tested.
8. **Overall assessment is a worst-case roll-up, never an average.** One
   confident HIGH finding among a thousand clean samples is the case that
   matters, and any mean would bury it.
9. **Writing an unencrypted private key requires an explicit opt-in.** An
   unencrypted operational signing key should be a decision someone made, not a
   default they inherited. Mirrors Module 2's
   `allow_unsafe_deserialisation`.
10. **A provenance check that could not run is never a pass, and never a
   quarantine.** An absent trust store, replay database, anchor or expectation
   degrades its attack class to `NOT_ASSESSED`, and rule `D-000-not-assessed`
   makes the resulting finding `REVIEW` — so a missing input cannot quarantine a
   pipeline, and cannot be mistaken for a clean result either.

## Known security limitations

- **Manifests themselves are still not signed by default.** Module 3 makes it
  possible — a manifest digest can be bound into a signed provenance record, and
  `ExpectedBinding.from_model_manifest` is the join — but `cvtrust dataset
  manifest` and `cvtrust model manifest` still write plain JSON. A manifest
  stored *alongside* the artifact it describes can therefore still be replaced
  wholesale by an adversary with write access: self-tampering is detected,
  wholesale replacement with a self-consistent forgery is not. **Store baseline
  manifests separately from the artifacts they describe.** Wiring signing into
  those two commands is an open item, deliberately not done under a
  provenance brief.
- **A private key is not protected from a compromised host.** This software is a
  process reading a file; an adversary with code execution as the signing user
  can read the key, or simply ask this software to sign. Passphrase encryption
  and `0600` permissions raise the bar against a careless copy, not against a
  compromise. An HSM is the correct answer and is not integrated. See
  `docs/cryptographic-model.md` §5.
- **Trust is only as good as the channel each key came through.** A trust store
  populated from the same source that supplied the records establishes nothing.
  This is recorded per key in a `provenance` field, printed in every finding's
  assumptions, and warned about by the CLI when left empty.
- **Tail truncation of a provenance log is undetectable without an anchor**, and
  an anchor stored beside the log it anchors protects against nothing.
- Contributor attribution rests on untrusted metadata (see
  `docs/threat-model.md` §4).
- The tool trusts its own configuration file. Protect it with filesystem
  permissions.
- No sandboxing of image decoding. A Pillow/libjpeg vulnerability would be
  reachable from a malicious image. Mitigation for a hostile deployment: run
  scans as an unprivileged user in a container or VM with no network.


---

## Module 2 — model security policy

### Hashing

Model identity uses **SHA-256 only**, via the same `core/hashing.py` policy. No
custom cryptography is implemented. Three digests are computed, and the reason
for each is in `docs/model-security.md` §3:

| Digest | Over | Question |
|---|---|---|
| `file_sha256` | artifact bytes, streamed | Is this the same artifact? |
| `graph_digest` | canonical JSON of topology, shapes, dtypes — **no weight values** | Is this the same architecture? |
| `parameter_digest` | canonical JSON over per-tensor content digests | Are these the same weights? |

Per-tensor digests quantise floats to a fixed decimal grid before hashing. Raw
IEEE-754 bytes would be the obvious choice and would be **wrong**: the same
weights stored as float32 and float16 would digest differently, and the manifest
would report "different weights" for what is a container change. Six decimal
places is far finer than any meaningful weight perturbation and far coarser than
float32 epsilon.

Non-finite weights are encoded by a distinct sentinel rather than being allowed
to poison the digest.

### Identity is never a name

Not a filename, not a path, not a display name, not a declared version string,
not the architecture field inside the artifact. The lab's
`substitution_architecture` scenario keeps the reference's architecture name in
its ONNX metadata specifically so this is measured rather than asserted, and the
finding records `used_in_identity_decision: false` alongside the declared
metadata it ignored.

### Deserialisation — the largest input-handling risk in the project

| Format | Risk | Policy |
|---|---|---|
| ONNX | protobuf parsing; no code execution | Loaded. `onnx.checker` result recorded as a fact, including failure. |
| TorchScript | archive parsing; no arbitrary Python globals | Loaded. Recommended format. |
| `torch.save` state dict | tensor unpickling only | Loaded with `weights_only=True`. |
| `torch.save` module pickle | **executes arbitrary code on load** | **Refused by default.** Requires explicit `--allow-unsafe-deserialisation`, and the manifest records that it happened. |

The refusal message names the safe alternatives rather than only saying no.
This is pinned by `test_a_module_pickle_is_refused_by_default`.

Neither image nor model decoding is sandboxed. For a hostile deployment, run as
an unprivileged user in a container or VM with no network.

### Conservative-by-default decisions, Module 2

- **Graph optimisation disabled** in the ONNX session. Operator fusion rewrites
  the executed graph, which would make captured activation names unavailable and
  mean what runs is not what the manifest describes.
- **Single-threaded execution** in both runtimes. Multi-threaded float reduction
  changes summation order, which changes the low bits of a logit, which changes
  an argmax at a decision boundary — and a behavioural fingerprint that is not
  reproducible is not evidence.
- **Fixed batch size** for the battery, for the same reason.
- **Dynamic input axes refused** beyond the batch axis. Guessing a spatial size
  would fingerprint a shape the model was never declared for.
- **A probed input shape is labelled as probed.** Torch artifacts declare no
  signature, so one is established empirically, and the manifest records that it
  is an empirical fact rather than a claim by the artifact.
- **Benchmark artifacts are never fetched.** Absent means `NOT_ASSESSED` with
  the reason `"required local artifact unavailable"`.
- **An uninterpretable statistic is not reported as a verdict.** Neural
  Cleanse's anomaly index below eight classes, and the activation analyses
  throughout, report evidence without thresholding it.

---

## Module 4 — assurance security policy

### Input handling

Module 4's inputs are **JSON reports produced elsewhere**, in a pipeline whose
contributors are untrusted. They are treated as untrusted files, not as trusted
internal state.

- **Every finding is re-validated** against the frozen `Finding` schema at load.
  `extra="forbid"` plus the confidence contract means a smuggled `trust_score`
  field, an invented severity, a fifth confidence basis, an out-of-range
  confidence, a `DETERMINISTIC` finding at 0.4, or an uncalibrated finding above
  the 0.6 cap are all refused **loudly**, naming the index and the violation —
  never fused silently.
- **The declared module is checked against the argument slot.** A provenance
  report handed to `--dataset-report` is refused, because a scope silently
  assessed by the wrong evidence is the worst available outcome.
- **A malformed file is an error, not an empty result.** A missing `findings`
  array, a non-array `findings`, a JSON scalar and unparseable JSON all raise
  rather than degrading to "nothing found".

### What the schema cannot stop, and what is done instead

Deleting a well-formed finding produces a well-formed report. Module 4 fuses
what it is given and does not re-verify its inputs — deliberately, since
re-deriving a digest here could disagree with Module 2's and the disagreement
would be undetectable and fatal. Every fused report is therefore **cited by id
and by content**, so an edited report stays attributable after the fact.
Detecting the edit is the job of a signature over the report, not of the fusion
engine, and the limitation is printed rather than papered over.

### Conservative-by-default decisions, Module 4

- **A missing input is `NOT_ASSESSED`, which outranks `ACCEPT`.** Withholding a
  report is the cheapest attack in a multi-contributor pipeline, and the
  disposition vocabulary is the defence: an overall `ACCEPT` requires all four
  scopes to have been assessed.
- **The corroboration floors do not apply to `DETERMINISTIC` evidence.** An
  operator raising `corroboration_min_confidence` is suppressing weak
  statistical evidence; if that also silenced a failed signature check, the knob
  would be a switch for turning off the cryptography. Asserted by a test at
  confidence 0.99 / severity `CRITICAL`.
- **No rule escalates on distribution shift.** The strongest statement the
  distribution scope makes is `REVIEW` (ADR-018).
- **A family contributes at most one unit of independent support.** Measured at
  2,000 correlated findings: no escalation from volume, and a single
  deterministic failure alongside them still quarantines and is still cited.
- **Evidence below a floor is demoted, never deleted.** It stays in the graph,
  in the lineage and in the report, with the reason it did not count — because
  "nothing was observed" and "something weak was observed and not acted on" are
  different answers.
- **Sub-threshold statistics are not reported as verdicts.** A metric below its
  sample floor reports `INSUFFICIENT_SAMPLE` with the requirement named, and the
  report states that a refusal to answer is not a negative answer.
- **No configuration key can turn a rule off.** The rule table is code and data
  in this process, is emitted verbatim into every report, and its version is
  bound into the decision, the run context and the report digest — so two runs
  that reached `ACCEPT` under different rule tables are never mistaken for the
  same result.

### The air gap, Module 4

Every null is a **permutation null constructed from the data at analysis time**,
so there is nothing to download and no calibration table to fetch. The offline
guarantee is enforced dynamically for each Module 4 stage **separately** — shift
analysis, evidence normalisation, policy evaluation, end-to-end assurance with
report generation, and lab construction — rather than by one end-to-end run,
because an end-to-end run would pass if any single stage were skipped.
