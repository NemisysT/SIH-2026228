# Testing

```bash
pytest                              # everything (~75 s, 182 tests)
pytest -m "not slow"                # fast unit layer only (~5 s)
pytest -m adversarial               # evasion attempts
pytest --cov=cvtrust --cov-report=term-missing
```

## Layers, and what each is for

| Layer | Count | Purpose |
|---|---|---|
| **unit** (`tests/unit/`) | 110 | Canonical serialisation, hashing, the evidence schema's own invariants, perceptual-hash properties, statistical primitives, calibration and disposition, all three adapters, manifest construction, graceful degradation. |
| **integration** (`tests/integration/`) | 49 | The whole pipeline on clean and attacked corpora; contributor aggregation lineage; the CLI as a subprocess; reporting renderers in-process. |
| **adversarial** (`tests/adversarial/`) | 8 | Deliberate evasion attempts. |
| **regression** (`tests/regression/`) | 15 | Determinism and tamper detection. |

Coverage: **90%** of `src/cvtrust`. The remaining gap is concentrated in
rendering branches and the optional CNN backend's loaded path (which requires
vendored weights that are not in the repository).

## The kinds of test that matter here

### Negative tests — clean data must not be accused
An assurance tool that flags clean data is worse than no tool. Four tests assert
on the clean corpus: no `HIGH`/`CRITICAL` findings, never `QUARANTINE`, total
flagged-sample rate ≤5% (measured: **0.89%**), and zero `label_flip`,
`duplicate_flood` or `systematic_mislabel` findings.

### Adversarial tests — including the ones that must fail
Three tests assert that a **documented limitation is still true**:

- rotation defeats near-duplicate detection,
- a uniformly renamed class is undetectable,
- an oversized dataset is refused rather than approximated.

If a future change made rotation detectable, those tests fail and the
detector's `limitations` text must be updated. Coverage claims and code cannot
drift apart silently. A suite that only ever proves the tool works is not a
security suite.

### Schema-contract tests
The evidence schema's rules are enforced by validators and tested directly:
evidence cannot exist without a measured observation; `DETERMINISTIC` confidence
must be exactly 1.0; uncalibrated confidence is capped at 0.60 *and* must carry
the `uncalibrated` limitation; statistical confidence is capped at 0.99;
findings are immutable; finding IDs are content-addressed and do **not** change
when a score or severity changes, so recalibration updates a finding rather than
creating a new one.

### Determinism tests
- Two runs over identical inputs produce the same `stable_digest`, the same
  `report_id`, the same `run_id`, and the same finding IDs, confidences and
  severities.
- A structural diff of two report dumps may differ **only** in fields named in
  `DIGEST_EXCLUDED_FIELDS`.
- `run_id` changes when the seed, a threshold or the dataset changes.
- A changed threshold changes the report digest.
- **Corpus generation is reproducible across processes**, asserted by running
  generation in two subprocesses and comparing manifest digests. This test
  exists because seeding from Python's salted `hash()` once broke exactly this.
- Attacks are reproducible: the same scenario built twice yields identical
  ground truth and identical report digests.
- Sample ordering does not depend on filesystem iteration order.
- Ground truth is never inside the dataset root.

### Tamper tests
A single flipped bit, a deleted sample, an injected sample, a **same-size
content swap** between two images (which preserves every file size and the total
count), and tampering with the manifest file itself. Each must be detected and
must name the affected file with both digests.

### Graceful-degradation tests
A detector whose requirements are unmet must produce `NOT_ASSESSED` **with a
machine-readable reason**, never zero findings — which in a report is
indistinguishable from "clean". Asserted by monkeypatching a detector to raise
`DetectorUnavailable` and checking the coverage entry carries the reason. The
same contract will carry Module 2's `REQUIRES_WHITE_BOX`.

## Measured behaviour

See `docs/attack-matrix.md` for the full table with evaluation populations.
Headline numbers, corpus of 336 clean samples:

| | P | R | FPR clean |
|---|---|---|---|
| `duplicate_flood` | 1.000 | 1.000 | 0.0000 |
| `near_duplicate_flood` | 1.000 | 1.000 | 0.0000 |
| `label_flip` | 1.000 | 0.950 | 0.0000 |
| `systematic_mislabel` (contributor-level) | 1.000 | 1.000 | 0.0000 |
| `ood_insertion` | 0.889 | 1.000 | 0.0089 |
| clean corpus, all classes | — | — | **0.89%** flagged |

## Adding a test

- If it needs a corpus, use the session-scoped `clean_root` fixture — generation
  is deterministic, so sharing costs nothing in isolation.
- Mark anything that generates a corpus or runs the pipeline `@pytest.mark.slow`.
- If you add a detector, add: a negative test on clean data, a detection test on
  a lab scenario, and at least one evasion attempt. If the evasion succeeds,
  assert that it succeeds and state it in the detector's `limitations`.


---

## Module 2 test layers

Module 2 adds **139 tests** (321 total). They are organised around the same
principle as Module 1's: a test that asserts a *limitation is still true* is as
valuable as one that asserts a capability works.

| File | What it protects |
|---|---|
| `tests/unit/test_model_manifest.py` | The three digests move **independently** — a re-serialisation changes only `file_sha256`, a weight edit moves `parameter_digest` but not `graph_digest`, a different architecture moves all three. Also: identity is content not filename, a tampered manifest is refused, and a reshape is detected as a structural change rather than a value change. |
| `tests/unit/test_model_battery.py` | Battery determinism (same seed and spec → same digest and same tensors), probe pairing (without which the metamorphic and trigger metrics cannot be computed), trigger application bounds, and the Jensen–Shannon properties that motivated choosing it over KL — symmetry, the 1-bit bound, and finiteness at zero probability. |
| `tests/unit/test_model_params.py` | Peer grouping by (operator, role), and the **measured false-alarm simulation** behind `DEFAULT_PEER_Z` — including an assertion that the conventional 3.5 threshold is unusable here, so nobody quietly reverts it. |
| `tests/integration/test_model_pipeline.py` | The full path, and the schema contracts: Module 2 findings are Module 1 `Finding` objects, bound to the artifact digest, carrying non-empty observations and declared limitations. Also the assessment matrix, both false-positive cases, and the black-box pathway. |
| `tests/adversarial/test_model_evasion.py` | Attacks chosen to be **outside** the detectors' assumptions. Several assert a *miss*, pinning a documented coverage boundary so the code and `docs/model-security.md` cannot drift apart. |
| `tests/regression/test_model_determinism.py` | Two assessments agree on `report_id`; only declared volatile fields differ; and **cross-process** determinism of both a full assessment and model training, via subprocess. |
| `tests/security/test_offline.py` | The offline guarantee, two independent ways. |

## Module 3 test layers

Module 3 adds **258 tests** (579 total). The organising principle is the same,
with one addition specific to a deterministic module: **there is nothing here to
calibrate, so the lab is scored by exact set equality rather than by precision
and recall.** A verifier that raises an extra failure fails a scenario as hard as
one that misses a failure.

| File | What it protects |
|---|---|
| `tests/unit/test_provenance_record.py` | Canonicalisation, which everything else rests on: equivalent outputs produce identical bytes regardless of emission order or dict key order; tied scores still get a total order; keypoints order by index, not by score; the label vocabulary is bound; masks bind shape and label map; the digest surface is asserted float-free on a real record; `entry_digest` is shown to cover the signature, not only the payload. |
| `tests/unit/test_provenance_keys.py` | The key lifecycle and the rule that **validity and trust are different claims**: the three signature failure modes are distinguished (missing / malformed / invalid); an envelope naming a key it does not carry is malformed; an unencrypted key needs an explicit opt-in and is written `0600`; revocation preserves history and requires a reason; a trust store whose ids do not fingerprint its keys is refused at load. |
| `tests/unit/test_provenance_chain.py` | The chain as a table of structural attacks, each asserted individually — including the two that matter most: **tail truncation is not self-detectable** (asserted, with the anchor then detecting it) and an edit breaks *exactly* its successor link, which is what makes a break position readable as a diagnosis. Plus the replay database's four verdicts and the log loader's tolerance of one bad line. |
| `tests/integration/test_provenance_pipeline.py` | Create → sign → verify end to end; key rotation across a log; the coverage degradation when an input is absent; and the ADR-014 assertions — every finding `DETERMINISTIC` at 1.0, no aggregate score anywhere in the schema, and a verified chain saying nothing about model quality. Two `slow` tests bind a **real Module 2 ONNX manifest** and a **real Module 1 corpus image**, so the cross-module join is exercised rather than assumed. |
| `tests/security/test_provenance_attacks.py` | All 28 lab scenarios, parametrised one test each, asserted against ground truth held outside the verified artifacts. Plus the properties a per-position failure set cannot express: that an adversary with a key is caught *only* by trust and expectation; that a deleted record is invisible without the chain; that a truncated log is invisible without an anchor; and all three replay cases from the brief. |
| `tests/adversarial/test_provenance_evasion.py` | Attempts in **both** directions — making two different records share bytes, and making two identical records differ. Ordering rotations, JSON key rotation, whitespace, `0.1+0.2` against `0.3`, `-0.0`, non-finite scores, Unicode NFC/NFD, a label containing JSON syntax, a label containing the quantisation marker, duplicate JSON keys, unknown fields, 2000-detection outputs, six unusual timestamps, and deliberate nonce reuse. |
| `tests/regression/test_provenance_determinism.py` | Records, signatures, the clean baseline and the **whole 28-scenario lab** are byte-reproducible from a seed; verification reports agree on `report_id` across runs; a changed configuration changes the run id; every log line is canonical JSON, so two logs can be diffed meaningfully. |
| `tests/integration/test_cli.py` | The provenance command surface, including the full documented lifecycle (keygen → trust → record → anchor → verify-log) as a subprocess, and the three exit codes. |

### Scoring the provenance lab

`cvtrust lab provenance-evaluate` compares each scenario's observed failure
codes against its declared ones, **per record, per position**, as sets. 28/28
reproduce exactly. There is no threshold to tune and no calibration table is
produced — Module 3's findings are `DETERMINISTIC` at confidence 1.0, and
calibrating an equality test would be a number pretending to be a measurement.

Writing those expectations is where the work was: the first run disagreed with
reality on fifteen scenarios, because chain breaks **localise** to the successor
link rather than propagating, and because an interior edit leaves the head and
count intact so the anchor still verifies. Both are correct behaviour and better
diagnostics than what had been assumed, and the expectations were corrected to
match. Four scenarios are deliberately *not* attacks — `clean`, `key_rotation`,
`legitimate_reprocess` and (in a different sense) `modified_model_artifact` —
because a lab containing only attacks measures nothing.

### The lab's two test-only constructions

Signing keys derived from a published seed, and deterministic nonces. Both exist
so the lab is byte-reproducible; a key derived from a published seed is a key
every reader of the source already has. A test asserts that
`from_private_bytes` appears in **no shipped module but the lab**, so the
construction cannot leak into the production path.

### The offline test, specifically

Both halves are necessary and neither is sufficient:

1. **Dynamic** — `socket.socket`, `socket.create_connection` and
   `socket.getaddrinfo` are replaced with functions that raise, and a full
   dataset scan, a full ONNX model assessment, the TorchScript gradient pathway,
   a model training run and — added for Module 3 — key generation, signing,
   verification, chain verification, replay detection, trust and revocation, and
   a full build-and-evaluate of the 28-scenario provenance lab are executed
   through them.
2. **Static** — the shipped source is parsed and asserted to contain no import
   of a network module, no URL literal, and no call to `torch.hub`,
   `load_state_dict_from_url`, `from_pretrained`, `hf_hub_download`,
   `snapshot_download` or `urlretrieve`, and no `torchvision.models(weights=…)`
   with anything other than `None`. Module 3 adds three more static assertions:
   no certificate, OCSP, CRL, key-server or RFC 3161 timestamp API appears
   anywhere under `provenance/`; no crypto library other than `hashlib`,
   `secrets` and `cryptography` is imported there; and seed-derived signing keys
   are confined to the attack lab.

The dynamic half cannot catch a download path that simply was not exercised;
the static half cannot catch an indirect call. Together they are a reasonable
guarantee, and they are the reason the air-gap claim is checkable rather than
asserted.

### Tests that assert a limitation

These exist so that a documented boundary and the code cannot drift apart:

- `test_neural_cleanse_declares_its_anomaly_index_uninterpretable_at_low_class_count`
  — asserts the index flags **nothing** at six classes, which is the measured
  behaviour, not the hoped-for one.
- `test_a_very_low_opacity_trigger_degrades_the_probe` — asserts a blended
  trigger is *less* effective against the declared full-opacity family. This
  test found a real bug: the sweep was silently overriding a caller's declared
  opacity, so the "faint" probe was measuring a full-opacity patch.
- `test_unsupported_trigger_families_are_declared_in_every_finding` — asserts
  that sample-specific, semantic and adaptive backdoors are named as uncovered
  in every trigger finding's limitations.
- `test_peer_screening_false_alarm_rate_is_measured_not_assumed` — reproduces
  the null simulation and asserts the conventional threshold would be unusable.
- `test_the_report_never_asserts_that_the_model_is_safe` — checks every
  assertive field of a report. Scoped deliberately to statuses, titles, details
  and evidence statements rather than the whole document, because the
  limitations section legitimately contains the sentence "This report never
  states that a model is safe".
- `test_the_shipped_default_config_matches_the_code_defaults` — a config file
  that drifts from the code is a threshold the analyst believes is active and
  is not.

## Module 4 test layers

Module 4 adds **232 tests** (811 total). The organising principle inverts here,
and deliberately: for Modules 1–3 most of the lab is attacks, but **nine of
Module 4's ten population pairs contain no attack at all.** The failure this
module can most easily commit is calling a legitimate seasonal, terrain, sensor
or illumination change an attack, so the majority of its evidence is a measured
false-positive rate rather than a detection rate.

| File | Tests | What it protects |
|---|---:|---|
| `tests/unit/test_shift_metrics.py` | 33 | Each metric's contract, and the sample floors that bound it. The permutation p-value floor is 1/(B+1) and is reported; the cross-fitted covariance refuses below 80 reference samples; the PSI budget auto-scales to `ceil(m/alpha)−1` so BH significance is reachable at all — with the off-by-one asserted exactly (2299, not 2300), because that was a real bug; `INSUFFICIENT_SAMPLE` is a distinct status from `NOT_ASSESSED`, with distinct remedies. |
| `tests/unit/test_shift_context.py` | 20 | The distinction the whole module rests on: *the declaration predicts this movement* versus *the declaration is true*. Consistency is asserted to be reported as consistency and never as confirmation; the declaration carries `declaration_validated: false`; a missing declaration is a missing input, not a suspicious one; the heuristic table is printed so an analyst can argue with it; and `gradient` is asserted present in the `sensor` row, with the measurement that forced it in the docstring. Also the reference-contamination caveats and the binding of the feature space into the reference identity. |
| `tests/unit/test_assurance_evidence.py` | 24 | Normalisation, families and the corroboration floors. Findings are immutable inputs; `DETERMINISTIC` evidence is exempt from the confidence floor; `NOT_ASSESSED` coverage never supports; demoted evidence stays in the graph and in the lineage rather than disappearing. |
| `tests/unit/test_assurance_policy.py` | 39 | Every rule fires on the evidence it documents and not otherwise — and, more importantly, the **prohibitions**. Two of these walk the source: one over the AST looking for arithmetic on float literals and score-like identifiers, one over every report schema's `model_fields` looking for an aggregate field. Both exist because an earlier version of the first test matched the *docstring explaining why there are no weights*. |
| `tests/integration/test_assurance_pipeline.py` | 30 | The full path over real imagery and real upstream findings. Nothing here hand-writes evidence: a rule that fires on evidence no detector actually emits is exactly what an integration test exists to catch, and a fixture written by the same author would hide it. |
| `tests/regression/test_assurance_determinism.py` | 19 | Three separate properties, each able to fail without the others noticing: the *measurement* is reproducible (same p-values, not merely the same verdict), the *decision* is reproducible and order-independent, and the *report digest* excludes exactly the fields that legitimately move — asserted by mutating timestamps and timings and showing the digest survives, and by bumping the policy version and showing it does not. |
| `tests/security/test_assurance_attacks.py` | 30 | Attacks on the assurance layer itself: a downgraded `DETERMINISTIC` finding, an out-of-range confidence, an invented severity or basis, a smuggled `trust_score` field, a report with no findings array, a model report in the dataset slot, withheld reports, a loosened configuration that must not reach the cryptography, and the rule table's own integrity (every fired rule is a published rule; every cited finding was supplied). One test asserts the attack the schema **cannot** stop — deleting a well-formed finding — and what is done instead. |
| `tests/adversarial/test_assurance_evasion.py` | 32 | Both directions in one file, because the system can only be judged on the pair. Escalation survives a 2,000-finding flood; five correlated detectors are one phenomenon; high-confidence/low-severity does not escalate and high-severity/moderate-confidence is not dismissed; both "valid provenance + suspicious model" and "invalid provenance + clean model" stay expressible; no rule escalates on shift alone, asserted over the **whole verdict vocabulary** rather than one case; and four real-imagery false-positive checks. |
| `tests/security/test_offline.py` | +5 | The Module 4 pathways, amputated **one stage at a time** rather than by a single end-to-end run — shift analysis, evidence normalisation, policy evaluation, end-to-end assurance with report generation, and lab construction. An end-to-end run would pass if any one stage were skipped, and an unexercised stage is where an accidental dependency survives. |

### Two rules that exist because a test found a hole

`RULE-DATA-004` and `RULE-SHIFT-050` were both added during evaluation, not
during design, and both close the same *kind* of defect — evidence that reached
no rule and therefore vanished from the report:

- When every dataset finding was confounded by a coincident shift,
  `RULE-DATA-002` (needs unconfounded evidence) and `RULE-DATA-010` (needs no
  evidence) both declined to fire and **the dataset scope disappeared** — which
  reads as "nothing to say about the dataset" when the truth was "there is a
  finding and it cannot be separated from the shift". `RULE-DATA-004`:
  *a confounded finding is not a refuted one.*
- Per-sample OOD evidence reached no rule at all when no population-level shift
  assessment was supplied. `RULE-SHIFT-050` catches it, and is silenced when a
  shift assessment exists so the same phenomenon is not counted twice.

### The legitimate-but-unusual group

Four of the nineteen pipeline scenarios contain no attack at all, and their
expectations were **measured before they were written down**. Two reach
`ACCEPT` (a clean model with unusual weight statistics assessed with no
reference; the same input legitimately reprocessed). Two deliberately do not:
re-serialisation reaches `REVIEW` ("the artifact changed and the model did
not"), and a legitimately fine-tuned model reaches `QUARANTINE`, because the
artifact supplied is not the artifact that was assured. The rule's wording
carries the whole distinction — *"the model is not the assured artifact"*, never
"tampered", never "malicious" — and `legitimate_finetuning` exists to keep
`QUARANTINE ≠ malicious` visible rather than assumed.

### Three lab expectations that were wrong, and one rule that is not exercised

Recorded because "the tests pass" is not the interesting statement.

The `misdeclared_illumination` scenario expected `PARTIALLY_EXPLAINED` and got
`CONSISTENT`. **The engine was right**: illumination, season and terrain all
place ~93% of their displacement in the colour view, so a season declaration
genuinely does cover an illumination movement. It was renamed
`misdeclared_illumination_as_season` and kept as the explicit *negative control*
for the explanation mechanism, with `misdeclared_sensor_as_illumination` added
as the paired positive control. The `dataset_only` scenario expected `ACCEPT`
and got `NOT_ASSESSED` — also right, and now published as
`accept_requires_full_coverage`. The model baseline was `clean_retrain_0`, which
is an *independently retrained* model and therefore genuinely mismatches the
reference; it was replaced by a self-comparison.

**`RULE-SHIFT-050` is not reached by any of the nineteen pipeline scenarios**,
because `ood_without_shift_assessment` resolves at the scope level before it. It
is covered by unit and adversarial tests only. Stated here rather than left as
an implicit gap.

### Running them

```bash
./.venv/bin/pytest                               # 811 tests, ~7 min
./.venv/bin/pytest -m "not slow"                 # fast subset
./.venv/bin/pytest tests/security                # the offline guarantee
./.venv/bin/pytest -m adversarial                # evasion and boundary tests
```

The model-lab fixture is session-scoped and trains six small networks once;
training is deterministic, so sharing it across tests costs nothing in
isolation. The provenance-lab fixture is session-scoped for the same reason,
though it is cheap — it signs a few dozen records and touches no model
runtime. Tests skip cleanly when no model runtime is installed, so the
optional extras stay genuinely optional.

### A native-runtime teardown race, and how it is handled

ONNX Runtime and PyTorch both install process-wide teardown handlers that take
their own locks. On macOS those handlers intermittently race during CPython
finalisation and abort the process with `recursive_mutex lock failed` —
**after** every test has passed and after pytest has already printed its
summary. Measured before the fix: exit code 134 on a fully green run, roughly
one run in six.

It is a race inside third-party C++ destructors and cannot be fixed from Python.
Two things narrow it and one closes it:

1. `ModelHandle.release_caches()` drops the second inference session that
   activation capture builds, so it does not outlive the analysis. Good hygiene
   independently of this problem — that session holds its own thread pools.
2. An autouse fixture collects after each test, keeping the live-session count
   near one instead of letting dozens accumulate across a module.
3. `pytest_unconfigure` exits with **pytest's own status** once output is
   flushed, skipping an interpreter finalisation whose only remaining work is
   destroying those runtimes.

`pytest_unconfigure` rather than `pytest_sessionfinish`, and that distinction
was found the hard way: the terminal reporter writes its summary line
(`321 passed in 167s`) from `sessionfinish`, so exiting there swallowed the one
line a reviewer actually reads. Even `trylast` was not enough.

The hook is deliberately narrow: it runs only when a model runtime was actually
imported, so a Module-1-only environment finalises normally and any teardown
error there still surfaces. A genuine test failure still exits non-zero —
verified, not assumed.

Measured after the fix: 4 consecutive full-suite runs all `321 passed`, exit 0,
summary line present; a deliberately failing test with both runtimes loaded
still exits 1.
