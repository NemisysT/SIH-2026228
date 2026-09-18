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

### The offline test, specifically

Both halves are necessary and neither is sufficient:

1. **Dynamic** — `socket.socket`, `socket.create_connection` and
   `socket.getaddrinfo` are replaced with functions that raise, and a full
   dataset scan, a full ONNX model assessment, the TorchScript gradient pathway
   and a model training run are executed through them.
2. **Static** — the shipped source is parsed and asserted to contain no import
   of a network module, no URL literal, and no call to `torch.hub`,
   `load_state_dict_from_url`, `from_pretrained`, `hf_hub_download`,
   `snapshot_download` or `urlretrieve`, and no `torchvision.models(weights=…)`
   with anything other than `None`.

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

### Running them

```bash
./.venv/bin/pytest                               # 321 tests, ~2 min 45 s
./.venv/bin/pytest -m "not slow"                 # fast subset
./.venv/bin/pytest tests/security                # the offline guarantee
./.venv/bin/pytest -m adversarial                # evasion and boundary tests
```

The model-lab fixture is session-scoped and trains six small networks once;
training is deterministic, so sharing it across tests costs nothing in
isolation. Tests skip cleanly when no model runtime is installed, so the
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
