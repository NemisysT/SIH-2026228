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
