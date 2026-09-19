# Coverage statement

This is the most important document in the repository. A clean report from a
system that never tested for an attack class is not a clean result, and this
file — mirrored by the machine-readable `coverage` section of every report and
by `cvtrust info` — is what makes the difference visible.

`Coverage` is a first-class value in the evidence schema:

| Value | Meaning |
|---|---|
| `SUPPORTED` | Assessed by a detector in this build, with measured behaviour. |
| `PARTIAL` | Assessed, but with material stated dependencies (feature space, declared reference) that bound what the result means. |
| `NOT_SUPPORTED` | The platform does not claim this class. |
| `NOT_ASSESSED` | Not assessed in this run — either owned by a later module, or the detector's requirements were not met. Carries a machine-readable reason. |
| `REQUIRES_WHITE_BOX` | Needs model weights/architecture/activations, which were not available. Reserved for Module 2; present in the schema from Module 1 so the contract is fixed. |

## Module 1 — dataset forensics

| Attack class | Coverage | Module | Detector | Notes |
|---|---|---|---|---|
| `duplicate_flood` | **SUPPORTED** | 1 | `exact_duplicate` | Cryptographic equality; confidence 1.0 and it means it. |
| `near_duplicate_flood` | **SUPPORTED** | 1 | `near_duplicate` | Two-stage; no rotation/reflection/heavy-crop invariance. |
| `label_flip` | **PARTIAL** | 1 | `label_consistency` | Feature-space dependent; cannot detect a uniformly mislabelled class. |
| `systematic_mislabel` | **SUPPORTED** | 1 | `systematic_mislabel` | Contributor-level claim is exact; sample-level attribution is a screening signal. |
| `ood_insertion` | **PARTIAL** | 1 | `ood` | Requires a trustworthy declared reference; self-reference is weaker and is reported as such. **OOD is never equated with malicious.** |
| `metadata_inconsistency` | **SUPPORTED** | 1 | `integrity` | Deterministic; detects contradictions within the dataset, not a consistent lie. |
| `dataset_tamper` | **SUPPORTED** | 1 | `cvtrust dataset verify` | Needs a manifest from before the tampering. Assessed by a separate command because it is the only class here requiring a second observation in time. |
| `trigger_injection` | `NOT_ASSESSED` | 2 | — | **Still open.** ADR-008 deferred *data-side* trigger detection to Module 2; Module 2 delivered the model side in full and deliberately did not add a dataset-image detector, which would be scope drift. Listed as an open item, not dropped. See ADR-011. |
| `inference_tampering` | `NOT_ASSESSED` | 3 | — | Owned by Module 3 and assessed by `cvtrust provenance verify-log`, not by a dataset scan. |
| `inference_replay` | `NOT_ASSESSED` | 3 | — | Same. |
| `record_reordering` | `NOT_ASSESSED` | 3 | — | Same. |
| `provenance_key_trust` | `NOT_ASSESSED` | 3 | — | Same. |
| `chain_truncation` | `NOT_ASSESSED` | 3 | — | Same. |
| `distribution_shift` | `NOT_ASSESSED` | 4 | — | Owned by Module 4 and assessed by `cvtrust assurance shift`, not by a dataset scan. Module 1 scores individual samples only; the two are deliberately kept separate. |

## Module 2 — model forensics and backdoor assurance

Full detail, including the measured numbers behind every claim, is in
`docs/model-security.md`. Summary:

| Attack class | Coverage | Detector | Notes |
|---|---|---|---|
| `model_substitution` | **SUPPORTED** | `model_identity` | SHA-256 over content. Three digests separate re-serialisation from substitution. Needs a trusted reference; without one it is `NOT_ASSESSED`, not clean. Measured 15/15 correct against the fact asserted. |
| `model_tampering` | **SUPPORTED** | `model_structure`, `model_parameters`, `model_behaviour` | Deterministic against a reference, and localised to named tensors. Degrades to `PARTIAL` without one (peer screening and metamorphic consistency only). |
| `model_backdoor` | **PARTIAL** | `model_trigger` | Declared patch family: measured P=1.00, **R=0.83**, FPR=0.00 over 15 lab models. The single miss is an out-of-family blended trigger the lab predicted would be missed. `PARTIAL` because coverage is bounded by the family, and because Neural Cleanse's anomaly index is uninterpretable below 8 classes. |
| `model_backdoor` (activation route) | **PARTIAL — context only** | `model_activation` | Measured **non-discriminating** in this build: the backdoored lift range lies inside the clean range. Reports corroborating context at INFO severity; never raises an independent finding. |

### Model-security coverage matrix

| Attack / anomaly | White-box | Black-box | Status |
|---|---:|---:|---|
| Model substitution | ✓ | ✓ | Supported |
| Re-serialisation (new bytes, same model) | ✓ | ✓ | Supported — distinguished, severity-capped |
| Structural modification | ✓ | — | Supported |
| Parameter modification (vs reference) | ✓ | — | Supported |
| Parameter anomaly (no reference) | partial | — | Partial — screening signal only |
| Behavioural deviation (vs reference) | ✓ | ✓ | Supported |
| Behavioural instability (no reference) | ✓ | ✓ | Partial |
| Patch backdoor, declared family | ✓ | ✓ | Supported |
| Trigger reconstruction (Neural Cleanse) | partial | — | Partial — needs gradients; index needs ≥8 classes |
| Blended / low-opacity backdoor | partial | partial | Partial |
| Sample-specific / input-aware trigger | — | — | **Not supported** |
| Semantic backdoor | — | — | **Not supported** |
| Adaptive backdoor | limited | limited | **Not supported** |
| Benchmark evaluation (TrojAI / BackdoorBench) | — | — | Not assessed — local vendoring only |

### Access modes

A binary white/black split is not enough to be honest, because formats differ in
ways that change which method can run at all:

| Capability | ONNX | Torch `nn.Module` | TorchScript | Black-box |
|---|---:|---:|---:|---:|
| `inference` | ✓ | ✓ | ✓ | ✓ |
| `graph` | ✓ | partial | ✓ | ✗ |
| `parameters` | ✓ | ✓ | ✓ | ✗ |
| `activations` | ✓ | ✓ | **✗** | ✗ |
| `gradients` | **✗** | ✓ | ✓ | ✗ |

ONNX cannot support trigger reconstruction (no gradients); TorchScript cannot
support activation analysis (a `ScriptModule` refuses forward hooks). Both
consequences are reported in every affected run rather than silently omitted.

Verify this table against the running build:

```bash
cvtrust info
```

## Module 3 — inference provenance and cryptographic integrity

Full detail is in `docs/provenance.md`. Every coverage value here is
**conditional on what the operator supplied**, which is the defining property of
this module's coverage: four of the five classes degrade to `NOT_ASSESSED` when
their precondition is absent, and a finding raised by a check that could not run
is dispositioned `REVIEW` by rule `D-000-not-assessed` rather than quarantining a
pipeline over a missing input.

| Attack class | With everything supplied | Degraded to | When |
|---|---|---|---|
| `inference_tampering` | **SUPPORTED** | `PARTIAL` | No independent expectation (input artifact, model manifest, configuration or output). Only internal consistency and signatures were checked, and a forger holding a key can emit a consistent record about the wrong artifacts |
| `inference_replay` | **PARTIAL** | `NOT_ASSESSED` | No replay database. A valid signature does not establish that an inference happened once |
| `record_reordering` | **SUPPORTED** | — | Never degrades: linkage and sequence need nothing but the log |
| `provenance_key_trust` | **PARTIAL** | `NOT_ASSESSED` | No trust store. Every key is `UNKNOWN` and authenticity was not assessed |
| `chain_truncation` | **PARTIAL** | `NOT_ASSESSED` | No log anchor. Tail truncation is structurally undetectable from the log; front truncation is detected either way |

`inference_replay`, `provenance_key_trust` and `chain_truncation` are `PARTIAL`
even at their best, and the reasons are specific rather than decorative:

- **replay** is bounded by the local database's retention and by the integrity of
  that database, which an adversary with write access to the verifying host
  could roll back;
- **key trust** is an administrative fact whose guarantee is only as strong as
  the channel through which each key was obtained;
- **truncation** is assessed only for entries written before the anchor was
  taken.

### Provenance coverage matrix

| Attack | Detected | By what |
|---|---:|---|
| Edit any bound field without a key | ✓ | Ed25519 over canonical bytes |
| Edit and re-sign with an adversary key | ✓ | Trust store **and** the independent expectation — neither alone |
| Replace the model artifact under a genuine log | ✓ | Expectation re-derived from disk |
| Rewrite preprocessing or inference configuration | ✓ | Configuration binding, plus record self-consistency |
| Rewrite the output | ✓ | Output binding, self-consistency, expectation |
| Delete / insert / reorder / duplicate a record | ✓ | Hash-chain linkage + contiguous sequence |
| Strip or swap a signature on a chained record | ✓ | `entry_digest` covers the envelope |
| Re-present a genuine record | partial | Local replay database, within retention |
| Nonce reuse, sequence collision | ✓ | Replay database |
| Unknown / revoked / expired / wrong-purpose key | ✓ | Trust store |
| Envelope naming a key it does not carry | ✓ | Key-id consistency, checked before trust lookup |
| Unsupported schema version | ✓ | Refused, never guessed |
| Unparseable log line | ✓ | Reported as a finding; the rest of the log still verifies |
| **Front** truncation | ✓ | Genesis rule |
| **Tail** truncation | anchor only | Out-of-band head digest |
| Appending to an anchored log | not an attack | Reported `ANCHOR_STALE`, no finding raised |
| Signing a record for an inference that never ran | ✗ | **Not supported.** Needs trusted execution |
| Backdating into a retired key's window | partial | Policy-dependent; `at_verification_time` is immune |
| A compromised signing host | ✗ | **Not supported.** It can sign anything, correctly |
| A trust store filled from the same channel as the records | ✗ | **Not supported.** The assumption the module rests on |

### Scoring, and why there is no calibration table

Modules 1 and 2 measure precision and recall because their detectors produce
scores. Module 3 produces none: a signature verifies or it does not. The lab's
28 scenarios are scored by **exact set equality** between expected and observed
failure codes, per record — an extra failure fails as hard as a missed one — and
28/28 reproduce exactly.

No calibration table exists for Module 3 and none will. Every finding is
`DETERMINISTIC` at confidence 1.0, and calibrating an equality test would
produce a number pretending to be a measurement.

## Module 4 — distribution shift and evidence fusion

Module 4 adds one attack class and seven **capabilities**. The distinction
matters: an attack class is something an adversary might do; a capability is
something the assurance engine does with evidence. Both are in the
machine-readable `coverage` and `capabilities` sections of every assurance
report, and both are printed by `cvtrust info`.

### Attack class

| Attack class | Coverage | Assessed by | Notes |
|---|---|---|---|
| `distribution_shift` | **PARTIAL** | `cvtrust assurance shift` | Permutation energy test over the joint 614-d feature distribution, with movement attributed to feature views and checked against the declared operational context. `PARTIAL` at best, permanently, for two independent reasons: the result is bounded by the reference population's own integrity, **which this system does not establish**, and a shift is never equated with an attack. Without a reference the outcome is `NOT_ASSESSED` — never "stable". |

`distribution_shift` degrades further, and the vocabulary distinguishes the
reasons:

| Situation | Reported as |
|---|---|
| Both populations above the sample floors, metrics ran | `ASSESSED` |
| Either side below its floor (default 20) | `INSUFFICIENT_SAMPLE` — a refusal to answer, not a negative answer |
| A metric's own precondition unmet (e.g. <80 reference samples for the cross-fitted covariance) | `NOT_ASSESSED`, with the requirement named |
| No reference population supplied at all | The scope is `NOT_ASSESSED` and is listed in the decision's unassessed areas |

### Capability matrix

| Capability | Status | What it means | Why it is not stronger |
|---|---|---|---|
| `distribution_shift` | **PARTIAL** when a reference was supplied and the floors were met; `NOT_ASSESSED` otherwise | Population-level two-sample testing with a permutation null, five metrics, explicit sample sufficiency, and a reference identity bound to the feature space. | Bounded by the reference population's own integrity, which this system does not establish; and a shift is never equated with an attack. Listed as both an attack class and a capability so a reader auditing the capability list does not have to know to look in a second table. |
| `operational_drift` | **PARTIAL** | Whether an observed shift is accounted for by a declared operational change (season, terrain, sensor, illumination, acquisition mode). | **Permanently PARTIAL.** The mapping from a declared change to the feature views it would move is a documented, uncalibrated heuristic over one feature space; and a declaration is a claim by the supplying side that nothing here verifies. Illumination, season and terrain are *not separable* by this measurement — all three place ~93% of their displacement in the colour view. |
| `evidence_fusion` | **SUPPORTED** | Findings from Modules 1–4 normalised into one evidence model and combined by an explicit, versioned 23-rule table. | No score, no weights, no arithmetic across evidence classes — by design (ADR-016), not by omission. |
| `evidence_dependency` | **PARTIAL** | Evidence grouped into phenomenon families; a family contributes at most one unit of independent support however many findings or detectors it contains. Confounded evidence stops counting as corroboration. | Independence is decided by a **curated table, not measured**. Two detectors correlated in a way the table does not record would still count as two phenomena. The table is printed in every report so the assumption is challengeable. |
| `cross_module_lineage` | **SUPPORTED** | Every disposition names the rules that produced it; every rule names the findings that made it fire, back to the module, detector and version. | — |
| `coverage_aware_assurance` | **SUPPORTED** | A scope with no input is `NOT_ASSESSED`, never `ACCEPT`; unassessed areas are carried in the decision, at scope and attack-class granularity, each with a remedy. | — |
| `policy_disposition` | **SUPPORTED** | The rule table is data, emitted verbatim into every report, and reproducible from (inputs, policy version, configuration, seed, software version). | — |
| `conflicting_evidence` | **SUPPORTED** | Disagreement between evidence classes is recorded as a factual statement and never resolved into one narrative. | The recording rule carries `ACCEPT` deliberately, so noting a conflict can neither raise nor lower an outcome. |

### What Module 4 explicitly does **not** do

| | Why |
|---|---|
| Re-verify upstream reports | It consumes the reports the other three modules produced and never re-derives a digest, re-scores a detector or re-dispositions a finding. A mismatch between what Module 2 reported and what Module 4 said Module 2 reported would be undetectable and fatal, so there is no code path that could produce one. A **forged but well-formed** upstream report is therefore fused as written — and cited by id and content so it stays attributable. |
| Establish that the reference population is clean | Nothing in this system does. A contaminated reference makes a clean population look shifted and a shifted one look clean. The reference's trust level defaults to `UNKNOWN` and is never inferred. |
| Validate a declared operational context | `declaration_validated: false` on every explanation. Consistency is reported as consistency, never as confirmation. |
| Escalate on distribution shift | No rule does. The strongest statement the distribution scope makes is `REVIEW` (ADR-018). |
| Produce any aggregate number | No trust score, no risk score, no "overall confidence". Asserted by tests that walk the AST for arithmetic on score-like names and that scan every report schema's fields (ADR-016). |
| Separate a genuine dataset attack from a coincident legitimate shift | The confounding table cannot. Such a case is held at `REVIEW` rather than escalated. **An accepted, documented cost.** |

### Dispositions and what they mean here

| Disposition | Meaning in an assurance decision |
|---|---|
| `ACCEPT` | Every scope was assessed and none produced evidence clearing the corroboration floor. A statement about **the checks that ran**, bounded by the coverage statement. Never a statement that anything is safe, authentic or uncompromised. |
| `REVIEW` | Something was observed that an analyst should look at: an uncorroborated statistical finding, an unexplained shift, a confounded finding that cannot be separated from a coincident phenomenon, or a severe finding from an uncalibrated detector. |
| `NOT_ASSESSED` | At least one scope had no input. **Outranks `ACCEPT`** — three clean scopes do not average away the fourth's absence — and is outranked by `REVIEW` and `QUARANTINE`, so a gap never softens a real failure. |
| `QUARANTINE` | A deterministic integrity failure, or corroborated evidence across independent families. Reserved; no statistical detector reaches it alone, and no shift verdict reaches it at all. |

## Confidence basis coverage

Which detectors can produce which quality of confidence, in this build:

| Detector | Basis without a calibration table | Basis with one |
|---|---|---|
| `integrity` | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) |
| `exact_duplicate` | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) |
| `near_duplicate` | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `ood` | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `label_consistency` | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `systematic_mislabel` | `STATISTICAL` (≤0.99) | `STATISTICAL` (≤0.99) |
| `contributor_aggregation` | `STATISTICAL`, further capped at the mean confidence of its children | same |
| `model_identity` | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) |
| `model_structure` | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) |
| `model_parameters` (vs reference) | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) |
| `model_parameters` (peer screening) | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `model_behaviour` | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `model_activation` | `DETERMINISTIC` (1.0, INFO severity — context, not detection) | same |
| `model_trigger` | `HEURISTIC_UNCALIBRATED` (≤0.60) | `CALIBRATED` |
| `provenance_verifier` | `DETERMINISTIC` (1.0) | `DETERMINISTIC` (1.0) — there is no table, and there is nothing to calibrate |
| `distribution_shift` (unresolved / no context) | `DETERMINISTIC` (1.0, INFO severity — the observation is a fact, its meaning is not) | same |
| `distribution_shift` (graded) | `STATISTICAL` (1 − p from the permutation null, ≤0.99) | same — the null is constructed at analysis time, so there is no table to load |
| `assurance_policy` | Emits no findings of its own | — |

**Consequence to be aware of:** with no calibration table loaded, no
threshold-based finding can recommend `QUARANTINE` — policy rule
`D-110-severe-but-uncalibrated` downgrades it to `REVIEW`. Run
`cvtrust lab evaluate` and pass `--calibration` to obtain measured confidence.
The model-side equivalent is `cvtrust lab model-build` followed by
`cvtrust lab model-evaluate`, then `cvtrust model assess --calibration`.

**A caveat specific to model calibration:** the unit of evaluation there is the
*model*, so a table is built from a handful of artifacts rather than thousands
of samples. The Wilson lower bound keeps the resulting confidence low precisely
because the support is small, which is the honest behaviour — but it means
model-side `CALIBRATED` confidence will look weak, and it should.

## What "SUPPORTED" does and does not mean

It means: a detector in this build assessed this class, its behaviour was
measured on the attack-lab corpus, and the measurement is in
`docs/testing.md` with its evaluation population.

It does **not** mean: complete detection of that class in general, detection on
imagery unlike the attack-lab corpus, or that a clean result proves absence.
Every report prints these limitations; `docs/limitations.md` is the full list.

For Module 2 there is one further rule, enforced by a test: **no output ever
states that a model is safe.** The strongest positive statement available is
`NO_ANOMALY_DETECTED`, which is a statement about the tests that ran.

For Module 3 the equivalent rule is narrower and stronger: `PROVENANCE VERIFIED`
is a statement about the integrity of the *records*, and about the checks that
actually ran — the report's verification matrix names every check that produced
neither a pass nor a fail, so a reader can see the run's blind spots rather than
infer their absence. It says nothing whatever about the quality of the
inferences those records describe. A cryptographically perfect chain over a
backdoored model is entirely possible, and the assurance system keeps both facts
alive independently (ADR-014).
