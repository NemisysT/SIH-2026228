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
| `inference_tampering` | `NOT_ASSESSED` | 3 | — | |
| `inference_replay` | `NOT_ASSESSED` | 3 | — | |
| `record_reordering` | `NOT_ASSESSED` | 3 | — | |
| `distribution_shift` | `NOT_ASSESSED` | 4 | — | Population-level shift and the drift-vs-manipulation distinction. Module 1 scores individual samples only. |

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
