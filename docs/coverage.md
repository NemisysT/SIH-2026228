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

## Module 1 build — current coverage

| Attack class | Coverage | Module | Detector | Notes |
|---|---|---|---|---|
| `duplicate_flood` | **SUPPORTED** | 1 | `exact_duplicate` | Cryptographic equality; confidence 1.0 and it means it. |
| `near_duplicate_flood` | **SUPPORTED** | 1 | `near_duplicate` | Two-stage; no rotation/reflection/heavy-crop invariance. |
| `label_flip` | **PARTIAL** | 1 | `label_consistency` | Feature-space dependent; cannot detect a uniformly mislabelled class. |
| `systematic_mislabel` | **SUPPORTED** | 1 | `systematic_mislabel` | Contributor-level claim is exact; sample-level attribution is a screening signal. |
| `ood_insertion` | **PARTIAL** | 1 | `ood` | Requires a trustworthy declared reference; self-reference is weaker and is reported as such. **OOD is never equated with malicious.** |
| `metadata_inconsistency` | **SUPPORTED** | 1 | `integrity` | Deterministic; detects contradictions within the dataset, not a consistent lie. |
| `dataset_tamper` | **SUPPORTED** | 1 | `cvtrust dataset verify` | Needs a manifest from before the tampering. Assessed by a separate command because it is the only class here requiring a second observation in time. |
| `trigger_injection` | `NOT_ASSESSED` | 2 | — | Deferred with the model-side backdoor methods (ADR-008). |
| `model_substitution` | `NOT_ASSESSED` | 2 | — | |
| `model_tampering` | `NOT_ASSESSED` | 2 | — | |
| `model_backdoor` | `NOT_ASSESSED` | 2 | — | |
| `inference_tampering` | `NOT_ASSESSED` | 3 | — | |
| `inference_replay` | `NOT_ASSESSED` | 3 | — | |
| `record_reordering` | `NOT_ASSESSED` | 3 | — | |
| `distribution_shift` | `NOT_ASSESSED` | 4 | — | Population-level shift and the drift-vs-manipulation distinction. Module 1 scores individual samples only. |

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

**Consequence to be aware of:** with no calibration table loaded, no
threshold-based finding can recommend `QUARANTINE` — policy rule
`D-110-severe-but-uncalibrated` downgrades it to `REVIEW`. Run
`cvtrust lab evaluate` and pass `--calibration` to obtain measured confidence.

## What "SUPPORTED" does and does not mean

It means: a detector in this build assessed this class, its behaviour was
measured on the attack-lab corpus, and the measurement is in
`docs/testing.md` with its evaluation population.

It does **not** mean: complete detection of that class in general, detection on
imagery unlike the attack-lab corpus, or that a clean result proves absence.
Every report prints these limitations; `docs/limitations.md` is the full list.
