# Model security — what Module 2 assesses, and what it does not

This is the Module 2 counterpart to `docs/coverage.md`, and it is written to be
read by someone looking for the gaps. A clean model report from a system that
never tested for an attack is not a clean result, and this file is what makes
the difference visible.

**The word _safe_ does not appear in any Module 2 output.** A model is only ever
assessed against the attacks and behaviours actually tested, under a stated
access mode and a stated probe battery. The strongest positive statement the
system can make is `NO_ANOMALY_DETECTED`, which is a statement about the tests
that ran, not about the model. This is enforced by a test
(`test_the_report_never_asserts_that_the_model_is_safe`), not by review.

---

## 1. The assessment matrix

Module 2 reports **six independent levels** and never combines them into a
single number. There is no `overall_score` field in the report schema and there
will not be one: a "model trust = 72%" figure is strictly less informative than
the matrix below, because it cannot tell an analyst what to do next.

```
MODEL ASSURANCE
────────────────────────────
Model:      detector_v17.onnx
SHA-256:    abc123…
Access:     WHITE_BOX  (gradients absent)

Identity:   ⚠ MISMATCH             different artifact from the reference
Structure:  ✓ CONSISTENT           weight-blind graph digest matches
Parameters: ⚠ ANOMALOUS            8 tensors differ, change is distributed
Behaviour:  ⚠ ANOMALOUS            3.2% prediction disagreement on the battery
Activation: ✓ NO_ANOMALY_DETECTED  context only — see §6
Trigger:    ‼ HIGH_RISK_INDICATOR  patch drives 79% of probes onto class 2

Disposition: QUARANTINE REQUIRED
```

Statuses form a closed vocabulary: `VERIFIED`, `NO_ANOMALY_DETECTED`,
`CONSISTENT`, `MISMATCH`, `ANOMALOUS`, `HIGH_RISK_INDICATOR`,
`REQUIRES_WHITE_BOX`, `NOT_ASSESSED`, `ASSESSMENT_UNAVAILABLE`.

---

## 2. Coverage matrix

| Attack / anomaly | White-box | Black-box | Status | Notes |
|---|---:|---:|---|---|
| Model substitution | ✓ | ✓ | **SUPPORTED** | SHA-256 over content. Needs a trusted reference; without one it is `NOT_ASSESSED`, not clean. |
| Re-serialisation (new bytes, same model) | ✓ | ✓ | **SUPPORTED** | Distinguished from substitution by the three-digest design (§3). Severity capped at MEDIUM. |
| Structural modification | ✓ | — | **SUPPORTED** | Weight-blind graph digest, then per-layer diff. Needs `graph` access. |
| Parameter modification (vs reference) | ✓ | — | **SUPPORTED** | Deterministic per-tensor comparison; localises the change to named tensors. |
| Parameter anomaly (no reference) | partial | — | **PARTIAL** | Peer-group robust z-screening. A screening signal only; severity capped at MEDIUM. |
| Behavioural deviation (vs reference) | ✓ | ✓ | **SUPPORTED** | Five metrics over a versioned, digested battery. |
| Behavioural instability (no reference) | ✓ | ✓ | **PARTIAL** | Metamorphic consistency; reference-free. |
| Patch backdoor, declared family | ✓ | ✓ | **SUPPORTED** | Measured P=1.00, R=0.83, FPR=0.00 over 15 lab models (§5). The single miss is the out-of-family blended trigger the lab predicted would be missed. |
| Trigger reconstruction (Neural Cleanse) | partial | — | **PARTIAL** | Needs gradients → torch/TorchScript only. **Anomaly index is uninterpretable below 8 classes** (§6). |
| Blended / low-opacity backdoor | partial | partial | **PARTIAL** | Outside the full-opacity probe family. At opacity 0.12 it was caught by feature overlap (luck, not design); at opacity 0.08 it was **missed**, as predicted. |
| Sample-specific / input-aware trigger | — | — | **NOT_SUPPORTED** | The optimisation searches for one *universal* mask, so it cannot find a per-input one. Declared, not assessed. |
| Semantic backdoor | — | — | **NOT_SUPPORTED** | Trigger is a real-world object, not a perturbation. |
| Adaptive backdoor (trained against these detectors) | limited | limited | **NOT_SUPPORTED** | Documented in the literature as evadable; no defence claimed. |
| Activation-based backdoor detection | — | — | **PARTIAL (context only)** | Measured **non-discriminating** in this build. See §6. |
| Benchmark evaluation (TrojAI / BackdoorBench) | — | — | **NOT_ASSESSED** | Only from a locally vendored directory. Never downloaded. §8. |
| Data-side `trigger_injection` | — | — | **NOT_ASSESSED** | Dataset forensics, not model forensics. Open item; see §10. |

Verify this table against the running build:

```bash
cvtrust info
```

---

## 3. Model identity — three digests, three questions

One digest is not enough to describe a model, for the same reason one digest is
not enough to describe an image (Module 1's `file_sha256` / `pixel_sha256`
split).

| Digest | Taken over | Answers |
|---|---|---|
| `file_sha256` | the bytes on disk | *Is this the same artifact?* |
| `graph_digest` | topology, operators, tensor names, shapes, dtypes — **no weight values** | *Is this the same architecture?* |
| `parameter_digest` | weight tensor values, canonically ordered, container-independent | *Are these the same weights?* |

The decomposition separates cases an analyst must never see merged:

| `file` | `graph` | `parameter` | Interpretation | Severity |
|---|---|---|---|---|
| = | = | = | Same artifact | — |
| ≠ | = | = | **Re-serialised.** Behaviour unchanged. | MEDIUM |
| ≠ | = | ≠ | Same architecture, different weights: fine-tune, retrain, **or backdoor** | HIGH |
| ≠ | ≠ | ≠ | Different model — substitution | CRITICAL |

Identity is **never** derived from a filename, path, display name or declared
version string. The lab's `substitution_architecture` scenario deliberately
keeps the reference's architecture name in its ONNX metadata, and is caught
anyway, because the declared name plays no part in the decision. That is pinned
by `test_declared_metadata_cannot_launder_a_substituted_model`.

`parameter_digest` quantises floats to a fixed decimal grid before hashing, so
the digest describes weight *values* rather than their storage dtype — a model
exported once at float32 and once at float16 with the same weights is not
reported as having different weights.

---

## 4. Access modes and capabilities

A WHITE_BOX / BLACK_BOX binary is not enough to be honest, because the formats
differ in ways that change which published method can run:

| Capability | ONNX | Torch `nn.Module` | TorchScript | Black-box |
|---|---:|---:|---:|---:|
| `inference` | ✓ | ✓ | ✓ | ✓ |
| `graph` | ✓ | partial | ✓ | ✗ |
| `parameters` | ✓ | ✓ | ✓ | ✗ |
| `activations` | ✓ | ✓ | **✗** | ✗ |
| `gradients` | **✗** | ✓ | ✓ | ✗ |

Two consequences are reported in every affected run:

- **ONNX has no input gradients.** ONNX Runtime does not differentiate, so
  Neural Cleanse trigger *reconstruction* is not performed on an ONNX artifact.
  A gradient-free trigger-family probe runs instead, under a different method
  name (`trigger_family_probe`) and `Coverage.PARTIAL`.
- **TorchScript refuses forward hooks.** A `ScriptModule` raises on
  `register_forward_hook`, so activation capture is unavailable and the
  spectral-signature and clustering analyses report `NOT_ASSESSED` rather than
  running on a substitute representation.

A method that wanted a capability and did not get it reports
`REQUIRES_WHITE_BOX` (the remedy is more access) or `NOT_ASSESSED` (the remedy
is a different export). Conflating those would send the analyst after the wrong
thing.

`--black-box` genuinely *removes* capabilities from the handle before analysis
rather than flagging them, so white-box methods take their real unavailable
path. It is not a simulation.

---

## 5. Measured results

Evaluation population: **15 model artifacts** from
`cvtrust.attack_lab.model_attacks` — small CNNs (~24k parameters, 6 classes)
trained from published seeds on the Module 1 synthetic corpus. The unit of
evaluation is the *model*, so every rate rests on few observations and the
Wilson lower bound in the calibration tables reflects that.

Reproduce with:

```bash
cvtrust lab model-build --out model_lab
cvtrust lab model-evaluate model_lab
```

### Backdoor detection — trigger level

| Metric | Value |
|---|---|
| Precision | **1.000** |
| Recall | **0.833** (5 of 6) |
| F1 | **0.909** |
| False-positive rate | **0.000** (0 of 9 non-backdoor models) |
| AUROC | **0.981** |

Per-model attack success rates, which is what makes the threshold defensible
rather than tuned:

| Scenario | Ground truth | Score | Outcome |
|---|---|---|---|
| `backdoor_blended` | backdoor | 0.833 | detected |
| `backdoor_badnets` | backdoor | 0.750 | detected |
| `backdoor_small_patch` | backdoor | 0.750 | detected |
| `backdoor_high_rate` | backdoor | 0.667 | detected |
| `backdoor_low_rate` | backdoor | 0.667 | detected |
| — threshold — | | **0.500** | |
| `substitution_architecture` | not a backdoor | 0.333 | correctly quiet |
| `backdoor_blended_faint` | backdoor | 0.292 | **MISSED** |
| `clean_retrain_1` | clean | 0.167 | correctly quiet |
| `clean_unusual_init` | clean | 0.167 | correctly quiet |
| `parameter_tamper_small/large` | tampering | 0.167 | correctly quiet |
| `reserialised` | not a backdoor | 0.125 | correctly quiet |
| `clean_finetuned` | clean | 0.042 | correctly quiet |
| `clean_retrain_2` | clean | 0.042 | correctly quiet |
| `clean_retrain_0` | clean | 0.000 | correctly quiet |

The threshold sits in a genuinely empty region: the highest non-backdoor scores
0.333 and the lowest *detected* backdoor scores 0.667.

**The one miss is the one the lab predicted.** `backdoor_blended_faint` is a
Chen et al. blended trigger at opacity 0.08 — deliberately constructed to sit
**outside** the full-opacity patch family the probe sweeps. Its ground truth
records `trigger_in_declared_probe_family: false` and the note "The
gradient-free probe is expected to MISS it. This scenario exists to measure that
miss rather than to be detected." It has a true attack success rate of 1.000
against its own trigger, so the backdoor is real and effective; the probe simply
does not test for it.

That is the coverage boundary working as designed and being measured rather than
asserted. `backdoor_blended` at opacity 0.12 *was* caught, but by feature
overlap with the full-opacity family rather than by design, which is luck and is
reported as such.

### Degradation under black-box access

Running the same 15 scenarios with graph, parameter, activation and gradient
access genuinely removed:

| Attack class | White-box | Black-box |
|---|---|---|
| `model_backdoor` | P 1.000 / R 0.833 | **P 1.000 / R 0.833** — unchanged |
| `model_substitution` | 15/15 correct | **15/15 correct** — unchanged |
| `model_tampering` | P 0.143 / R 1.000 | **P 0 / R 0** — nothing flagged |

The first two are unchanged because hashing bytes and probing a trigger family
need no internal access. The third drops to zero *correctly*: parameter analysis
reports `REQUIRES_WHITE_BOX` and flags nothing, which the report shows as an
unassessed level with a reason rather than as a clean one.

### Identity — deterministic verification

Scored against the fact it asserts (do the digests differ?), not against an
attack label:

| Metric | Value |
|---|---|
| Correct | **15 / 15** |
| Accuracy | **1.000** |

> **Why the attack-labelled precision for identity is 0.133 and why that number
> is meaningless.** Every lab artifact differs from the reference, *including*
> the clean retrains — a model retrained from a different seed is a different
> file with different weights. The identity detector reports MISMATCH on all of
> them and every one of those reports is true. Scored against "was this an
> attack?", the clean retrains become false positives. The detector did not get
> anything wrong; the question was wrong. Both framings are published in the
> evaluation output with this caveat attached.

### Performance (Apple M-series CPU, single-threaded)

| Measurement | Value |
|---|---|
| Model load + manifest | < 50 ms |
| Full ONNX assessment, white-box (94-probe battery) | **121 ms mean, 220 ms max** |
| Full assessment, black-box | 89 ms mean, 116 ms max |
| Full TorchScript assessment (includes Neural Cleanse) | 4.5 s mean, 6.2 s max |
| Full 15-scenario ONNX evaluation | ~1.8 s |
| Building the whole model lab (16 models) | ~90 s |
| Peak RSS | ~437 MB |

Neural Cleanse dominates the TorchScript pathway, which is the expected cost of
a per-class optimisation and the reason the budget is configurable and recorded.

No GPU required; none used. CPU execution is the baseline workflow.

---

## 6. Two measured negative results

These are the most important entries in this document, because they are places
where a published method did **not** work in this setting and the system says so
rather than shipping a detector that fires incorrectly.

### 6.1 Activation analysis does not discriminate here

**Methods:** spectral signatures (Tran, Li & Madry, NeurIPS 2018) and activation
clustering (Chen et al., AAAI-19 SafeAI).

Both were published as **training-set** poisoning detectors: they assume the
poisoned training data is in hand and look for the poisoned subset inside it.
Module 2 does not have the supplier's training set — that is the premise — so
the implementation applies them to the probe battery instead.

Measured across the full lab, as lift over the trigger probes' 0.447 base rate
in the battery:

| Group | Spectral lift | Clustering lift |
|---|---|---|
| 6 backdoored models | 0.00 – 0.90 | 0.00 – 1.15 |
| 9 clean / non-backdoor | 0.42 – **1.64** | 0.00 – 1.20 |

**The backdoored range lies inside the clean range, and the highest lift of any
model belongs to a clean one.** An earlier revision of this code thresholded
that statistic; it fired on `clean_retrain_0` and stayed silent on
`backdoor_badnets` — exactly backwards. Running the lab against it is what
caught that.

Two structural reasons, neither fixable by tuning:

1. Any working classifier separates a bright corner patch from a clean image.
   That is a visual difference, and detecting it is the model's job, so
   separation carries almost no information about whether a backdoor exists.
2. The majority/minority relationship inverts. In the original setting the
   poisoned examples are a small minority *inside the target class*. Here the
   triggered probes are driven onto the target class and become its *majority*,
   so the minority cluster the method reports is the clean subset — it flags the
   wrong half.

**Decision:** the activation level runs both analyses, records their full output
as evidence, and reports **corroborating context at INFO severity** when a
backdoor signal has already been established behaviourally. In that case the
measurement is genuinely useful — it names the layer and representation
structure carrying the behaviour. It is localisation, not detection, its
coverage is `PARTIAL` with this measurement as the stated reason, and it never
raises an independent backdoor finding.

### 6.2 Neural Cleanse's anomaly index is uninterpretable below 8 classes

**Method:** Wang et al., IEEE S&P 2019.

The implementation is faithful, including the paper's **dynamic λ scheduler** —
which is not an optional refinement. With a fixed mask penalty, each class
converges to whatever its own loss landscape allows, the per-class norms are not
comparable, and the MAD over them is dominated by that incomparability. Measured
here: a fixed penalty gave the true backdoor class an anomaly index of 1.31,
below the threshold of 2 — a miss. With the dynamic schedule the search
converges to the smallest mask reaching the success target, and the **ranking
becomes correct on every backdoored model**: the true target class has the
smallest reconstructed mask, by a factor of 5 to 50.

But the *index* still does not separate clean from backdoored at this class
count:

| Model | Smallest mask L1 | Its attack success rate |
|---|---|---|
| `backdoor_badnets` (class 2, true target) | 5.9 | 1.00 |
| `clean_retrain_0` (class 0, **no backdoor**) | 6.8 | 1.00 |

A 24k-parameter CNN over 6 synthetic classes has classes that are trivially
reachable by a tiny universal perturbation, so a clean model produces the same
signature. Wang et al. evaluate on datasets with **10 classes at minimum**
(MNIST) and up to 2622.

**Decision:** below `MIN_CLASSES_FOR_ANOMALY_INDEX = 8`, the index is declared
uninterpretable, is not thresholded, and flags nothing. The per-class mask norms
and their ranking are still reported as evidence, because the ranking is
genuinely informative. Coverage stays `PARTIAL` with the reason attached. On a
model with enough classes the index is reported and thresholded normally — that
path is implemented but is **not measured by this lab**, and is therefore not
claimed as SUPPORTED.

### 6.3 A third correction, for completeness

Peer-group parameter screening originally used the conventional
Iglewicz–Hoaglin threshold of 3.5. Simulated against the null — peer groups
drawn from one distribution, so every flag is a false alarm:

| Group size | z = 3.5 | z = 5.0 | z = 6.0 | z = 8.0 |
|---|---|---|---|---|
| 6 | 0.350 | 0.150 | 0.090 | 0.033 |
| 8 | 0.360 | 0.102 | 0.050 | 0.018 |
| 12 | 0.290 | 0.065 | 0.013 | 0.000 |
| 20 | 0.280 | 0.035 | 0.013 | 0.000 |

At 3.5, roughly a third of clean models would carry a parameter-anomaly finding.
The conventional threshold is for a *single* statistic on a large sample; this
screening tests **four** statistics on groups often smaller than ten tensors.
Fixed by applying the Croux–Rousseeuw finite-sample MAD correction and raising
the threshold to **8.0**, measured at ≤3% family-wise. Reproduced by
`test_peer_screening_false_alarm_rate_is_measured_not_assumed`.

A second defect surfaced alongside it: grouping peers by operator type alone put
BatchNorm scales, biases, running means and running variances in one group,
whose median and MAD describe nothing. Role-aware grouping
(`<op_type>/<role>`) took a clean lab model from 8 reported outliers to 0.

---

## 7. Deserialisation is an attack surface

A `.pt`/`.pth` file produced by `torch.save` on an `nn.Module` is a **pickle**,
and unpickling executes code from the file. This is an integrity tool whose
premise is that the artifact is untrusted, so:

- `torch.load(..., weights_only=True)` is the default, restricting the unpickler
  to tensors and plain containers.
- A full-module pickle **fails that check and is refused**, with a message
  naming the safe alternatives. Pinned by
  `test_a_module_pickle_is_refused_by_default`.
- Loading one anyway requires an explicit `--allow-unsafe-deserialisation`, and
  the manifest records that it happened.

**Ask suppliers for ONNX or TorchScript.** Neither unpickles arbitrary Python.
ONNX additionally gives activation access; TorchScript additionally gives
gradients. Supplying both is ideal, and is what the model lab does.

Image and model decoding are not sandboxed. For a hostile deployment, run
assessments as an unprivileged user in a container or VM with no network.

---

## 8. Vendoring benchmark artifacts into an air-gapped environment

NIST TrojAI and BackdoorBench are the standard evaluation corpora for backdoor
detection. **Neither is downloaded, ever.** Module 2 reads them only from a
local directory an operator has populated out of band.

Expected layout:

```
<benchmark_dir>/
  index.json
  models/
    id-00000001/model.onnx
    ...
```

```json
{
  "benchmark": "trojai",
  "round": "train-round-1",
  "license": "<recorded verbatim, never interpreted>",
  "models": [
    {"id": "id-00000001",
     "path": "models/id-00000001/model.onnx",
     "ground_truth": {"poisoned": true, "trigger_family": "polygon",
                      "target_class": 3}}
  ]
}
```

Point the configuration at it:

```yaml
model:
  benchmark_dir: /srv/benchmarks/trojai-round1
```

`ground_truth` is read **only** by the evaluation harness, never by a detector —
the same separation Module 1 enforces by keeping attack ground truth outside the
dataset root.

**Licensing.** TrojAI artifacts are published by NIST/IARPA and BackdoorBench by
its authors; each carries its own terms. Obtain them through your own channel,
confirm the terms permit use in your deployment, and record the licence text in
`index.json`. This project vendors neither and makes no claim about their terms.

If the directory is absent, empty or unreadable, the answer is `NOT_ASSESSED`
with the reason `"required local artifact unavailable"` — never a silent pass
and never a fetch.

---

## 9. Reproducibility

Every model assessment records `run_id`, `seed`, `config_hash`, all three model
digests, the reference digests, the battery version and digest, detector and
adapter versions, runtime versions (onnx, onnxruntime, torch), platform,
timestamps and timings.

Module 2's specific determinism hazards and their handling:

| Hazard | Handling |
|---|---|
| ONNX Runtime thread count changing float reduction order | session pinned to 1 intra-op / 1 inter-op thread, `ORT_SEQUENTIAL`, graph optimisation disabled |
| Torch thread count | `torch.set_num_threads(1)`, inference under `no_grad` |
| Variable batch size changing reduction order | battery forwarded in a fixed, configured batch size |
| Float text formatting in digests | everything passes through `digest_safe`/`quantize` (ADR-004) |
| Trigger-search optimiser randomness | seeded from the run seed, never global RNG |
| Non-determinism in lab model *training* | every seed derived via SHA-256 from `(seed, scenario, index)`, never Python's salted `hash()` |

Cross-process determinism of a full assessment and of model training is asserted
by subprocess tests in `tests/regression/test_model_determinism.py`.

---

## 10. Known gaps, stated rather than hidden

1. **Data-side `trigger_injection` remains `NOT_ASSESSED`.** Module 1's ADR-008
   deferred it to Module 2 on the grounds that doing it without the model-side
   counterpart would be a partial capability presented as a complete one. Module
   2 delivers the model side in full but does *not* add the data-side image
   detector: that is dataset forensics, and adding it under a model-forensics
   brief would be scope drift. It is an open item, not a dropped one.
2. **Activation-based detection contributes no independent signal** (§6.1).
3. **Neural Cleanse's index is unmeasured above 8 classes** (§6.2). The code
   path exists; this lab cannot exercise it, so it is not claimed.
4. **Adaptive adversaries are not defended against.** An attacker who optimises
   a backdoor against these specific detectors — regularising the reconstructed
   mask norm toward the clean population, or suppressing the spectral signature
   during training — is known in the literature to succeed.
5. **The evaluation population is small and synthetic.** 15 artifacts of one
   architecture family on one synthetic corpus. Recalibration against
   representative models is a deployment step.
6. **A reference model is a trust assumption, not a fact.** Every
   reference-dependent claim assumes the reference was obtained through a
   channel independent of the one that supplied the artifact under assessment.
   Module 3 will sign manifests; until then, that assumption is unverified.
