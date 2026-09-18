# Module 2 Plan — Model Forensics + Backdoor Assurance

**Project:** `cvtrust` — Trustworthy Computer Vision Integrity Assurance (SIH26228)
**Module:** 2 of 5 — Model Integrity Assurance
**Status:** design frozen for implementation
**Depends on:** Module 1 (evidence schema, canonical serialisation, hashing, run
context, config, registry, calibration, disposition, coverage, attack lab,
reporting). Module 1 interfaces are treated as **contracts**.

---

## 1. Scope boundary

### In scope

Ingest an untrusted computer-vision **model artifact**, establish its
cryptographic identity, describe its structure, characterise its behaviour
against a versioned probe battery, compare it to a trusted reference where one
exists, look for backdoor-like behaviour with a small set of well-understood
published methods, and emit findings in the **existing Module 1 `Finding`
schema** with explicit coverage and limitations.

### Explicitly out of scope for Module 2

| Capability | Deferred to |
|---|---|
| Ed25519 signatures over manifests / inference records | Module 3 |
| Inference hash chain, replay detection, record reordering | Module 3 |
| Population-level distribution-shift characterisation, cross-module evidence fusion | Module 4 |
| Analyst web UI | Module 5 |
| **Data-side** `trigger_injection` detection (patch artifacts in *training images*) | remains open — see §11 |

### What Module 2 must never claim

The word *safe* does not appear in any Module 2 output. The vocabulary is:

```
VERIFIED · NO_ANOMALY_DETECTED · SUSPICIOUS · HIGH_RISK_INDICATOR
ASSESSMENT_UNAVAILABLE · NOT_ASSESSED · REQUIRES_WHITE_BOX · PARTIAL
```

A model is only ever assessed *against the attacks and behaviours actually
tested*, under a stated access mode, with a stated battery.

---

## 2. Threat model

**Trust boundary.** The model artifact, every field of its embedded metadata,
its filename, its declared version string and its declared architecture name are
**untrusted input**. The analyst's machine, the `cvtrust` code, the
configuration, and the *reference model designation* are trusted.

**Adversary.** A party who can place a model artifact where the pipeline will
load it: a compromised model registry, a malicious supplier, an insider with
write access to the deployment, or a poisoned training pipeline upstream.

**Adversary capabilities assumed.**

- Replace the artifact wholesale with a different model (substitution).
- Re-serialise the same model so the bytes differ but behaviour does not.
- Modify a subset of weights or the graph after assurance (tampering).
- Train or fine-tune a model with a backdoor installed by data poisoning.
- Choose the trigger family, its size, position, opacity and target class.
- Read this repository, and therefore know exactly which probes we run.

**Adversary capabilities NOT defended against, stated up front.**

- An adaptive adversary who optimises the backdoor *against these detectors*
  (e.g. regularising the trigger's reconstructed mask norm toward the clean
  population, or suppressing the spectral signature during training). The
  published methods we implement are known to be evadable in this setting and
  we say so rather than claiming otherwise.
- Sample-specific / input-aware triggers, semantic backdoors (a real-world
  object as the trigger), and triggers distributed across the whole image at
  very low amplitude. These are tested in the adversarial suite with the
  expected outcome being **degraded, honestly reported coverage**, not
  detection.

| # | Threat | Attack class id | Module 2 posture |
|---|---|---|---|
| M1 | Model substitution | `model_substitution` | SUPPORTED — deterministic (content identity) |
| M2 | Model re-serialisation (same weights, new bytes) | `model_substitution` | SUPPORTED — distinguished from M1 by the three-digest design (§4) |
| M3 | Structural modification | `model_tampering` | SUPPORTED with a reference; PARTIAL without |
| M4 | Parameter modification | `model_tampering` | SUPPORTED with a reference (white-box); PARTIAL without |
| M5 | Behavioural deviation | `model_tampering` | SUPPORTED with a reference; PARTIAL without (metamorphic self-consistency only) |
| M6 | Patch backdoor (BadNets family) | `model_backdoor` | SUPPORTED white-box; PARTIAL black-box |
| M7 | Blended / low-opacity backdoor | `model_backdoor` | PARTIAL — measured, degraded |
| M8 | Sample-specific / adaptive backdoor | `model_backdoor` | NOT_SUPPORTED — declared, tested, reported as a miss |

---

## 3. Access modes — a hard architectural boundary

The brief requires a WHITE_BOX / BLACK_BOX split. A binary is not enough to be
honest, because **ONNX gives us parameters and activations but not gradients**,
and Neural Cleanse needs gradients. So the manifest carries both:

- `access_mode` — the headline: `WHITE_BOX` | `BLACK_BOX`
- `capabilities` — the fine-grained truth, each independently declared:

| Capability | Meaning | ONNX | Torch `nn.Module` | TorchScript | Black-box |
|---|---|---|---|---|---|
| `inference` | forward pass | ✓ | ✓ | ✓ | ✓ |
| `graph` | topology, op sequence, tensor shapes | ✓ | partial | ✓ | ✗ |
| `parameters` | weight tensor values | ✓ | ✓ | ✓ | ✗ |
| `activations` | intermediate tensor values | ✓ | ✓ | ✓ | ✗ |
| `gradients` | ∂loss/∂input | ✗ | ✓ | ✓ | ✗ |

Consequence, stated in every report: on an ONNX artifact, trigger
**reconstruction** (Neural Cleanse) is not performed. A gradient-free
**trigger-family probe** is performed instead and is labelled as such, with
`Coverage.PARTIAL`. A detector never describes a black-box or gradient-free
result in white-box language.

A white-box method invoked without the capability it needs returns
`Coverage.REQUIRES_WHITE_BOX` or `Coverage.NOT_ASSESSED` with a machine-readable
reason — reusing Module 1's `DetectorUnavailable` contract verbatim.

---

## 4. Model identity — three digests, three questions

Module 1 established that one digest is not enough for an image (`file_sha256`
for the artifact, `pixel_sha256` for the content). The same argument applies,
more strongly, to a model. Module 2 computes three:

| Digest | Taken over | Answers |
|---|---|---|
| `file_sha256` | the bytes on disk | *Is this the same artifact?* |
| `graph_digest` | topology, op sequence, tensor names, shapes, dtypes — **no weight values** | *Is this the same architecture?* |
| `parameter_digest` | the weight tensor values, canonically ordered, container-independent | *Are these the same weights?* |

This decomposition is what lets the report separate cases an analyst must not
confuse:

| `file` | `graph` | `parameter` | Interpretation |
|---|---|---|---|
| = | = | = | Same artifact. |
| ≠ | = | = | **Re-serialised.** Identity mismatch, behaviour unchanged. Reported as `model_substitution` with severity MEDIUM, not HIGH — the evidence says what it says. |
| ≠ | = | ≠ | Same architecture, different weights: fine-tune, retrain, or **backdoor**. |
| ≠ | ≠ | ≠ | Different model. Substitution. |

Identity is **never** based on filename, path, display name or a
user-supplied version string. SHA-256 only, via `core/hashing.py`. No custom
cryptography.

---

## 5. Package layout

```
src/cvtrust/models/            NEW — model ingestion and analysis primitives
    base.py            ModelAdapter protocol, ModelHandle, AccessMode,
                       Capability, ModelOutput, MODEL_ADAPTERS registry
    manifest.py        ModelManifest, build_model_manifest, verify_model_manifest
    onnx_adapter.py    ONNX  (onnx + onnxruntime)
    torch_adapter.py   PyTorch nn.Module / state_dict
    torchscript_adapter.py
    battery.py         ReferenceBattery — versioned, digested probe inputs
    behaviour.py       BehaviouralFingerprint + the five divergence metrics
    params.py          layer-wise parameter statistics and comparison
    activations.py     spectral signature + activation clustering
    trigger.py         Neural Cleanse (gradient) + gradient-free patch sweep
    benchmark.py       optional LOCAL TrojAI / BackdoorBench ingestion

src/cvtrust/detectors/
    model_base.py      ModelAnalysisContext, ModelDetector, MODEL_DETECTORS
    model_identity.py      model_substitution      DETERMINISTIC
    model_structure.py     model_tampering         DETERMINISTIC
    model_parameters.py    model_tampering         white-box
    model_behaviour.py     model_tampering         black-box capable
    model_activation.py    model_backdoor          white-box
    model_trigger.py       model_backdoor          white-box / gradient-free

src/cvtrust/model_pipeline.py  assess_model() — the Module 2 entry point
src/cvtrust/reporting/model_report.py   ModelAssuranceReport
src/cvtrust/attack_lab/model_synth.py   small CNN + trainer (CPU, seconds)
src/cvtrust/attack_lab/model_attacks.py model scenario matrix
src/cvtrust/attack_lab/model_evaluate.py evaluation + calibration
```

**Nothing in Module 1 is replaced.** `FindingFactory`, `CalibrationSet`,
`DispositionPolicy`, `CoverageStatement`, `RunContext`, `Finding`,
`canonical_json`, `sha256_*` and the `Registry` are reused as-is. The only
Module 1 edit required is widening `FindingFactory.__init__`'s type hint from
`AnalysisContext` to a two-attribute structural protocol (`calibration`,
`policy`) — it already uses nothing else. That is a type-level change with no
runtime behaviour change.

---

## 6. Reference battery

Deterministic, versioned, digested. For a fixed `(seed, battery config, input
spec)` the probe tensors are bit-identical on every machine, and their digest is
recorded in the report.

| Category | Content | Why it is in the battery |
|---|---|---|
| `clean` | class-conditional samples from the Module 1 synthetic generator | the operating point; everything else is measured relative to it |
| `borderline` | convex interpolations between two class prototypes | decision-boundary behaviour is where a retrained model differs first |
| `perturbation` | brightness, contrast, gaussian noise, JPEG re-encode, small translation, small crop — applied to `clean` | metamorphic pairs: prediction *should* be preserved, so a flip is a measurement |
| `ood` | the Module 1 thermal-palette out-of-distribution renderer | guards the inverse error: OOD input must not be reported as a backdoor |
| `trigger_probe` | a declared patch family: {positions} × {sizes} × {patterns} | the only inputs on which a targeted-transition claim may be made |

`battery_digest = SHA-256(canonical(spec ‖ per-probe tensor digests))`.

A behavioural claim without its battery digest is not a measurement, so the
digest is mandatory in every behavioural finding's evidence.

---

## 7. Behavioural difference metrics — five, each justified

§12 of the brief says choose a small number of strong, explainable metrics. We
choose five and record why each exists.

1. **Prediction agreement** — fraction of probes where supplied and reference
   agree on argmax.
   *Why:* the most directly interpretable difference there is; an analyst can
   be shown the disagreeing probes. First thing that moves under substitution.
2. **Jensen–Shannon divergence** (base 2, mean over probes, bounded [0,1]).
   *Why JS and not KL:* KL is unbounded and undefined when a class has zero
   probability under one model — which happens constantly with softmax
   underflow. JS is symmetric, always finite, and bounded, so values are
   comparable across models and across runs. KL is **deliberately not used**.
3. **Confidence shift** — mean top-1 confidence, supplied minus reference.
   *Why:* retraining and fine-tuning move calibration even when argmax is
   preserved; this catches "same answers, different model".
4. **Metamorphic consistency** — fraction of (clean, perturbed) pairs whose
   prediction is preserved. Absolute, so it needs **no reference model**, which
   is what keeps the black-box pathway meaningful on its own.
5. **Targeted transition concentration** — over `trigger_probe` inputs, the
   largest share of prediction flips landing on a single class, with the
   corresponding attack success rate.
   *Why:* generic brittleness scatters flips across classes; a targeted
   backdoor concentrates them on one. That asymmetry is the signal, and it is
   what separates "fragile model" from "backdoor-like behaviour".

Not implemented, deliberately: accuracy against a ground-truth label set (we do
not hold trustworthy labels for an arbitrary supplied model's task), and cosine
similarity of embeddings (only defined when both models expose comparable
internal layers — reported instead as a white-box parameter/activation
comparison where that holds).

---

## 8. Backdoor methods — the research-bearing part

Four published methods, each researched, each with a written method card in
`docs/research.md` covering threat model, assumptions, required access,
required data, cost, strengths, weaknesses, known failure cases and our
implementation decision. **Chosen for being well-understood, not for being
impressive.**

| Method | Origin | Access | What we do with it |
|---|---|---|---|
| **Neural Cleanse** trigger reconstruction | Wang et al., IEEE S&P 2019 | white-box + **gradients** | Per-target-class mask/pattern optimisation; MAD anomaly index over mask L1 norms. Implemented for the Torch pathway only. |
| **Gradient-free trigger-family probe** | our adaptation of the BadNets threat model (Gu et al. 2017) to a black-box sweep | inference only | Declared patch family swept over position × size × pattern; ASR + target concentration. Explicitly *not* reconstruction, and labelled `trigger_probe`. |
| **Spectral signatures** | Tran, Li & Madry, NeurIPS 2018 | white-box activations | Per-class top-singular-vector projection outlier score over the battery representation matrix. |
| **Activation clustering** | Chen et al., AAAI-W 2019 (SafeAI) | white-box activations | Per-class PCA→2-means split with silhouette + minority-share, the published backdoor signature. |

**Important honesty note carried into the code and the docs:** spectral
signatures and activation clustering were published as *training-set* poisoning
detectors — they assume access to the poisoned training data and look for the
poisoned subset inside it. We apply them to the **probe battery** instead, which
changes what they can claim: they detect that the model maps a subset of
*probes* into an anomalously separated representation region. That is a real and
useful signal when the battery contains trigger probes, and it is a materially
weaker claim than the original papers make. This adaptation is documented as an
adaptation, not presented as the original method.

Rejected, with reasons (recorded in `docs/research.md`): STRIP (requires a
superimposition assumption that does not hold for low-opacity blends and costs
N× inference per query), Fine-Pruning (a *mitigation*, not a detector, and it
modifies the artifact under assessment), MNTD (needs a meta-classifier trained
over thousands of shadow models — exactly the "neural network that predicts
whether another neural network is malicious" the brief forbids), and ABS
(stimulation analysis with a large, fragile implementation surface relative to
what it would add over Neural Cleanse here).

---

## 9. Detector map

| Detector | Attack class | Access needed | Confidence basis | Without a reference model |
|---|---|---|---|---|
| `model_identity` | `model_substitution` | metadata only | DETERMINISTIC | NOT_ASSESSED (needs a reference to compare to) |
| `model_structure` | `model_tampering` | `graph` | DETERMINISTIC | NOT_ASSESSED, reason recorded |
| `model_parameters` | `model_tampering` | `parameters` | DETERMINISTIC (vs reference) / CALIBRATED (peer-layer) | PARTIAL — peer-layer robust z-score only |
| `model_behaviour` | `model_tampering` | `inference` | CALIBRATED | PARTIAL — metamorphic consistency only |
| `model_activation` | `model_backdoor` | `activations` | CALIBRATED | SUPPORTED — both methods are reference-free |
| `model_trigger` | `model_backdoor` | `gradients` → full; `inference` → probe | CALIBRATED | SUPPORTED — reference-free |

Severity and confidence stay **separate** (§22 of the brief, ADR-006 of Module
1). A trigger-search hit is `severity=HIGH` because a backdoor is consequential,
while its confidence comes from the measured calibration table and is typically
well below 1.0. Both numbers are printed, never multiplied together.

---

## 10. Model attack lab

Extends, never replaces, the Module 1 attack lab. Same contract: ground truth is
**generated, not annotated**, and is written **outside** the directory the
detectors read.

```
model_lab/
  _reference/  reference.pt · reference.onnx · training_spec.json
  <scenario>/
    model.onnx · model.pt        <- the only thing a detector sees
    ground_truth.json            <- what was actually done
    attack_config.json           <- seed + parameters, sufficient to regenerate
```

Scenario matrix (§27 of the brief — the point is to include attacks that do
**not** match our detectors' assumptions):

| Family | Variants | Purpose |
|---|---|---|
| clean | 3 seeds | false-positive floor |
| clean, fine-tuned | 1 | legitimately different weights, no backdoor |
| clean, unusual init | 1 | "naturally unusual weights" — must not become a finding |
| clean, distribution-shifted battery | 1 | operational variation must not become "backdoor" |
| re-serialised | 1 | identity ≠ behaviour, the distinction made visible |
| substitution | 2 | different architecture, and same architecture/different training |
| parameter tamper | 2 | one layer, small and large magnitude |
| BadNets patch backdoor | 4 | trigger size × position × poison rate |
| Blended low-opacity backdoor | 2 | **outside** the patch family our probe sweeps — expected to degrade |

The backbone is a small CNN trained on the Module 1 synthetic corpus at 32×32,
6 classes — seconds per model on CPU, no pretrained weights, no downloads.

---

## 11. Known gap carried forward, stated rather than hidden

Module 1's ADR-008 deferred **data-side** `trigger_injection` detection (finding
patch artifacts in *training images*) to Module 2, on the grounds that doing it
without the model-side counterpart would be a partial capability presented as a
complete one. Module 2 delivers the model side in full. It does **not** add the
data-side image detector: that is dataset forensics, not model forensics, and
adding it under a model-forensics brief would be scope drift.

`trigger_injection` therefore remains `NOT_ASSESSED` in the coverage statement,
with its reason updated to say precisely this and to name the model-side classes
that *are* assessed. It is listed as an open item, not quietly dropped.

---

## 12. Reproducibility requirements

Every model assessment inherits Module 1's `RunContext` and records:

```
run_id · seed · config_hash · model file/graph/parameter digests
reference model digests · battery digest · battery version
detector versions · adapter versions · runtime versions (onnx, onnxruntime, torch)
python/numpy/platform · timestamps · timings
```

Volatile fields (`observed_at`, `started_at`, `finished_at`, `duration_ms`,
`timings_ms`) are excluded from the report's stable digest by the existing
`DIGEST_EXCLUDED_FIELDS` mechanism. Two runs of the same assessment on the same
machine — and in a separate process — must produce the same `report_id`.

Determinism hazards specific to Module 2, and how each is handled:

| Hazard | Handling |
|---|---|
| ONNX Runtime thread count affecting float reduction order | session pinned to 1 intra-op / 1 inter-op thread |
| Torch thread count and non-deterministic kernels | `torch.set_num_threads(1)`, `torch.use_deterministic_algorithms` where supported, inference under `no_grad` |
| Float text formatting in digests | all floats pass through `digest_safe`/`quantize` (ADR-004) before hashing — never formatted into a digest |
| Trigger-search optimiser randomness | initialised from `RunContext.rng("trigger")`, never global RNG |
| Non-determinism in model *training* for the lab | every trainer seeded from `_model_seed(seed, scenario, index)` via SHA-256, never Python's salted `hash()` (the Module 1 bug this rule came from) |

---

## 13. Offline guarantee

`onnx`, `onnxruntime` and `torch` become **optional extras**, never hard
dependencies, and are absent-tolerant exactly like Module 1's optional CNN
backend: missing package → `DetectorUnavailable` with a precise reason →
`NOT_ASSESSED` in the report.

No component may download weights, benchmark data or anything else. Enforced by
a test that (a) patches `socket.socket` to raise and runs a full model
assessment, and (b) asserts by source inspection that no `cvtrust` module
imports `urllib`, `requests`, `http.client` or calls `torch.hub` /
`torchvision.models(weights=...)`.

TrojAI / BackdoorBench artifacts are supported only through a **local** ingest
directory. If it is absent: `NOT_ASSESSED`, reason `"required local artifact
unavailable"`. Never fetched.

---

## 14. Completion criteria

Module 2 is complete when every item in §36 of the brief holds *and*:

- `pytest` is green for the whole repository, Module 1 included.
- The offline test passes.
- Cross-process determinism of a model assessment is demonstrated.
- Every coverage claim in `docs/model-security.md` is backed by a measurement
  in the evaluation output, not by intent.
