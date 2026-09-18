# cvtrust — Trustworthy Computer Vision Integrity Assurance

**SIH 2026 · Problem Statement SIH26228** — Trustworthy Computer Vision
Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor
Pipelines
**Organisation:** Ministry of Defence · Indian Army (DGIS) · **Theme:**
Blockchain & Cybersecurity · **Category:** Software

An offline, air-gapped assurance layer for computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted.

> **Build status: Modules 1 and 2 of 5 complete** — foundation and dataset
> forensics (M1), model forensics and backdoor assurance (M2). Inference
> provenance (M3), evidence fusion (M4) and the analyst web platform (M5) are
> **not** implemented, and every report declares them `NOT_ASSESSED` rather than
> silently omitting them. Run `cvtrust info` to see exactly what this build
> assesses.
>
> **A model assurance report never states that a model is safe.** The strongest
> positive statement available is `NO_ANOMALY_DETECTED` — a statement about the
> tests that ran, under a recorded access mode and probe battery. That is
> enforced by a test, not by review.

---

## The idea in one paragraph

Most "AI security dashboards" produce a risk score. A score is not evidence. This
system is built the other way round: it starts from the **observation** (this
file's SHA-256 equals that one's; these ten neighbours carry a different label;
this contributor's flag rate is 14% against a cohort's 0%, p = 5e-77), attaches a
**confidence with a declared basis**, states the **severity** separately, names
the **affected asset and contributor**, recommends a **disposition** by an
explicit published rule, and then says which attack classes it **did not test
for**. A finding that cannot show its working cannot be represented in the
schema — `EvidenceItem.observation` is a required, non-empty mapping.

## Quick start

```bash
./scripts/setup.sh      # the only step that needs a network
./scripts/demo.sh       # the whole story, end to end, ~15 s
```

The demo generates a clean corpus from a published seed, establishes a
cryptographic baseline, measures its own false-alarm rate on clean data, builds a
four-contributor attack, detects it with evidence, scores itself against ground
truth, tampers with the dataset after the baseline, catches that, and finishes by
printing what it does not claim.

```bash
./scripts/evaluate.sh   # generate all 6 dataset scenarios, measure every detector
./.venv/bin/pytest      # 321 tests, ~2 min 45 s
./.venv/bin/cvtrust info
```

Module 2, end to end:

```bash
cvtrust lab model-build --out model_lab       # trains 1 reference + 15 scenarios, ~40 s
cvtrust lab model-evaluate model_lab          # measures every model detector
cvtrust model assess model_lab/backdoor_badnets/model.onnx \
    --reference model_lab/_reference/reference.onnx
```

## What it detects today

| Threat (PS §2.1) | Coverage | Method | P | R | FPR (clean) |
|---|---|---|---|---|---|
| Exact duplicate flooding | **SUPPORTED** | SHA-256 over bytes *and* over decoded pixels | 1.000 | 1.000 | 0.0000 |
| Near-duplicate flooding | **SUPPORTED** | pHash clustering + independent feature-space confirmation | 1.000 | 1.000 | 0.0000 |
| Label flipping | PARTIAL | distance-weighted k-NN disagreement + class-centroid margin | 1.000 | 0.950 | 0.0000 |
| Systematic mislabelling | **SUPPORTED** | directional concentration, binomial test vs leave-one-out cohort, BH-corrected | 1.000 | 1.000¹ | 0.0000 |
| Out-of-distribution insertion | PARTIAL | Mahalanobis + k-NN + PCA residual vs declared reference | 0.889 | 1.000 | 0.0089 |
| Malformed / contradictory metadata | **SUPPORTED** | schema, dimension, bbox, category and identifier validation | deterministic | | |
| Post-baseline dataset tampering | **SUPPORTED** | manifest re-verification (`dataset verify`) | deterministic | | |
| Backdoor trigger injection (**data side**) | `NOT_ASSESSED` | open item — see ADR-011 | | | |
| Inference tampering / replay / reordering | `NOT_ASSESSED` | Module 3 | | | |
| Population distribution shift | `NOT_ASSESSED` | Module 4 | | | |

### Module 2 — models

Measured over **15 model artifacts** (small CNNs trained from published seeds;
the unit of evaluation is the *model*, so every rate rests on few observations):

| Threat (PS §2.2) | Coverage | Method | P | R | FPR |
|---|---|---|---|---|---|
| Model substitution | **SUPPORTED** | SHA-256 over content, three digests (artifact / architecture / weights) | 15/15 correct against the fact asserted | | |
| Re-serialisation vs substitution | **SUPPORTED** | graph digest + parameter digest disagreement pattern | deterministic | | |
| Structural modification | **SUPPORTED** | weight-blind graph fingerprint, then per-layer diff | deterministic | | |
| Parameter modification | **SUPPORTED** | per-tensor digest + relative L2, localised to named tensors | deterministic | | |
| Behavioural deviation | **SUPPORTED** | prediction agreement · Jensen–Shannon · confidence shift · metamorphic consistency | | | |
| Backdoor, declared patch family | PARTIAL | gradient-free family sweep; targeted-transition concentration | **1.000** | **0.833** | **0.000** |
| Trigger reconstruction | PARTIAL | Neural Cleanse with the paper's dynamic λ schedule | ranking correct on 6/6; **index uninterpretable below 8 classes** | | |
| Activation-based detection | PARTIAL (context) | spectral signatures + activation clustering | **measured non-discriminating — demoted** | | |
| Sample-specific / semantic / adaptive backdoors | `NOT_SUPPORTED` | declared, tested, reported as a miss | | | |

Backdoor score separation: non-backdoor models 0.000–0.333, detected backdoors
0.667–0.833, threshold 0.50 — a genuinely empty region on both sides.

**The one miss is the one the lab predicted.** `backdoor_blended_faint` is a
blended trigger at opacity 0.08, deliberately built to sit *outside* the
full-opacity family the probe sweeps; its ground truth says in advance that the
probe is expected to miss it. It is a real, fully effective backdoor (true
attack success rate 1.000) that this method does not test for. That is a
coverage boundary being measured rather than asserted — which is worth more than
a recall of 1.000 would have been.

Full numbers, including the two methods that **did not work** and why, in
[`docs/model-security.md`](docs/model-security.md).

¹ contributor-level, which is the claim this detector makes; sample-level
attribution is a screening signal at R ≈ 0.75.

**On clean data: 336 samples, 4 findings, 0.89% of samples flagged, zero
HIGH/CRITICAL, zero QUARANTINE.** An assurance tool that cries wolf is worse than
no tool, so this is measured and asserted by tests.

All metrics were measured on synthetic corpora under published seeds — see
`docs/attack-matrix.md` and `docs/model-security.md` §5 for the evaluation
populations, and `docs/limitations.md` for what that does and does not imply.

### Two methods that did not work, reported rather than hidden

Spectral signatures and activation clustering, applied to a probe battery rather
than the training set they were published for, produced a backdoored
trigger-coincidence range of 0.00–1.15 against a *clean* range of 0.00–1.64 —
the backdoored range sits **inside** the clean one, and the highest lift of any
model in the lab belongs to a clean model. An earlier revision thresholded that
statistic and fired backwards. It is now demoted to context-only, with the
measurement published as its coverage reason.

Neural Cleanse locates the right class on every backdoored model (smallest
reconstructed mask, by 5–50×), but at six classes a *clean* model produced a
mask as small (L1 6.8 at success 1.00, against the backdoored model's 5.9 at
1.00). Its anomaly index is therefore declared uninterpretable below eight
classes rather than reported as a verdict.

This is ADR-013: a measurement that contradicts a design is more valuable than
the design, and hiding it would make every other number here unbelievable.

## What a finding looks like

```
╭─ F-651cb22b2061  Contributor 'charlie' systematically labels 'vehicle' ──────╮
│                  content as 'building' (9 of 72 units)                       │
│ Asset          contributor:charlie                                           │
│ Assessment     MEDIUM · confidence 0.99 (hypothesis test) · coverage SUPPORTED│
│ Method         systematic_mislabel v1.0                                      │
│                                                                              │
│ Evidence                                                                     │
│ • 9 of this contributor's 72 analysed units (12.5%) carry the declared label  │
│   'building' while their neighbourhood suggests 'vehicle'. Across the rest of │
│   the cohort the same directional pair occurs in 0 of 252 units (0.00%).      │
│     observation: contributor_pair_count, contributor_units, contributor_rate, │
│                  cohort_pair_count, cohort_units, cohort_rate, rate_ratio,    │
│                  baseline                                                    │
│ • One-sided binomial test of H0: rate <= 0.0000 gives p = 8.511e-44; after    │
│   Benjamini-Hochberg correction over 1 tests, q = 8.511e-44 (alpha = 0.01).   │
│     observation: successes, trials, null_rate, p_value, q_value, alpha,       │
│                  n_tests, correction                                         │
│ • 9 units follow one directional mapping at an unbounded multiple of the      │
│   cohort rate (the rest of the cohort had none)                              │
│     observation: affected_units, rate_ratio, contributor_rate                │
│                                                                              │
│ Limitations                                                                  │
│ ! inherits the label-consistency detector's feature-space dependence: if the  │
│   suggested labels are wrong, the directional structure tested here is wrong  │
│ ! a mapping applied uniformly by every contributor has no cohort baseline to  │
│   stand out against and is not detectable by this test                       │
│ ! statistical significance is evidence of a non-random pattern, not proof of  │
│   intent; an unfamiliar annotation guideline produces the same signature      │
│                                                                              │
│ Recommended disposition: REVIEW   [rule D-200-actionable]                    │
╰────────────────────────────────── systematic_mislabel ───────────────────────╯
```

Real output from `attack_lab/systematic_mislabel`, reproducible with
`./scripts/evaluate.sh`.

Note what is present: the arithmetic, the baseline it was compared against, the
multiple-testing correction, the limitations, and the ID of the policy rule that
chose the disposition. Note what is absent: any number an analyst cannot check.

## How confidence is produced

There are exactly four legal bases, enforced by the schema's validators rather
than by code review:

| Basis | Meaning | Value |
|---|---|---|
| `DETERMINISTIC` | A verified fact — SHA-256 equality, a box outside the image | exactly 1.0 |
| `STATISTICAL` | A hypothesis test | `1 − q` (BH-adjusted), capped at 0.99 |
| `CALIBRATED` | A threshold whose precision was **measured** on attack-lab scenarios | Wilson 95% **lower bound** of measured precision |
| `HEURISTIC_UNCALIBRATED` | No measurement exists for this detector version | documented prior, capped at **0.60**, and the finding *must* carry the `uncalibrated` limitation |

Consequence, by design: **with no calibration table loaded, no threshold-based
finding can recommend quarantine.** Policy rule
`D-110-severe-but-uncalibrated` downgrades it to `REVIEW`, because quarantine
should require measured evidence quality.

## Architecture

```
DATASET (untrusted)
   ├─ DatasetAdapter          coco | yolo | folder — registry, not hard-coded
   ├─ ContributorResolver     sidecar > adapter-native > path-pattern > unknown
   ├─ FeatureStore            one decode per image → facts + pHashes + 614-d embedding
   ├─ DatasetManifest ──────► digest = DATASET IDENTITY (Modules 2–5 bind here)
   ├─ Detector[]              fixed order — a real dependency chain, see below
   ├─ ContributorAggregator   rate vs leave-one-out cohort, binomial + BH
   ├─ DispositionPolicy       published rule table → ACCEPT | REVIEW | QUARANTINE
   ├─ CoverageStatement       every known attack class, including Modules 3–5
   └─ AssuranceReport         JSON + console/Markdown + reproducibility context

MODEL ARTIFACT (untrusted)
   ├─ ModelAdapter            onnx | torchscript | torch — registry, not hard-coded
   ├─ Capability set          inference · graph · parameters · activations · gradients
   ├─ ModelManifest ────────► file_sha256   = ARTIFACT identity
   │                          graph_digest  = ARCHITECTURE identity (weight-blind)
   │                          parameter_digest = WEIGHT identity (container-blind)
   ├─ ReferenceBattery        versioned + digested: clean · borderline · perturbation
   │                          · OOD · declared trigger family
   ├─ ModelDetector[]         identity → structure → parameters → behaviour
   │                          → activation → trigger   (fixed dependency chain)
   ├─ AssessmentMatrix        six levels, NEVER combined into one score (ADR-012)
   └─ ModelAssuranceReport    the SAME Finding schema, policy and coverage statement
```

The detectors are not five independent demos. `near_duplicate` publishes the
duplicate groups that `label_consistency` **excludes from its neighbourhoods** —
without which an adversary flips one label, floods near-copies carrying the same
wrong label, and the neighbourhood agrees with itself. `ood` publishes the
out-of-distribution set that `label_consistency` uses to **qualify its own
evidence**. `label_consistency` publishes the suggestions that
`systematic_mislabel` tests for directional structure. That is why the order is
fixed in code and not configurable.

## On blockchain — the honest answer

The problem statement's theme is Blockchain & Cybersecurity, and the
architectural conclusion is that **a distributed ledger solves a problem this
deployment does not have** (ADR-009).

A ledger buys Byzantine agreement among mutually distrusting writers. The target
deployment is a single air-gapped analyst authority: one writer, no consensus
requirement, no network to gossip blocks over. Adding consensus would add nodes,
key distribution and a synchronisation requirement that *directly contradicts
the air gap*.

What is actually required is tamper-evidence and non-repudiation, and those are
obtained without a ledger — this is the TUF/in-toto model of signed metadata
about artifacts:

| Requirement | Mechanism |
|---|---|
| Artifact identity | SHA-256 over bytes, and separately over decoded content |
| Dataset identity | Manifest digest over canonical, float-free serialisation |
| Detect post-hoc modification | Re-derive and compare digests (`dataset verify`) |
| Non-repudiation | Ed25519 detached signature over the digest (Module 3) |
| Detect removal / reordering | Hash chain with sequence numbers (Module 3) |
| Inclusion proofs at volume | Merkle tree over the chain (Module 3, if justified) |
| Detect replay | Nonce + monotonic sequence + signed timestamp (Module 3) |

The manifest format is already signature-ready; Module 3 attaches a signature
without a schema change. Full reasoning in `docs/architecture.md` §ADR-009.

## Offline by construction

No network at runtime, no cloud inference, no external API, no OpenAI or
Anthropic dependency, no remote database, no cloud authentication, no telemetry,
and **no pretrained weight downloads** — the default 614-dimensional feature
space is a deterministic classical descriptor precisely so that the tool needs
no artifact whose own provenance it would then have to assure. Installation
needs a package index; nothing after that does. A CNN backend exists behind the
same interface for deployments that vendor weights locally, records the weight
file's SHA-256 in the report, and refuses with a clear message rather than
fetching anything.

Module 2 holds the same line. Its models are trained from seeds rather than
downloaded, and NIST TrojAI / BackdoorBench artifacts are read **only** from a
locally vendored directory — absent means `NOT_ASSESSED` with the reason
`"required local artifact unavailable"`, never a fetch. The guarantee is tested
two ways: dynamically, by amputating `socket` and running full dataset and model
assessments through it; and statically, by asserting the shipped source contains
no network imports, no URL literals, and no call to `torch.hub`,
`from_pretrained` or `torchvision.models(weights=...)`. See
`tests/security/test_offline.py` and `docs/deployment.md`.

## Reproducibility

Every run records a `RunContext` whose `run_id` is
`sha256(config ‖ dataset_digest ‖ seed)` — derived from the inputs, not
generated randomly. Two runs over the same dataset produce the same `run_id`,
the same `report_id`, the same finding IDs and the same confidences on any
machine. A structural diff of two reports may differ only in fields named in
`DIGEST_EXCLUDED_FIELDS` (timings, and the dataset's path — because a dataset's
identity is its content digest, not its location). Corpus generation and every
attack are pure functions of their seeds, asserted across separate processes.

Finding IDs are content-addressed, and deliberately exclude score and severity,
so recalibrating a detector **updates** a finding rather than creating a new one.

## Commands

```bash
cvtrust info                                       # coverage statement for this build
cvtrust dataset scan   <root> [--reference F] [--calibration F] [--out F]
cvtrust dataset manifest <root> --out baseline.json
cvtrust dataset verify baseline.json <root>        # post-baseline tamper check
cvtrust lab generate   --out attack_lab/_clean --per-class 14
cvtrust lab attack     <clean-root> <out> --scenario combined
cvtrust lab evaluate   attack_lab --calibration-out reports/calibration.json

cvtrust model manifest <model.onnx> --out model-baseline.json
cvtrust model verify   model-baseline.json <model.onnx>   # post-assurance change
cvtrust model assess   <model.onnx> --reference <trusted.onnx> [--black-box]
                                    [--calibration F] [--out F] [--markdown-out F]
cvtrust lab model-build    --out model_lab
cvtrust lab model-evaluate model_lab
cvtrust demo
```

`model assess` takes `--black-box` to *genuinely* drop graph, parameter,
activation and gradient access before analysis, so the white-box methods take
their real unavailable path and the report says what black-box coverage actually
is. It is not a simulation.

`dataset scan` and `model assess` exit codes compose: `0` clean · `1` review ·
`2` explained error · `3` quarantine or verification failure.

## Documentation

| | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Data flow, interfaces, and all thirteen architecture decision records |
| [`docs/threat-model.md`](docs/threat-model.md) | Trust boundary, adversary capabilities, per-threat residual risk, attacks on the detectors themselves |
| [`docs/research.md`](docs/research.md) | Method cards with assumptions and access requirements, methods **rejected** with reasons, and the eleven defects the evaluation harnesses caught |
| [`docs/model-security.md`](docs/model-security.md) | **Module 2.** Coverage matrix, access modes, measured results, the two methods that did not work, benchmark vendoring |
| [`docs/coverage.md`](docs/coverage.md) | What is assessed, what is not, and what `SUPPORTED` does not mean |
| [`docs/attack-matrix.md`](docs/attack-matrix.md) | Every scenario, every measured metric, with evaluation populations |
| [`docs/limitations.md`](docs/limitations.md) | The complete list, per detector |
| [`docs/security.md`](docs/security.md) | Cryptographic policy, input handling, conservative-by-default decisions |
| [`docs/testing.md`](docs/testing.md) | Test layers, including the tests that assert a limitation is still true |
| [`docs/deployment.md`](docs/deployment.md) | Air-gapped install, wheelhouse, everyday use |
| [`docs/module-1-plan.md`](docs/module-1-plan.md) | The design Module 1 was built to |
| [`docs/module-2-plan.md`](docs/module-2-plan.md) | The design Module 2 was built to |

## Stack

Python 3.11+ · NumPy · SciPy · scikit-learn · Pillow · Pydantic v2 · Typer ·
Rich · `cryptography` (Ed25519, for Module 3 — the manifest format is
signature-ready now) · pytest.

**Optional extras for Module 2:** `onnx` + `onnxruntime` (ONNX support) and
`torch` (TorchScript, the gradient pathway, and the model attack lab's trainer).
Both are genuinely optional: an absent runtime makes that format unavailable and
the pipeline reports `NOT_ASSESSED` with a reason naming the missing package. It
never becomes a crash and never becomes a silent pass.

No GPU, no services, no database. Model assessment runs on CPU in ~120 ms.
