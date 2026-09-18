# cvtrust — Trustworthy Computer Vision Integrity Assurance

**SIH 2026 · Problem Statement SIH26228** — Trustworthy Computer Vision
Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor
Pipelines
**Organisation:** Ministry of Defence · Indian Army (DGIS) · **Theme:**
Blockchain & Cybersecurity · **Category:** Software

An offline, air-gapped assurance layer for computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted.

> **Build status: Module 1 of 5 complete** — foundation and dataset forensics.
> Model forensics (M2), inference provenance (M3), evidence fusion (M4) and the
> analyst web platform (M5) are **not** implemented, and every report declares
> them `NOT_ASSESSED` rather than silently omitting them. Run `cvtrust info` to
> see exactly what this build assesses.

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
./scripts/evaluate.sh   # generate all 6 scenarios and measure every detector
./.venv/bin/pytest      # 182 tests, ~75 s
./.venv/bin/cvtrust info
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
| Backdoor trigger injection | `NOT_ASSESSED` | Module 2 | | | |
| Model substitution / tampering / backdoor | `NOT_ASSESSED` | Module 2 | | | |
| Inference tampering / replay / reordering | `NOT_ASSESSED` | Module 3 | | | |
| Population distribution shift | `NOT_ASSESSED` | Module 4 | | | |

¹ contributor-level, which is the claim this detector makes; sample-level
attribution is a screening signal at R ≈ 0.75.

**On clean data: 336 samples, 4 findings, 0.89% of samples flagged, zero
HIGH/CRITICAL, zero QUARANTINE.** An assurance tool that cries wolf is worse than
no tool, so this is measured and asserted by tests.

All metrics were measured on a synthetic corpus under published seeds — see
`docs/attack-matrix.md` for the evaluation population, and
`docs/limitations.md` for what that does and does not imply.

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
   ├─ CoverageStatement       every known attack class, including Modules 2–5
   └─ AssuranceReport         JSON + console/Markdown + reproducibility context
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
fetching anything. See `docs/deployment.md`.

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
cvtrust demo
```

`dataset scan` exit codes compose: `0` clean · `1` review · `2` explained error ·
`3` quarantine or verification failure.

## Documentation

| | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Data flow, interfaces, and all nine architecture decision records |
| [`docs/threat-model.md`](docs/threat-model.md) | Trust boundary, adversary capabilities, per-threat residual risk, attacks on the detectors themselves |
| [`docs/research.md`](docs/research.md) | Method cards with assumptions and access requirements, methods **rejected** with reasons, and the six bugs the evaluation harness caught |
| [`docs/coverage.md`](docs/coverage.md) | What is assessed, what is not, and what `SUPPORTED` does not mean |
| [`docs/attack-matrix.md`](docs/attack-matrix.md) | Every scenario, every measured metric, with evaluation populations |
| [`docs/limitations.md`](docs/limitations.md) | The complete list, per detector |
| [`docs/security.md`](docs/security.md) | Cryptographic policy, input handling, conservative-by-default decisions |
| [`docs/testing.md`](docs/testing.md) | Test layers, including the tests that assert a limitation is still true |
| [`docs/deployment.md`](docs/deployment.md) | Air-gapped install, wheelhouse, everyday use |
| [`docs/module-1-plan.md`](docs/module-1-plan.md) | The design this module was built to |

## Stack

Python 3.11+ · NumPy · SciPy · scikit-learn · Pillow · Pydantic v2 · Typer ·
Rich · `cryptography` (Ed25519, for Module 3 — the manifest format is
signature-ready now) · pytest. No GPU, no services, no database.
