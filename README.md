# cvtrust — Trustworthy Computer Vision Integrity Assurance

**SIH 2026 · Problem Statement SIH26228** — Trustworthy Computer Vision
Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor
Pipelines
**Organisation:** Ministry of Defence · Indian Army (DGIS) · **Theme:**
Blockchain & Cybersecurity · **Category:** Software

An offline, air-gapped assurance layer for computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted.

> **Build status: all five modules complete** — foundation and dataset
> forensics (M1), model forensics and backdoor assurance (M2), inference
> provenance and cryptographic integrity (M3), distribution shift and evidence
> fusion (M4), and the analyst platform in `web/` (M5), which computes nothing
> of its own. Every report declares what it did not assess rather than silently
> omitting it. Run `cvtrust info` to see exactly what this build assesses.
>
> **There is no trust score.** Module 4 combines evidence from all four scopes
> by an explicit, versioned table of 23 rules — printed in full in every report
> — and never by arithmetic. An analyst who disagrees with a disposition can
> name the rule. `ACCEPT` requires **all four scopes to have been assessed**: a
> scope nobody looked at is `NOT_ASSESSED`, which outranks `ACCEPT`, so
> withholding a report can never be read as a clean result (ADR-016, ADR-019).
>
> **A distribution shift is never an attack.** Terrain, season, sensor and
> illumination changes are the normal condition of a reconnaissance pipeline and
> produce the same signature as manipulation. No rule escalates on shift alone
> (ADR-018).
>
> **A model assurance report never states that a model is safe.** The strongest
> positive statement available is `NO_ANOMALY_DETECTED` — a statement about the
> tests that ran, under a recorded access mode and probe battery. That is
> enforced by a test, not by review.
>
> **A provenance report never states that an inference was correct.**
> `PROVENANCE VERIFIED` is a statement about the integrity of the *records* and
> about the checks that actually ran. A cryptographically perfect chain over a
> backdoored model is entirely possible — and the system keeps that fact and the
> model's own assessment alive independently, never combining them into one
> number (ADR-014).

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
git clone <repo-url> && cd cv-trust
./setup.sh      # once: installs everything and builds the demo data
./run.sh        # the complete demo -> http://localhost:3000
```

Two commands, and there is nothing else to start.

`./setup.sh` is the whole setup. From a fresh clone it checks the
prerequisites, creates `.venv` and installs the engine, creates the working
directories and local configuration that Git deliberately does not carry,
installs the analyst platform's dependencies, builds the four attack labs,
exports the analyst feed the frontend reads, and smoke-tests the result. The
first run takes about five minutes, most of it generating labs; running it
again skips whatever is already in place and takes seconds. It never
overwrites configuration you have edited.

**Prerequisites:** Python **3.11+**, and Node **20.9+** for the analyst
platform. Nothing else — no database, no services, no GPU, and **no secrets,
API keys or accounts anywhere in this project**. `./setup.sh` is the only step
that needs a network; runtime never touches one.

Then run the demo:

```bash
./run.sh
```

`./run.sh` is the canonical launcher and the only command a judge needs. It
checks that `./setup.sh` has been run, verifies the engine's output is on disk
(and builds it if it is not), builds the analyst platform if the sources have
changed since the last build, serves it, and waits until the dashboard actually
answers before printing **DEMO READY** with every URL. Ctrl+C stops it and
takes the server down with it.

**There is exactly one long-lived process.** Modules 1–4 are a library and a
CLI, not a service: the engine *runs once*, writes JSON reports to
`reports/analyst/`, and is then finished. Module 5 — the Next.js application in
`web/` — reads those files from disk. So there is no API server, no database,
no queue, no worker and no reverse proxy to start, and nothing listening except
the platform itself on port 3000.

| | |
|---|---|
| `./run.sh` | the demo: the production build, served on http://localhost:3000 |
| `./run.sh --port 3010` | serve somewhere else (or `PORT=3010 ./run.sh`) |
| `./run.sh --dev` | frontend in development mode, with hot reload |
| `./run.sh --refresh-feed` | re-run the real Module 1–4 pipelines and rewrite `reports/analyst` first |
| `./run.sh --rebuild` | rebuild the frontend even if the current build looks current |
| `./run.sh --prepare-only` | build the labs, the feed and the frontend, then exit without serving |
| `./run.sh --open` | open the dashboard in a browser once it is ready |

**To stop the demo: press Ctrl+C.** The launcher stops the server, its worker
processes and nothing else; it leaves no orphan holding port 3000, and running
`./run.sh` again afterwards is a clean start. If a platform is *already*
serving on the port, `./run.sh` says so and reuses it rather than starting a
second copy.

The engine also demonstrates itself in the terminal, with no frontend involved:

```bash
./scripts/demo.sh                     # the whole story, end to end, ~15 s
```

That demo generates a clean corpus from a published seed, establishes a
cryptographic baseline, measures its own false-alarm rate on clean data, builds a
four-contributor attack, detects it with evidence, scores itself against ground
truth, tampers with the dataset after the baseline, catches that, and finishes by
printing what it does not claim.

### Setup options

| | |
|---|---|
| `./setup.sh` | everything below, in order. The normal path. |
| `./setup.sh --skip-web` | Python engine only; do not touch Node or `web/` |
| `./setup.sh --skip-model-lab` | skip Module 2's model training (~70 s). 17 of the 19 analyst scenarios then export as `NOT_RUN` **with the reason** — the engine reporting missing evidence rather than inventing it. |
| `./setup.sh --skip-feed` | no labs, no analyst feed. The frontend will say it has no data. |
| `./setup.sh --force` | recreate `.venv`, reinstall the frontend's dependencies, rebuild the labs and the feed |
| `./setup.sh --wheelhouse DIR` | install from pre-downloaded wheels with no package index — see [docs/deployment.md](docs/deployment.md) |
| `PYTHON=/path/to/python3.13 ./setup.sh` | build `.venv` with a specific interpreter |

`scripts/setup.sh` still works: it forwards to `./setup.sh`.

### What setup generates locally, and why none of it is in Git

Everything here is either reproducible from a published seed, operational key
material, or too large to carry in version control. A fresh clone does not have
it, and `./setup.sh` creates it.

| Path | What it is |
|---|---|
| `.venv/` | the Python environment |
| `attack_lab/` `model_lab/` `provenance_lab/` | generated corpora, trained models, signed logs and **test-only private keys** — pure functions of their seeds |
| `assurance_lab/_scenarios/` | per-run scratch for the fusion scenarios (the lab itself *is* in Git) |
| `reports/` | every report the engine writes |
| `reports/analyst/` | the analyst feed, rebuilt from the engine by `cvtrust analyst export` |
| `reports/live/` | left empty: an operator fills it with a real assessment ([docs/deployment.md](docs/deployment.md)) |
| `keys/` | mode 700. Operational Ed25519 signing keys, if you create any. Never committed. |
| `web/node_modules/` | installed by `npm ci` from the committed `web/package-lock.json`. About 550 MB, carried across the air gap with the repository rather than committed |
| `web/.env` | local frontend environment, copied from `web/.env.example` and never overwritten |

### One-time manual configuration

**There is none, and there are no secrets.** The system has no cloud, no
external API, no account and no token; the frontend reads JSON from disk. The
only local configuration file is `web/.env`, which `./setup.sh` writes from the
checked-in `web/.env.example`. Edit it only to point the platform at a feed
outside this repository (`CVTRUST_DEMO_DIR`, `CVTRUST_LIVE_DIR`).

Two things are genuinely optional and are *not* automated:

- **Publishing a live assessment.** `reports/live/` stays empty until an
  operator puts a real assessment there. Demo and live data are never blended,
  and asking for live data never silently returns demo data. See
  [docs/deployment.md](docs/deployment.md) § Publishing a live assessment.
- **The visual-fidelity check.** `scripts/module5_visual_check.py` diffs the
  frontend against the supplied design reference, which is not part of this
  repository. Point `CVTRUST_DESIGN_REFERENCE` at it if you have it; the
  matching tests skip themselves when it is absent.

### Everyday commands

```bash
./scripts/demo.sh       # end-to-end demonstration, ~15 s
./scripts/evaluate.sh   # generate all 6 dataset scenarios, measure every detector
./.venv/bin/pytest      # 811 tests, ~5 min
./.venv/bin/cvtrust info
```

Module 2, end to end:

```bash
cvtrust lab model-build --out model_lab       # trains 1 reference + 15 scenarios, ~40 s
cvtrust lab model-evaluate model_lab          # measures every model detector
cvtrust model assess model_lab/backdoor_badnets/model.onnx \
    --reference model_lab/_reference/reference.onnx
```

Module 3, end to end — **needs no model runtime**, because it binds Module 2's
digests rather than recomputing them:

```bash
./scripts/provenance-evaluate.sh    # 28 scenarios, 3 reports, benchmark, ~10 s
```

That script builds the provenance attack lab, checks all 28 scenarios against
ground truth by exact set equality, then renders three reports that are worth
reading side by side: a clean log that **verifies**, the same log after an
adversary with their own signing key rewrote a bound model digest — which is
**COMPROMISED** despite every signature being valid — and a truncated log
verified *without* an anchor, which reports `NOT_DETECTABLE` rather than clean.

Module 4, end to end — **needs the other three labs** for the fusion scenarios,
and says so rather than faking them if they are absent:

```bash
./scripts/assurance-evaluate.sh     # 10 population pairs + 15 fusion scenarios, ~2 min
```

That script builds the population lab — **nine of its ten pairs contain no
attack at all**, because the failure this module can most easily commit is
calling a legitimate seasonal, terrain, sensor or illumination change an attack
— then fuses the real Module 1, 2 and 3 labs through nineteen end-to-end
scenarios. It finishes by rendering the two reports that make the design
argument: the same Module 1 findings assessed **with** and **without** the shift
context supplied. Identical evidence, a different governing rule, 41 of 42 items
marked confounded in one and none in the other, and the same conservative
disposition in both — which is itself a documented limit rather than a result
being understated.

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
| Population distribution shift | PARTIAL | Module 4 — permutation energy test vs a declared reference, movement attributed to feature views, checked against the declared operational context | — | — | **0 / 10 false shift alarms** |

### Module 4 — distribution shift and evidence fusion

Two labs, because there are two jobs. **Ten population pairs**, nine of which
contain no attack at all — the measurement is a *false-positive rate* on
legitimate operational changes, which is the failure this module can most easily
commit. **Nineteen end-to-end pipeline scenarios**, every one fusing findings
produced by the real Module 1, 2 and 3 pipelines; nothing is hand-written.

**10 / 10 shift verdicts match. 19 / 19 fusion dispositions match, firing
exactly the rules their specs name — zero missing, zero unexpected.**

| Situation | Verdict / disposition | Why it matters |
|---|---|---|
| Two clean draws from one process | `NO_SHIFT_DETECTED`, energy *p* = 0.954 | The headline false-positive measurement |
| Declared night collection / sensor swap / winter / desert | `SHIFT_CONSISTENT_WITH_DECLARED_CONTEXT` | Four legitimate operational changes, none escalated |
| The same change, undeclared | `SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT` → `REVIEW` | An open question, phrased as one — never "attack" |
| A sensor swap declared as an illumination change | `SHIFT_PARTIALLY_EXPLAINED`, residual named: `gradient` | The check has teeth |
| Six current samples against 192 | `INSUFFICIENT_SAMPLE` → `NOT_ASSESSED` | A refusal to answer, not a negative answer |
| Legitimate shift + independent signature failure | `QUARANTINE` from **provenance**; distribution stays `REVIEW` | The escalation is carried by the cryptography, not by the shift |
| Dataset anomaly during a legitimate shift | `REVIEW`, 20 of 24 items confounded | The documented cost: confounded evidence is not refuted, and not escalated |
| Three clean scopes, one report withheld | `NOT_ASSESSED` | Absence never reads as clean |
| 2,000 correlated findings from one family | No escalation; one real failure alongside still quarantines and is still cited | A family contributes at most one unit of independent support |

Measured cost (240 samples per side): shift characterisation 3.2 s (dominated by
feature extraction, not by the statistics), evidence normalisation 0.5 ms,
policy evaluation over 23 rules **0.18 ms and independent of population size**,
report construction 13 ms. At 10,000 fused findings the whole fusion layer costs
150 ms.

### Module 3 — inference provenance

Measured over **28 reproducible provenance scenarios**. Scoring here is *exact
set equality* between expected and observed failure codes, per record — not
precision and recall — because a signature verifies or it does not. An extra
failure fails a scenario as hard as a missed one. **28/28 reproduce exactly.**

| Threat (PS §2.1) | Coverage | Detected by |
|---|---|---|
| Record tampering — input, model, configuration or output | **SUPPORTED**¹ | Ed25519 over canonical bytes, record self-consistency, and the analyst's independent expectation |
| Model substitution behind a valid record | **SUPPORTED**¹ | The bound Module 2 digests vs the model actually held |
| Record deletion / insertion / reordering / duplication | **SUPPORTED** | Hash chain over `entry_digest` + contiguous sequence numbers |
| Signature stripping or substitution | **SUPPORTED** | The chained digest covers the envelope, not only the payload (ADR-015) |
| Unknown / revoked / expired / wrong-purpose signing key | **PARTIAL**² | The local offline trust store |
| Inference replay | **PARTIAL**³ | Local replay database: exact, nonce reuse, sequence collision |
| Log truncation | **PARTIAL**⁴ | Front: the genesis rule. Tail: **only** against an out-of-band anchor |

¹ Degrades to `PARTIAL` with no independent expectation supplied.
² `NOT_ASSESSED` with no trust store — every key is then `UNKNOWN`.
³ `NOT_ASSESSED` with no replay database, and always bounded by its retention.
⁴ `NOT_ASSESSED` with no anchor. **A tail-truncated chain is internally
perfect**, and the report says `NOT_DETECTABLE` rather than clean.

Measured cost, 200 records: signing 0.117 ms, full verification (27 checks)
0.492 ms, chain verification 8.8 ms, ~2.8 KB per record.

**The most instructive scenario in the lab** is `modified_model_digest`: an
adversary holding their own signing key rewrites the bound model digest and
re-signs. The signature verifies. The record is internally perfect. It is caught
only because the key is not in the trust store *and* the digest contradicts the
model the analyst assured — neither alone would have found it.

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

Module 3 sits entirely in the first row. Every provenance finding is
`DETERMINISTIC` at 1.0 — a signature verifies or it does not, and there is
nothing to calibrate in an equality test, so **no calibration table exists for
it and none will**. A test asserts that no provenance finding ever arrives with
any other basis, and the provenance report schema has no aggregate score field
of any kind (ADR-014). A second policy rule matters here too:
`D-000-not-assessed` downgrades a finding to `REVIEW` when the check that raised
it could not actually run — so a missing trust store cannot quarantine a
pipeline, and cannot be mistaken for a clean result either.

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

REFERENCE vs CURRENT POPULATION        M1 · M2 · M3 REPORTS (untrusted JSON)
   ├─ ShiftCharacterizer      energy (omnibus) + mean · covariance · PSI · JS
   │                          every metric: ASSESSED | INSUFFICIENT_SAMPLE
   │                                      | NOT_ASSESSED
   ├─ OperationalContext      a DECLARED claim, checked, never validated
   ├─ ShiftAssessment ──────► one of seven verdicts. Never a score. Never "attack"
   │                                   │
   ├─ NormalizedEvidence[]    findings carried VERBATIM; nothing is rewritten
   ├─ EvidenceGraph           families + confounding — a family contributes AT
   │                          MOST ONE unit of independent support (ADR-017)
   ├─ AssurancePolicyEngine   23 explicit versioned rules, printed in the report
   ├─ ScopeDecision × 4       dataset · model · provenance · distribution,
   │                          kept separate and never collapsed (ADR-014)
   └─ PipelineAssuranceReport strictest scope wins, with the scope NAMED.
                              NO aggregate score, and there will not be one
```

The detectors are not five independent demos. `near_duplicate` publishes the
duplicate groups that `label_consistency` **excludes from its neighbourhoods** —
without which an adversary flips one label, floods near-copies carrying the same
wrong label, and the neighbourhood agrees with itself. `ood` publishes the
out-of-distribution set that `label_consistency` uses to **qualify its own
evidence**. `label_consistency` publishes the suggestions that
`systematic_mislabel` tests for directional structure. That is why the order is
fixed in code and not configurable.

## The analyst platform

Modules 1 to 4 are the engine. Module 5 is the application an analyst uses, and
it computes nothing — every verdict, number and sentence it displays was
produced by the engine and written to a JSON report.

```bash
./run.sh                                       # both of the steps below, ready-checked
```

which is, underneath, nothing more than:

```bash
cvtrust analyst export --out reports/analyst   # run the real pipelines, write the feed
cd web && npm run build && npm start           # http://localhost:3000
```

Ten screens: the assurance dashboard, dataset, model, provenance, audit trail,
distribution shift, the evidence explorer, the decision, coverage, and the demo
scenario matrix. The evidence explorer is the one that matters most — it walks
a disposition back through the rule that produced it, the evidence that rule
rested on, the detector that observed it, and the detector's own raw
measurement, without summarising anything away on the journey.

**Demo and live data are never blended.** The demo source is real Module 1–4
output over the attack lab's nineteen scenarios; the live source is a directory
an operator fills with output from a real assessment. Which one is on screen is
stated in words on every page, and asking for live data never silently returns
demo data.

**There is still no score.** The UI introduces no trust score, no security
score and no gauge, because the architecture has none. Three separate checks
fail the build if one appears — in the exported reports, in the frontend's own
projections, and in every rendered page.

The frontend is built offline: fonts self-hosted, assets local, no analytics,
no external API, and no runtime dependency on any hosted origin.

```bash
./scripts/module5-verify.sh          # the end-to-end gate: engine → feed → UI
```

That script exports the feed from the real pipelines, runs the backend boundary
tests and the frontend projection tests, builds the application, serves it, then
fetches all ten screens for all nineteen scenarios and asserts that what each
page says matches what the engine's JSON says. 190 page renders, checked.

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
| Non-repudiation | Ed25519 detached signature over canonical bytes — **built** |
| Detect removal / reordering | Hash chain over payload **and** signature, plus sequence numbers — **built** |
| Detect replay | Nonce + sequence + a local observation database — **built** |
| Detect truncation | An out-of-band log anchor — **built**, and honestly scoped |
| Inclusion proofs at volume | A Merkle tree — **still not built, and still not needed** |

Module 3 built all of that and there is still no ledger. The Merkle tree is the
one item from this table that was listed as conditional and remains
unimplemented, on purpose: a tree buys efficient *inclusion proofs* — proving one
record is in a log without shipping the log — which matters when a verifier holds
a root and a prover holds the data. Here the analyst holds the whole log and
verifies 200 entries in 8.8 ms. Adding it would mean a second set of invariants
to get wrong in exchange for solving nobody's problem. The point to add it is
when membership must be proved to a party that does not hold the log.

Full reasoning in `docs/architecture.md` §ADR-009 and
`docs/cryptographic-model.md`.

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
`"required local artifact unavailable"`, never a fetch.

Module 3 is where this usually breaks, because signing systems accumulate
network dependencies: a key server, an OCSP responder, a CRL fetch, a remote
timestamp authority. There are **none**. Keys are generated locally, trust is a
local administrative record, and a timestamp is reported as the producer's claim
rather than as proof of time.

The guarantee is tested two ways. **Dynamically**, by amputating `socket` and
running through it a full dataset scan, a full model assessment, the TorchScript
gradient pathway, model training, and — for Module 3 — key generation, signing,
verification, chain verification, replay detection, revocation and a complete
build-and-evaluate of the 28-scenario provenance lab. **Statically**, by
asserting the shipped source contains no network imports, no URL literals, no
call to `torch.hub`, `from_pretrained` or `torchvision.models(weights=...)`, no
certificate/OCSP/CRL/key-server/RFC-3161 API anywhere under `provenance/`, and no
cryptography library other than `hashlib`, `secrets` and `cryptography`. See
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

cvtrust analyst export --out reports/analyst        # Module 5: build the analyst feed

cvtrust model manifest <model.onnx> --out model-baseline.json
cvtrust model verify   model-baseline.json <model.onnx>   # post-assurance change
cvtrust model assess   <model.onnx> --reference <trusted.onnx> [--black-box]
                                    [--calibration F] [--out F] [--markdown-out F]
cvtrust lab model-build    --out model_lab
cvtrust lab model-evaluate model_lab

cvtrust provenance keygen      --out keys/signer.pem --passphrase "$PASSPHRASE"
cvtrust provenance trust add   keys/signer.pub.json --store trust_store.json \
                               --provenance "hand-carried from the signing enclave"
cvtrust provenance trust list  --store trust_store.json
cvtrust provenance trust revoke <key_id> --store trust_store.json --reason "..."
cvtrust provenance record      <image> <output.json> --key keys/signer.pem \
                               --log provenance.jsonl --model-manifest model-baseline.json
cvtrust provenance anchor      provenance.jsonl --out /separate/media/anchor.json
cvtrust provenance verify-log  provenance.jsonl --store trust_store.json \
                               --anchor /separate/media/anchor.json --replay-db replay.json \
                               --model-manifest model-baseline.json [--out F] [--markdown-out F]
cvtrust provenance verify      <record.json> --store trust_store.json
cvtrust provenance benchmark   --records 200
cvtrust lab provenance-build    --out provenance_lab
cvtrust lab provenance-evaluate provenance_lab

cvtrust assurance shift  <current-root> --reference <reference-root> \
                         --declare "illumination=low,acquisition_mode=night" \
                         --reference-declare "illumination=daylight" \
                         --reference-provenance "2025 baseline collection, hand-carried" \
                         --out reports/shift.json
cvtrust assurance assess --dataset-report reports/dataset.json \
                         --model-report reports/model.json \
                         --provenance-report reports/provenance.json \
                         --shift reports/shift.json \
                         --out reports/assurance.json --markdown-out reports/assurance.md
cvtrust lab assurance-build    --out assurance_lab --per-class 8
cvtrust lab assurance-evaluate assurance_lab --dataset-lab attack_lab \
                         --model-lab model_lab --provenance-lab provenance_lab
cvtrust demo
```

`model assess` takes `--black-box` to *genuinely* drop graph, parameter,
activation and gradient access before analysis, so the white-box methods take
their real unavailable path and the report says what black-box coverage actually
is. It is not a simulation.

`provenance keygen` **refuses** to write an unencrypted private key without
`--allow-unencrypted`: an unencrypted operational signing key should be a
decision someone made, not a default they inherited. And `verify-log` without an
anchor reports tail truncation as `NOT_DETECTABLE`, never as clean — a truncated
chain is internally perfect, and no amount of verification can see past that.

`assurance shift` takes `--declare` as a **claim**, never as a fact. The
declaration is recorded, checked against where the movement actually landed, and
marked `declaration_validated: false` in the output — consistency between an
observed shift and a declared change is reported as consistency, never as
confirmation. `--reference-trust` defaults to `UNKNOWN` and is never inferred:
nothing in this system establishes that a reference population is clean.

`assurance assess` takes **every argument optionally**, and that is the design.
Every real deployment is missing something, and the only honest response to a
missing input is `NOT_ASSESSED` in that scope. Supplying nothing produces a
`NOT_ASSESSED` decision, never an `ACCEPT`.

`dataset scan`, `model assess`, `provenance verify-log` and `assurance assess`
exit codes compose: `0` clean/accept · `1` review · `2` explained error or
`NOT_ASSESSED` · `3` quarantine or verification failure.

## Documentation

| | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Data flow, interfaces, and all twenty architecture decision records |
| [`docs/threat-model.md`](docs/threat-model.md) | Trust boundary, adversary capabilities, per-threat residual risk, attacks on the detectors themselves |
| [`docs/research.md`](docs/research.md) | Method cards with assumptions and access requirements, methods **rejected** with reasons, and the twenty defects the evaluation harnesses caught |
| [`docs/model-security.md`](docs/model-security.md) | **Module 2.** Coverage matrix, access modes, measured results, the two methods that did not work, benchmark vendoring |
| [`docs/provenance.md`](docs/provenance.md) | **Module 3.** The record schema, canonicalisation, verification evidence, the failure taxonomy, replay and chain models, the attack lab, measured performance, and what the module does not establish |
| [`docs/cryptographic-model.md`](docs/cryptographic-model.md) | **Module 3.** Primitives and why each, what a signature does and does not establish, the host-trust assumption stated plainly, and the threats cryptography does not address |
| [`docs/coverage.md`](docs/coverage.md) | What is assessed, what is not, and what `SUPPORTED` does not mean |
| [`docs/attack-matrix.md`](docs/attack-matrix.md) | Every scenario, every measured metric, with evaluation populations |
| [`docs/limitations.md`](docs/limitations.md) | The complete list, per detector |
| [`docs/security.md`](docs/security.md) | Cryptographic policy, input handling, conservative-by-default decisions |
| [`docs/testing.md`](docs/testing.md) | Test layers, including the tests that assert a limitation is still true |
| [`docs/deployment.md`](docs/deployment.md) | Air-gapped install, wheelhouse, everyday use |
| [`docs/module-1-plan.md`](docs/module-1-plan.md) | The design Module 1 was built to |
| [`docs/module-2-plan.md`](docs/module-2-plan.md) | The design Module 2 was built to |
| [`docs/module-3-plan.md`](docs/module-3-plan.md) | The design Module 3 was built to, and the nine defects the provenance lab caught |
| [`docs/module-4-plan.md`](docs/module-4-plan.md) | **Module 4.** The design it was built to, the five shift methods and why those five, the fusion model, and the nine defects the assurance lab caught |
| [`docs/module-5-plan.md`](docs/module-5-plan.md) | **Module 5.** The analyst platform: the report boundary it consumes, the live/demo separation, the semantics the UI must preserve, and why there is still no score |

## Stack

Python 3.11+ · NumPy · SciPy · scikit-learn · Pillow · Pydantic v2 · Typer ·
Rich · `cryptography` (Ed25519, Module 3) · pytest.

The only cryptographic code in this repository is calls into `hashlib`,
`secrets` and `cryptography`. Nothing is invented, and a test asserts that no
other crypto library is imported anywhere under `provenance/`.

**Optional extras for Module 2:** `onnx` + `onnxruntime` (ONNX support) and
`torch` (TorchScript, the gradient pathway, and the model attack lab's trainer).
Both are genuinely optional: an absent runtime makes that format unavailable and
the pipeline reports `NOT_ASSESSED` with a reason naming the missing package. It
never becomes a crash and never becomes a silent pass.

No GPU, no services, no database. Model assessment runs on CPU in ~120 ms.
