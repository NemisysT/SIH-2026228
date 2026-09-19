# Module 4 — the design this was built to

Recorded after the fact, as Modules 1–3 were, so that a reviewer can see what
was intended, what changed under measurement, and why.

## 1. Objective

Two jobs, joined by one constraint.

**Characterise population-level distribution shift** between a current
population and a declared reference, and say whether a declared operational
change accounts for it.

**Fuse the evidence** that Modules 1–4 have produced into one disposition an
analyst can act on.

**Without ever producing a score.** That constraint is the module's organising
principle and it is enforced structurally — by the absence of any aggregate
field in any schema, by two tests that walk the source looking for one, and by
the fact that every disposition is traceable to a named rule (ADR-016).

Module 4 computes **no forensics of its own** beyond the shift analysis. It
consumes the reports the other three modules already produced, verbatim.

## 2. Constraints taken as given

| Constraint | How it shaped the design |
|---|---|
| No trust score, no security score, no overall AI confidence | The fusion layer is a rule table, not a model. Corroboration is the only aggregation performed and it is bounded to one unit per phenomenon family |
| Evidence fusion ≠ score addition | No arithmetic crosses an evidence class. A `DETERMINISTIC` cryptographic fact and a `STATISTICAL` detector score are never averaged (ADR-014, ADR-020) |
| Five evidence classes stay distinct | `DATA_INTEGRITY`, `MODEL_INTEGRITY`, `PROVENANCE_INTEGRITY`, `DISTRIBUTION_SHIFT`, `OPERATIONAL_CONTEXT` are separate facts. Four scope dispositions, never collapsed |
| Findings are immutable inputs | Module 4 never rewrites, re-scores or re-dispositions a finding. `NormalizedEvidence` is a *view* alongside the original, and the original is carried into the report |
| Fully offline | Every null is a permutation null constructed at analysis time, so there is nothing to download and no calibration table to fetch. Five dynamic offline tests, one per Module 4 stage |
| Preserve Modules 1–3 | Same `Finding` schema, same `Coverage` vocabulary, same confidence bases, same `RunContext`, same canonical digest path. Every change made to Modules 1–3 was additive and backward-compatible |
| No blockchain | ADR-009, unchanged. Nothing here needs consensus |
| No Module 5 | No frontend, dashboard, chart or UI workflow. Module 4 ends at a JSON schema and a console/Markdown rendering Module 5 can consume |

## 3. What was planned, and built

- Population-level shift characterisation, distinct from Module 1's per-sample OOD ✔
- A **small**, justified set of shift methods — five, not fifteen ✔
- Explicit sample sufficiency: `ASSESSED` / `INSUFFICIENT_SAMPLE` / `NOT_ASSESSED` ✔
- Reference identity, digest, provenance, version, trust — never assumed clean ✔
- Declared operational context, checked and never validated ✔
- Operational drift distinguished from unexplained movement, **without** ever equating shift with attack ✔
- Evidence normalisation with lineage back to module, detector and version ✔
- Dependency-aware aggregation with a published family table ✔
- An explicit, versioned, inspectable, deterministic policy engine (23 rules) ✔
- Coverage-aware disposition — `NOT_ASSESSED` outranks `ACCEPT` ✔
- Conflicting evidence preserved, never reconciled ✔
- A complete machine-readable report that keeps the underlying findings ✔
- Ten population pairs, nine of them **not** attacks ✔
- Nineteen end-to-end pipeline scenarios over real upstream findings ✔
- Four of them legitimate-but-unusual conditions that must not read as compromise ✔
- 232 tests across unit, integration, security, adversarial and regression ✔

## 4. Why these five shift methods, and not more

The brief asked for a small set with clear justification, and the discipline was
real: a long list of detectors inflates apparent capability while making the
multiple-comparison problem worse and the report harder to read.

| Method | Role | Decisive? |
|---|---|:---:|
| Energy distance + permutation null | Omnibus two-sample test over the joint 614-d space | **yes — the only one** |
| Per-block mean displacement | Says *where* the movement is, enabling the context check | no (`significant` is `None` by construction) |
| Cross-fitted covariance log-det ratio | Catches spread/correlation changes the mean misses | no |
| Marginal PSI + permutation + BH | Names the *physical quantity* that moved | no |
| Jensen–Shannon + permutation | Class mix and declared metadata | no |

One test decides. Four localise. Full method cards — purpose, assumptions,
reference requirements, sample-size requirements, strengths, weaknesses, failure
modes, calibration, interpretation, implementation decision — are in
[`docs/research.md`](research.md) §24–29, together with the methods rejected
(MMD, per-coordinate KS, Wasserstein, learned drift detectors, KL) and why.

## 5. Why rule-based fusion and not weighted scoring

A calibrated probabilistic model would be the defensible version of a score. It
needs three things this project does not have: a prior over attack-class
incidence in multi-contributor pipelines, per-detector error rates measured on
operational data, and an independence structure. The project's own method cards
say so — §14 and §15 record two Module 2 detectors measured non-discriminating,
and the `HEURISTIC_UNCALIBRATED` basis exists precisely because several
detectors have no measured error rate.

Without those three, weights are numbers chosen to make a demo look right,
stated with a precision they do not have, and — worst of all — unarguable.

The cost is accepted and stated: the rule table is coarser than a calibrated
model, and it cannot express "three weak signals together". Quantifying
"together" is exactly the part that needs the missing independence structure.
See ADR-016 and ADR-017.

## 6. The distinction the module is organised around

```
declared change PREDICTS this movement   ≠   the declaration is TRUE
population MOVED                         ≠   population was ATTACKED
no finding                               ≠   no attack exists
scope not assessed                       ≠   scope clean
evidence confounded                      ≠   evidence refuted
valid provenance                         ≠   trusted model
five correlated detectors                ≠   five independent observations
```

Each line is enforced somewhere structural rather than by convention:
`declaration_validated: false` on every explanation; no rule escalating on shift
alone; a `NOT_ASSESSED` disposition that outranks `ACCEPT`; `RULE-DATA-004`;
four scope dispositions that never merge; and a family table that caps
corroboration at one unit per phenomenon.

## 7. Backward-compatible changes to Modules 1–3

All additive; every Module 1/2/3 test stayed green throughout.

| File | Change | Why it was necessary |
|---|---|---|
| `features/classical.py` | `blocks()` publishing the five **measured** span boundaries, `ACQUISITION_NAMES` for the 23 physical statistics, and `extract_with_blocks()` alongside the unchanged `extract()` | Block attribution and PSI both need to know which coordinates mean what. Hard-coding the spans in Module 4 would let them drift from the extractor |
| `features/store.py` | `FeatureSet.acquisition` and `acquisition_names` | The named statistics are what make a PSI result actionable rather than merely significant |
| `core/config.py` | `ShiftConfig`, `AssuranceConfig`, wired as `Config.shift` and `Config.assurance` | Every value changes what a result *means*, so every value is in the config hash and printed in the report |
| `risk/coverage.py` | Enriched `distribution_shift`; added the assurance capability registry | §32 of the brief: the coverage matrix must name the new capabilities explicitly |
| `reporting/__init__.py`, `cli/main.py` | Exports and the `assurance` command group | New entry point |

## 8. Defects the assurance lab caught

Nine, recorded in full in [`docs/research.md`](research.md) §12–20. Four were
measured false positives or unreachable results in the shift metrics
(in-sample covariance at −2.35 on clean data; PSI at 0.37 against a folklore
band of 0.25; BH significance unreachable by construction at B=199; standardised
block attribution saturating at 1.000 on every pair). Two were genuine holes in
the rule table — a scope that could vanish (`RULE-DATA-004`) and evidence that
reached no rule (`RULE-SHIFT-050`). Three were **wrong expectations in the lab
itself**, where the engine's behaviour turned out to be the honest one and the
scenario was corrected rather than the code.

## 8a. The legitimate-but-unusual group

Section 26 of the brief asks whether the system reads every unusual condition as
compromise. Four scenarios answer it, with expectations measured before they
were specified:

| Scenario | Result | Why |
|---|---|---|
| `unusual_initialisation` | `ACCEPT`, 0 findings | Unusual weight statistics are not evidence of a backdoor |
| `legitimate_reprocess` | `ACCEPT`, 0 findings | The same input processed twice is a duplicate *subject*, never a replay |
| `legitimate_reserialisation` | `REVIEW` | New bytes, identical graph and parameter digests. "The artifact changed and the model did not" is a fact worth confirming, not an accusation |
| `legitimate_finetuning` | `QUARANTINE` | **Correct.** The artifact supplied is not the artifact that was assured — a digest comparison, not an inference. The rule says *"the model is not the assured artifact"*, never "tampered" |

The last row is the one worth dwelling on. `QUARANTINE` here means *stop and
re-assure*, not *treat this as an attack*, and the rule's wording is what
carries that distinction. A system that softened it to `REVIEW` to avoid
"false-positive" optics would be allowing an unassured model into a pipeline.

## 9. What Module 4 does not do

- Re-verify upstream reports. A forged but well-formed report is fused as
  written, and cited by id and content so it stays attributable.
- Establish that a reference population is clean. Nothing here does.
- Validate a declared operational context.
- Separate illumination, season and terrain — all three move the same view.
- Separate a genuine dataset attack from a coincident legitimate shift. Held at
  `REVIEW`, by design, with the cost documented.
- Produce any aggregate number, now or later.

## 10. Handover to Module 5

Module 5 consumes, and needs nothing added to Module 4:

| Surface | What it gives |
|---|---|
| `PipelineAssuranceReport` (JSON) | `run_context`, `asset_scope`, the four scope summaries, `distribution_shift`, `evidence_summary`, the full evidence graph, **the source findings verbatim**, the decision with supporting/contradicting/unassessed, coverage, capabilities, limitations |
| `AssuranceDecision` | `decision_id`, `policy_version`, every fired rule with its rationale and the evidence ids that made it fire, per-basis confidence summary, severity summary, lineage |
| `AssurancePolicyEngine.describe()` | The whole rule table as data — id, scope, conditions, required evidence, exclusions, disposition, rationale |
| `stable_digest()` | A comparison key across runs, excluding only timestamps, timings and filesystem locations |
| `exit_code_for()` | `0` accept · `1` review · `2` not assessed · `3` quarantine |

**Module 5 must not** add a score, a gauge, a percentage or a single-number
headline over this report. Every number in it is a measurement with a stated
basis; a dashboard that averaged them would undo the entire design.
