# Module 5 — Analyst platform

The assurance engine is Modules 1 to 4. Module 5 is the application an analyst
actually sits in front of. It computes nothing.

That constraint is the whole design. Every number, verdict, rule and sentence
on screen was produced by the engine and written to a JSON report; the frontend
selects, orders and renders. A page cannot disagree with the backend because a
page has nothing of its own to disagree with.

## Boundary

```
Module 1  dataset forensics      ─┐
Module 2  model forensics        ─┤
Module 3  inference provenance   ─┼─→  PipelineAssuranceReport (JSON on disk)
Module 4  shift + evidence fusion ┘             │
                                                ▼
                                      Module 5  analyst platform
                                      (Next.js, reads the filesystem)
```

`cvtrust analyst export` runs the real pipelines over the attack lab and writes
the feed. `web/` reads it. Nothing crosses that line in the other direction.

### The feed

```
reports/analyst/
  index.json                       the scenario catalogue
  capabilities.json                this build's coverage statement
  scenarios/<name>/assurance.json  Module 4 PipelineAssuranceReport
  scenarios/<name>/dataset.json    Module 1 report, byte-for-byte
  scenarios/<name>/model.json      Module 2 report, byte-for-byte
  scenarios/<name>/provenance.json Module 3 report, byte-for-byte
  scenarios/<name>/shift.json      Module 4 ShiftAssessment
```

`index.json` is the only shape Module 5 defines, and it is a catalogue rather
than an assessment: names, paths, the lab's declared expectation and the
disposition the policy engine actually produced. Its projected fields are
asserted equal to the report they point at by
`tests/integration/test_analyst_export.py`, so a list screen and a detail
screen cannot tell different stories.

A scenario whose upstream lab is absent is exported with `status="NOT_RUN"` and
the reason. It is never fabricated and never dropped.

## Live and demo are never blended

Two sources exist:

| Source | Directory | What it is |
|---|---|---|
| `DEMO` | `reports/analyst` | Real Module 1–4 output over attack-lab scenarios |
| `LIVE` | `reports/live` | Output of a real assessment, published by an operator |

The source rides in the query string, is stated in words on every screen, and
never falls back. Asking for `?source=live` on an empty live directory shows
the live empty state, not demo data — an analyst who asked for live results
must never be handed laboratory results without noticing.

## What the UI must not do

The engine has no universal score, by deliberate architectural decision. The UI
does not introduce one. There is no trust score, no security score, no 0–100
gauge and no weighted combination anywhere in `web/`, and three separate checks
fail the build if one appears:

- `tests/integration/test_analyst_export.py` walks every exported report for a
  scoring field;
- `web/tests/assurance.test.ts` walks the projections' own field names;
- `scripts/module5_check.py` scans every rendered page for a displayed score.

The same rule governs the smaller claims. A confidence number is always shown
with its basis, because an uncalibrated `0.9` is not a 90% chance of anything.
Module 2's six levels stay categorical. Coverage is counted, never divided. A
value the engine did not produce renders as an em dash, never as a zero.

## Information architecture

| Route | Brief | Shows |
|---|---|---|
| `/` | §6 | Assurance dashboard: identity, disposition, four scopes, evidence, coverage |
| `/dataset` | §8 | Module 1: identity, contributors, detectors, findings |
| `/model` | §9 | Module 2: six levels, access mode, backdoor coverage |
| `/provenance` | §10 | Module 3: per-record binding verification |
| `/audit` | §16 | Module 3: chain timeline, signing trail, replay |
| `/shift` | §11 | Module 4: populations, metrics, operational context |
| `/evidence` | §12 | Decision → rule → evidence → detector → raw observation |
| `/decision` | §15 | Disposition, why, assessed, not assessed, policy |
| `/coverage` | §14 | Build capability vs run coverage vs unassessed areas |
| `/demo` | §17 | The scenario matrix and the end-to-end walk |

## Semantics the UI is responsible for preserving

Three of the engine's distinctions are easy to destroy in a UI, so they have
dedicated tests:

**A chain break localises to the successor link** (§16). Module 3 establishes
that one link's declared predecessor does not match. It does not establish that
later records are forged. `/audit` marks exactly one break and renders later
entries as *unverified beyond the break* — visibly different from both verified
and failed.

**Population shift is not per-sample OOD** (§11). `/shift` shows the population
verdict and the OOD count side by side and says what each one means. The shift
view never uses the word "attack": whether independent evidence exists is the
policy engine's finding, not the shift module's.

**Correlated findings are not independent attacks** (§13). Evidence families
carry their confounders to the screen. In `ood_without_attack`, three detectors
observe one legitimate sensor change, and the platform reports zero independent
phenomena — the same answer the engine gives.

## Frontend design

The visual system is the supplied design reference, reused rather than
reinterpreted: same components, same Tailwind v4 theme (all 72 variables
unchanged), same fonts, same animations, same supplied imagery.
`scripts/module5_visual_check.py` diffs each transformed section against its
reference original and currently reports 98% of the reference's visual classes
preserved. The remainder are structural consequences of the data — four modules
where the reference had three steps, seven routes where it had five links — and
are listed in the script's output.

Two changes were made for the offline requirement rather than for design:

- `next/font/google` fetches from `fonts.gstatic.com` at build time, so the
  three families are self-hosted in `public/fonts` with the `@font-face`
  declarations `next/font` emitted, including the fallback metric overrides.
  Rendering is unchanged; the network dependency is gone.
- `@vercel/analytics` was removed.

The eight assets the reference loaded from a hosted blob store are the supplied
files in `SIH Images`, served from `public/`.

## Running it

```bash
cvtrust analyst export --out reports/analyst   # build the feed from the engine
cd web && npm run dev                          # http://localhost:3000
./scripts/module5-verify.sh                    # the full end-to-end gate
```

## Tests

| Suite | Command | Covers |
|---|---|---|
| Backend boundary | `pytest tests/integration/test_analyst_export.py` | Catalogue ≡ report, determinism, NOT_RUN, no score |
| Offline | `pytest tests/security/test_module5_offline.py` | No remote origin, self-hosted fonts, responsive parity |
| Projections | `cd web && npm test` | 60 tests: malformed, missing, unknown, empty, large, conflicting |
| End to end | `./scripts/module5-verify.sh` | 190 page renders checked against the engine's JSON |
| Visual | `python3 scripts/module5_visual_check.py` | Class, token and theme preservation vs the reference |

## Known limitations

- The live source is a directory an operator populates with real assessment
  output. The platform reads it; it does not run assessments itself. Driving
  the engine from the browser would put forensic logic behind an HTTP handler,
  which §20 rules out.
- The visual check is structural — classes, tokens, keyframes, theme
  variables. It cannot see a rendering regression that preserves every class,
  and it is not a pixel diff.
- The evidence explorer renders every item a report carries. The largest
  scenario carries 49; a report with tens of thousands would need windowing.
