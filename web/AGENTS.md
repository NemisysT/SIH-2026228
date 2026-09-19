# Working in web/

This is Module 5: the analyst platform for the cvtrust assurance engine.

## The two constraints that are not negotiable

**1. The frontend computes nothing.** Every value on screen comes from a JSON
report written by Modules 1–4. Do not derive, combine, average or infer. If a
screen needs a number the engine does not produce, the answer is to show what
the engine does produce, not to compute the missing one here. Forensic logic
belongs in `src/cvtrust/`, never in a React component.

**2. There is no universal score.** No trust score, no security score, no
safety score, no 0–100 gauge, no weighted combination. The architecture
deliberately has none; a UI that invented one would misrepresent the whole
system. Three checks enforce this and will fail the build.

## Consequences worth knowing before you edit

- A value the engine did not produce renders as an em dash, never as `0`.
- A confidence number always travels with its basis. An uncalibrated `0.9` is
  not a 90% chance of anything.
- `NOT_ASSESSED` is never rendered as clean. "We checked and found nothing" and
  "we checked nothing" must stay visibly different.
- Module 2's six levels stay categorical. Never turn a status into a percentage.
- Coverage is counted, never divided. Coverage is not security.
- A chain break localises to one link. Records after it are *unverified*, not
  invalid — the verifier does not establish that they are forged.
- Demo and live data are never blended, and live never falls back to demo.

## The design is not ours to change

The visual system is the supplied design reference, reused rather than
reinterpreted. Before changing spacing, type, colour or animation, run:

```bash
python3 ../scripts/module5_visual_check.py
```

It diffs each section against its reference original and reports what changed.
A new divergence needs a reason, and a responsive divergence needs an entry in
`DOCUMENTED_BREAKPOINT_DEVIATIONS` in `tests/security/test_module5_offline.py`.

## Before you commit

```bash
npm run typecheck && npm test && npm run build
cd .. && ./scripts/module5-verify.sh
```

The last one is the real gate: it runs the engine, builds the feed, serves the
app and asserts every screen agrees with the engine's JSON.
