# SIH26228 — analyst platform (Module 5)

The frontend for the cvtrust assurance engine. It computes nothing: every
verdict, number and sentence it shows was produced by Modules 1–4 and written
to a JSON report.

```bash
# To just run the demo, use the launcher at the repository root instead:
#   ./run.sh          builds the feed if needed, serves this application,
#                     and waits until it answers   -> http://localhost:3000
# The steps below are the same thing by hand, for working inside web/.
# From the repository root, ./setup.sh does both of these on a fresh clone.

# 1. Build the feed from the real pipelines (from the repository root)
cvtrust analyst export --out reports/analyst

# 2. Run the application
npm install     # only needed once; node_modules is vendored for offline use
npm run dev     # http://localhost:3000
```

`npm install` needs the `legacy-peer-deps` setting in `.npmrc`: `@react-three/fiber`
declares a peer range of react `<19.3` and this application is built and
verified against react 19.3.0. Do not resolve it by downgrading react.

## Layout

```
app/                     routes — one per analyst area, plus the report endpoints
  page.tsx               the assurance dashboard
  dataset|model|provenance|audit|shift|evidence|decision|coverage|demo/
  api/analyst/report/…   serves the engine's report files, byte for byte
components/
  landing/               the design reference's sections, carrying SIH data
  platform/              shell, primitives and the evidence explorer
  ui/                    the reference's shadcn components, unmodified
lib/analyst/             the data layer: types, projections, the disk source
  format.ts              display helpers — missing renders as —, never as 0
  assurance.ts           Module 4 projections; no aggregate is computed here
  dataset|model|provenance|shift.ts
  explorer.ts            the decision → raw observation drill-down
  source.ts              reads reports/analyst and reports/live from disk
tests/                   node --test, no framework dependency
public/images|video|fonts  the supplied assets, served locally
```

## Commands

```bash
npm run dev        # development server
npm run build      # production build (type errors fail it)
npm start          # serve the production build
npm test           # 60 projection tests, node --test + type stripping
npm run typecheck  # tsc --noEmit
```

## Two rules

**The frontend never decides anything.** It selects, orders and renders. If a
screen and the report disagree, the screen is wrong — and
`scripts/module5-verify.sh` in the repository root fails the build when they do.

**There is no score.** No trust score, no security score, no gauge, no weighted
combination. The engine has none by design and the UI does not add one.

## Offline

No network is used at build time or at run time: fonts are self-hosted in
`public/fonts`, all imagery is local, there is no analytics package, and the
data layer reads the filesystem rather than calling a service.
`tests/security/test_module5_offline.py` fails the build if that changes.

See [`../docs/module-5-plan.md`](../docs/module-5-plan.md) for the full design.
