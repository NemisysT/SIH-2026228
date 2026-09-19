import test from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"

import {
  findScenario,
  listScenarios,
  loadCatalogue,
  loadScenarioBundle,
  readArtifact,
  readJsonStrict,
  resolveScenario,
  sourceStatus,
} from "../lib/analyst/source.ts"
import { loadPageData, linkSuffix, readSource } from "../lib/analyst/page-data.ts"
import { buildOverview, scenarioCards } from "../lib/analyst/overview.ts"

test("the demo feed loads and holds the whole scenario matrix", async () => {
  const catalogue = await loadCatalogue("DEMO")
  assert.ok(catalogue, "the exported feed must be present")
  assert.ok((catalogue.scenarios ?? []).length >= 15)
  assert.equal(catalogue.kind, "DEMO")
})

test("an empty LIVE source reports itself rather than falling back to DEMO", async () => {
  const status = await sourceStatus("LIVE")
  const demo = await sourceStatus("DEMO")
  if (!status.available) {
    assert.equal(status.scenarioCount, 0)
    assert.ok(status.remedy.includes("cvtrust assurance assess"))
    assert.ok(demo.available, "and the demo feed is separately available")
    assert.deepEqual(await listScenarios("LIVE"), [], "LIVE must not serve DEMO rows")
  }
})

test("an unknown scenario name falls back to a real one, not to nothing", async () => {
  const resolved = await resolveScenario("does-not-exist", "DEMO")
  assert.ok(resolved)
  assert.equal(resolved.status, "RUN")
  assert.equal(await findScenario("does-not-exist", "DEMO"), null)
})

test("a scenario bundle loads every artifact the catalogue names", async () => {
  const scenario = await findScenario("combined_attack", "DEMO")
  assert.ok(scenario)
  const bundle = await loadScenarioBundle(scenario, "DEMO")
  assert.ok(bundle.assurance)
  assert.ok(bundle.dataset)
  assert.ok(bundle.model)
  assert.ok(bundle.provenance)
  assert.ok(bundle.shift)
  assert.deepEqual(bundle.malformed, [])
})

test("an artifact a run did not produce is absent, not empty", async () => {
  const scenario = await findScenario("no_inputs", "DEMO")
  assert.ok(scenario)
  const bundle = await loadScenarioBundle(scenario, "DEMO")
  assert.equal(bundle.dataset, null)
  assert.equal(bundle.model, null)
  assert.equal(bundle.provenance, null)
  assert.ok(bundle.assurance, "the assurance report itself still exists")
})

test("a malformed report file is reported as malformed, not as missing", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "cvtrust-feed-"))
  try {
    mkdirSync(path.join(dir, "scenarios", "broken"), { recursive: true })
    writeFileSync(path.join(dir, "scenarios", "broken", "assurance.json"), "{ not json")
    writeFileSync(
      path.join(dir, "index.json"),
      JSON.stringify({
        kind: "DEMO",
        scenarios: [
          {
            name: "broken",
            status: "RUN",
            files: { assurance: "scenarios/broken/assurance.json" },
          },
        ],
      }),
    )
    process.env.CVTRUST_DEMO_DIR = dir
    const scenario = await findScenario("broken", "DEMO")
    assert.ok(scenario)
    const bundle = await loadScenarioBundle(scenario, "DEMO")
    assert.equal(bundle.assurance, null)
    assert.deepEqual(bundle.malformed, ["assurance"], "malformed must not look like missing")

    const outcome = await readJsonStrict(path.join(dir, "scenarios", "broken", "assurance.json"))
    assert.equal(outcome.ok, false)
    if (!outcome.ok) assert.equal(outcome.kind, "MALFORMED")

    const absent = await readJsonStrict(path.join(dir, "nope.json"))
    assert.equal(absent.ok, false)
    if (!absent.ok) assert.equal(absent.kind, "MISSING")
  } finally {
    delete process.env.CVTRUST_DEMO_DIR
    rmSync(dir, { recursive: true, force: true })
  }
})

test("a path that escapes the report directory is refused", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "cvtrust-feed-"))
  try {
    writeFileSync(
      path.join(dir, "index.json"),
      JSON.stringify({
        scenarios: [
          { name: "evil", status: "RUN", files: { assurance: "../../../etc/passwd" } },
        ],
      }),
    )
    process.env.CVTRUST_DEMO_DIR = dir
    assert.equal(await readArtifact("DEMO", "evil", "assurance"), null)
    const scenario = await findScenario("evil", "DEMO")
    assert.ok(scenario)
    await assert.rejects(() => loadScenarioBundle(scenario, "DEMO"), /outside the report directory/)
  } finally {
    delete process.env.CVTRUST_DEMO_DIR
    rmSync(dir, { recursive: true, force: true })
  }
})

test("the source is read from the query string and defaults to DEMO", () => {
  assert.equal(readSource({}), "DEMO")
  assert.equal(readSource({ source: "live" }), "LIVE")
  assert.equal(readSource({ source: "LIVE" }), "LIVE")
  assert.equal(readSource({ source: ["live"] }), "LIVE")
  assert.equal(readSource({ source: "something-else" }), "DEMO")
})

test("the selection travels between pages in the query string", () => {
  assert.equal(linkSuffix("DEMO", "clean_baseline"), "?scenario=clean_baseline")
  assert.equal(linkSuffix("LIVE", "run-1"), "?scenario=run-1&source=live")
  assert.equal(linkSuffix("DEMO", undefined), "")
})

test("asking for LIVE never silently serves DEMO", async () => {
  const data = await loadPageData({ source: "live" })
  assert.equal(data.source, "LIVE")
  if (!data.status.available) {
    assert.equal(data.bundle, null)
    assert.equal(data.scenario, null)
    assert.deepEqual(data.options, [])
    assert.ok(data.other.available, "and the platform still knows DEMO has data")
  }
})

test("the overview model is built entirely from the report", async () => {
  const data = await loadPageData({ scenario: "combined_attack" })
  assert.ok(data.bundle)
  const model = buildOverview(data.bundle, "DEMO")
  assert.equal(model.hero.disposition, data.bundle.assurance?.decision?.disposition)
  assert.equal(model.scopes.cards.length, 4)
  assert.equal(model.pipeline.length, 4)
  assert.ok(model.evidence.metrics.length >= 3)
  assert.ok(model.findings.length > 0)
  for (const finding of model.findings) {
    assert.ok(finding.basis.length > 0, "the basis must accompany the confidence")
  }
})

test("the overview survives a bundle with no assurance report", () => {
  const model = buildOverview(null, "DEMO")
  assert.equal(model.hero.disposition, "NOT_ASSESSED")
  assert.equal(model.scopes.cards.length, 4)
  assert.equal(model.shift, null)
  assert.deepEqual(model.findings, [])
})

test("scenario cards report what the engine produced, not what was expected", async () => {
  const rows = await listScenarios("DEMO")
  const cards = scenarioCards(rows, "DEMO")
  assert.ok(cards.length > 0)
  for (const card of cards) {
    const row = rows.find((entry) => entry.name === card.name)
    assert.ok(row)
    assert.equal(card.disposition, row.observed_disposition ?? "NOT_ASSESSED")
    assert.ok(card.href.includes(card.name))
  }
})
