import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

import {
  coverageTally,
  coverageViews,
  decisionView,
  evidenceTally,
  evidenceViews,
  familyViews,
  inputsView,
  orderEvidence,
  scopeViews,
  SCOPE_ORDER,
} from "../lib/analyst/assurance.ts"
import { buildExplorer } from "../lib/analyst/explorer.ts"
import {
  CONFLICTING_REPORT,
  EMPTY_REPORT,
  MALFORMED_REPORT,
  UNKNOWN_FINDING_REPORT,
  largeEvidenceReport,
} from "./fixtures.ts"
import type { AssuranceReport } from "../lib/analyst/types.ts"

function load(scenario: string): AssuranceReport {
  return JSON.parse(
    readFileSync(`../reports/analyst/scenarios/${scenario}/assurance.json`, "utf8"),
  ) as AssuranceReport
}

test("all four scopes are always rendered, even when the report carries none", () => {
  const scopes = scopeViews(EMPTY_REPORT)
  assert.equal(scopes.length, 4)
  assert.deepEqual(
    scopes.map((scope) => scope.scope),
    [...SCOPE_ORDER],
  )
  for (const scope of scopes) {
    assert.equal(scope.disposition, "NOT_ASSESSED")
    assert.equal(scope.assessed, false)
    assert.ok(scope.statement.length > 0, "an unassessed scope must still explain itself")
  }
})

test("'checked nothing' and 'checked and found nothing' stay distinguishable", () => {
  const nothing = scopeViews(load("no_inputs"))
  const clean = scopeViews(load("clean_baseline"))
  assert.ok(nothing.every((scope) => !scope.assessed))
  assert.ok(clean.every((scope) => scope.assessed))
  assert.equal(decisionView(load("no_inputs")).disposition, "NOT_ASSESSED")
  assert.equal(decisionView(load("clean_baseline")).disposition, "ACCEPT")
})

test("the page's disposition is the engine's, for every exported scenario", () => {
  const index = JSON.parse(readFileSync("../reports/analyst/index.json", "utf8")) as {
    scenarios: { name: string; status: string; observed_disposition: string | null }[]
  }
  let checked = 0
  for (const row of index.scenarios) {
    if (row.status !== "RUN") continue
    const report = load(row.name)
    assert.equal(
      decisionView(report).disposition,
      row.observed_disposition,
      `${row.name}: the view must not reinterpret the decision`,
    )
    checked += 1
  }
  assert.ok(checked >= 15, `expected the full scenario matrix, got ${checked}`)
})

test("a malformed report renders as NOT_ASSESSED instead of throwing", () => {
  const decision = decisionView(MALFORMED_REPORT)
  assert.equal(decision.disposition, "NOT_ASSESSED")
  assert.deepEqual(decision.firedRules, [])
  const scopes = scopeViews(MALFORMED_REPORT)
  assert.equal(scopes.length, 4)
  assert.equal(scopes[0].disposition, "NOT_ASSESSED")
  assert.deepEqual(evidenceViews(MALFORMED_REPORT), [])
  assert.deepEqual(familyViews(MALFORMED_REPORT), [])
})

test("a coverage level the build does not know becomes NOT_ASSESSED, not SUPPORTED", () => {
  const tally = coverageTally(MALFORMED_REPORT)
  assert.equal(tally.SUPPORTED, 0)
  assert.equal(tally.NOT_ASSESSED, 1)
  const views = coverageViews(UNKNOWN_FINDING_REPORT)
  assert.deepEqual(views, [])
})

test("an unknown finding type survives to the screen unchanged", () => {
  const explorer = buildExplorer(UNKNOWN_FINDING_REPORT)
  assert.equal(explorer.evidence.length, 1)
  const item = explorer.evidence[0]
  // Unknown severity and basis are shown verbatim; the platform does not
  // quietly relabel a value it does not recognise.
  assert.equal(item.severity, "APOCALYPTIC")
  assert.equal(item.basis, "VIBES")
  assert.equal(item.coverage, "TOTALLY_COVERED")
  assert.equal(item.attackClass, "quantum_telepathy")
})

test("empty findings produce an empty list, never a fabricated one", () => {
  assert.deepEqual(evidenceViews(EMPTY_REPORT), [])
  assert.deepEqual(coverageViews(EMPTY_REPORT), [])
  assert.equal(evidenceTally(EMPTY_REPORT).total, 0)
  assert.equal(decisionView(EMPTY_REPORT).unassessed.length, 0)
})

test("conflicting evidence is preserved on both sides rather than resolved", () => {
  const decision = decisionView(CONFLICTING_REPORT)
  assert.equal(decision.firedRules.length, 2)
  assert.equal(decision.conflicts.length, 1)
  // The strictest rule sorts first, but the ACCEPT rule is still carried.
  assert.equal(decision.governingRules[0].rule_id, "RULE-A")
  assert.ok(decision.governingRules.some((rule) => rule.rule_id === "RULE-B"))
})

test("a large evidence set joins in linear time and loses nothing", () => {
  const report = largeEvidenceReport(5000)
  const started = performance.now()
  const items = evidenceViews(report)
  const elapsed = performance.now() - started
  assert.equal(items.length, 5000)
  assert.ok(
    items.every((item) => item.finding !== null),
    "every evidence item must still reach its source finding",
  )
  assert.ok(elapsed < 2000, `join took ${elapsed.toFixed(0)}ms — that suggests a quadratic scan`)
})

test("evidence ordering is deterministic and severity-first", () => {
  const report = load("combined_attack")
  const once = orderEvidence(evidenceViews(report)).map((item) => item.evidence_id)
  const twice = orderEvidence(evidenceViews(report)).map((item) => item.evidence_id)
  assert.deepEqual(once, twice, "the same report must order identically every time")
  const severities = orderEvidence(evidenceViews(report)).map((item) => item.severity)
  const order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
  for (let i = 1; i < severities.length; i += 1) {
    assert.ok(
      order.indexOf(String(severities[i - 1])) >= order.indexOf(String(severities[i])),
      "severity must be non-increasing",
    )
  }
})

test("evidence lineage reaches the source finding and keeps its basis", () => {
  const explorer = buildExplorer(load("combined_attack"))
  assert.ok(explorer.evidence.length > 0)
  for (const item of explorer.evidence) {
    assert.notEqual(item.findingId, "—", "every item must name its finding")
    assert.notEqual(item.detector, "—", "every item must name its detector")
    assert.ok(item.basis.length > 0, "the confidence basis must travel with the number")
  }
})

test("confounded evidence keeps its confounder attached", () => {
  const report = load("ood_without_attack")
  const explorer = buildExplorer(report)
  const confounded = explorer.evidence.filter((item) => item.activeConfounders.length > 0)
  assert.ok(
    confounded.length > 0,
    "this scenario is the one where three detectors see one phenomenon",
  )
  for (const item of confounded) {
    assert.ok(item.confoundedBy.length > 0)
  }
})

test("correlated families are not counted as independent phenomena", () => {
  // The legitimate new-sensor scenario: three detectors, one physical change.
  // 13 dataset-labelling observations are confounded by the population shift,
  // and the engine reports NO independent phenomenon as a result.
  const explorer = buildExplorer(load("ood_without_attack"))
  const withConfounder = explorer.families.filter(
    (family) => family.activeConfounders.length > 0,
  )
  assert.ok(
    withConfounder.length > 0,
    "this scenario must have a family confounded by the shift",
  )
  assert.ok(
    withConfounder.every((family) => !family.independent),
    "a family with an active confounder must never be reported as independent",
  )
  assert.equal(
    explorer.families.filter((family) => family.independent).length,
    0,
    "one phenomenon seen by three detectors is not three independent attacks",
  )

  // The contrast case: genuinely separate compromises DO count separately.
  const combined = buildExplorer(load("combined_attack"))
  assert.ok(
    combined.families.filter((family) => family.independent).length > 1,
    "independent compromises must still be counted independently",
  )
})

test("supplied and missing inputs are both reported", () => {
  const full = inputsView(load("clean_baseline"))
  assert.equal(full.supplied.filter((input) => input.supplied).length, 4)
  const none = inputsView(load("no_inputs"))
  assert.equal(none.supplied.filter((input) => input.supplied).length, 0)
  assert.equal(none.supplied.length, 4, "a missing input is listed, not omitted")
})

test("no projection invents an aggregate score", () => {
  const report = load("combined_attack")
  // Field names the projections define themselves. Engine payloads they carry
  // verbatim (a detector's own `detector_scores`, say) are the engine's data
  // and are deliberately passed through untouched.
  const ownKeys = new Set<string>()
  const collect = (value: unknown, depth = 0) => {
    if (depth > 2 || value === null || typeof value !== "object") return
    if (Array.isArray(value)) {
      for (const entry of value.slice(0, 3)) collect(entry, depth + 1)
      return
    }
    for (const [key, nested] of Object.entries(value)) {
      ownKeys.add(key)
      if (key !== "observation" && key !== "rawObservation") collect(nested, depth + 1)
    }
  }
  for (const shape of [
    decisionView(report),
    evidenceTally(report),
    coverageTally(report),
    scopeViews(report),
  ]) {
    collect(shape)
  }
  for (const key of ownKeys) {
    assert.ok(
      !/score|trustLevel|overall(Risk|Confidence)/i.test(key),
      `projection defined a scoring field: '${key}'`,
    )
  }

  // And the report itself must not carry one either — the engine's own promise.
  assert.equal((report as Record<string, unknown>).trust_score, undefined)
  assert.equal((report.decision as Record<string, unknown>).score, undefined)
})
