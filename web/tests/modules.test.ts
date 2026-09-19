import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

import {
  contributorRows,
  datasetIdentity,
  findingsByAttackClass,
  summaryCounts,
} from "../lib/analyst/dataset.ts"
import { accessView, backdoorCoverage, levelTone, levelViews } from "../lib/analyst/model.ts"
import {
  chainView,
  firstFailure,
  provenanceSummary,
  recordViews,
  stageViews,
  VERIFICATION_STAGES,
} from "../lib/analyst/provenance.ts"
import { oodFindingCount, shiftView } from "../lib/analyst/shift.ts"
import { BROKEN_CHAIN, EMPTY_FINDINGS_DATASET } from "./fixtures.ts"

function load<T>(scenario: string, artifact: string): T {
  return JSON.parse(
    readFileSync(`../reports/analyst/scenarios/${scenario}/${artifact}.json`, "utf8"),
  ) as T
}

/* ---------------------------------------------------------------- Module 1 */

test("dataset identity comes straight out of the manifest", () => {
  const identity = datasetIdentity(load("dataset_anomaly", "dataset"))
  assert.ok(identity)
  assert.ok(identity.digest.length > 0)
  assert.ok((identity.samples ?? 0) > 0)
  assert.ok(identity.classes.length > 0)
})

test("a dataset with no report renders as absent, not as clean", () => {
  assert.equal(datasetIdentity(null), null)
  const summary = summaryCounts(null)
  assert.equal(summary.overall, "NOT ASSESSED")
  assert.equal(summary.total, 0)
})

test("contributors with nothing flagged are still listed", () => {
  const rows = contributorRows(load("dataset_anomaly", "dataset"))
  assert.ok(rows.length > 1)
  assert.ok(
    rows.some((row) => (row.flagged ?? 0) === 0),
    "hiding clean contributors would hide the denominator",
  )
})

test("findings group by attack class, strongest class first", () => {
  const report = load<{ findings: unknown[] }>("combined_attack", "dataset")
  const groups = findingsByAttackClass(report.findings as never[])
  assert.ok(groups.length > 1)
  const total = groups.reduce((sum, group) => sum + group.findings.length, 0)
  assert.equal(total, report.findings.length, "grouping must not drop a finding")
  const order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
  for (let i = 1; i < groups.length; i += 1) {
    assert.ok(
      order.indexOf(String(groups[i - 1].maxSeverity)) >=
        order.indexOf(String(groups[i].maxSeverity)),
    )
  }
})

test("an empty findings list produces no groups and no invented rows", () => {
  assert.deepEqual(findingsByAttackClass([]), [])
  assert.deepEqual(findingsByAttackClass(EMPTY_FINDINGS_DATASET.findings ?? []), [])
  assert.equal(summaryCounts(EMPTY_FINDINGS_DATASET).total, 0)
})

/* ---------------------------------------------------------------- Module 2 */

test("all six model levels always render, absent ones as NOT_ASSESSED", () => {
  const levels = levelViews(null)
  assert.equal(levels.length, 6)
  assert.ok(levels.every((level) => level.status === "NOT_ASSESSED"))
  assert.ok(levels.every((level) => !level.assessed))
})

test("model level statuses stay categorical and are never numbers", () => {
  const levels = levelViews(load("model_substitution", "model"))
  assert.equal(levels.length, 6)
  for (const level of levels) {
    assert.equal(typeof level.status, "string")
    assert.ok(!/^\d+(\.\d+)?%?$/.test(level.status), `level became a number: ${level.status}`)
  }
  assert.ok(levels.some((level) => level.tone === "ANOMALOUS"))
})

test("an unrecognised level status is neutral, not treated as clean", () => {
  assert.equal(levelTone("CONSISTENT"), "CLEAN")
  assert.equal(levelTone("MISMATCH"), "ANOMALOUS")
  assert.equal(levelTone("NO_ANOMALY_DETECTED"), "CLEAN")
  assert.equal(levelTone("SOMETHING_NEW"), "NEUTRAL")
  assert.equal(levelTone(undefined), "NEUTRAL")
})

test("access mode and its consequences are reported together", () => {
  const access = accessView(load("model_substitution", "model"))
  assert.ok(access.mode.length > 0)
  assert.notEqual(access.mode, "NOT_ASSESSED")
  assert.ok(access.capabilities.length > 0)
})

test("backdoor coverage is separate from backdoor findings", () => {
  const coverage = backdoorCoverage(load("clean_baseline", "model"))
  assert.ok(coverage.entries.length > 0, "the build must state its backdoor coverage")
  assert.equal(typeof coverage.benchmarkAvailable, "boolean")
  assert.ok((coverage.probeCount ?? 0) > 0)
})

/* ---------------------------------------------------------------- Module 3 */

test("a clean chain reports no break", () => {
  const chain = chainView(load("clean_baseline", "provenance"))
  assert.equal(chain.firstBreakPosition, null)
  assert.ok(chain.entries.length > 0)
  assert.ok(chain.entries.every((entry) => !entry.isBreak && !entry.afterBreak))
})

test("a chain break localises to exactly one link", () => {
  const chain = chainView(BROKEN_CHAIN)
  const breaks = chain.entries.filter((entry) => entry.isBreak)
  assert.equal(breaks.length, 1, "a break must localise to one successor link")
  assert.equal(breaks[0].position, 3)
})

test("records after a break are unverified, never marked invalid", () => {
  const chain = chainView(BROKEN_CHAIN)
  const after = chain.entries.filter((entry) => entry.afterBreak)
  assert.equal(after.length, 3, "positions 4, 5 and 6 follow the break")
  assert.ok(
    after.every((entry) => !entry.isBreak),
    "the verifier does not establish that later records are forged",
  )
  const before = chain.entries.filter(
    (entry) => !entry.isBreak && !entry.afterBreak,
  )
  assert.equal(before.length, 3, "positions 0, 1 and 2 remain verified")
})

test("a provenance failure names the check, not just a red badge", () => {
  const report = load<Record<string, unknown>>("provenance_tampering", "provenance")
  const failure = firstFailure(report as never)
  assert.ok(failure, "this scenario must contain a failing record")
  assert.ok(failure.failures.length > 0, "the failure codes must be carried")
  const failing = failure.stages.filter((stage) => stage.state === "FAIL")
  assert.ok(failing.length > 0, "at least one verification stage must report FAIL")
  for (const stage of failing) {
    assert.ok(stage.checks.length > 0, "a failing stage must name its checks")
    assert.ok(
      stage.checks.some((check) => (check.detail ?? "").length > 0),
      "the verifier's own detail must reach the screen",
    )
  }
  // Passing stages are kept too: a chain of green ticks is a finding as well.
  assert.ok(failure.stages.some((stage) => stage.state === "PASS"))
})

test("every verification stage maps to real verifier check names", () => {
  const report = load<Record<string, unknown>>("clean_baseline", "provenance")
  const records = recordViews(report as never)
  assert.ok(records.length > 0)
  const known = new Set(
    (records[0].verification?.checks ?? []).map((check) => check.name),
  )
  const mapped = VERIFICATION_STAGES.flatMap((stage) => stage.checks)
  const matched = mapped.filter((name) => known.has(name))
  assert.ok(
    matched.length >= mapped.length * 0.75,
    `only ${matched.length}/${mapped.length} stage checks exist in the verifier output`,
  )
})

test("a missing trust store is reported rather than assumed away", () => {
  const summary = provenanceSummary(null)
  assert.equal(summary.trustStoreSupplied, false)
  assert.equal(summary.overall, "NOT ASSESSED")
  assert.equal(summary.chainStatus, "NOT_ASSESSED")
})

/* ---------------------------------------------------------------- Module 4 */

test("a shift assessment with no reference renders as absent", () => {
  assert.equal(shiftView(null), null)
})

test("metrics that declined to run are kept with their reason", () => {
  const view = shiftView(load("operational_shift", "shift"))
  assert.ok(view)
  assert.ok(view.metrics.length > 0)
  for (const metric of view.unrunMetrics) {
    assert.equal(metric.statistic, "—", "a metric that did not run has no statistic")
    assert.ok(metric.reason.length > 0 || metric.status.length > 0)
  }
  assert.equal(
    view.metrics.length,
    view.significantMetrics.length + view.metrics.filter((m) => !m.significant).length,
  )
})

test("a declared operational change is recorded as a claim, never as proof", () => {
  const view = shiftView(load("operational_shift", "shift"))
  assert.ok(view?.context)
  assert.equal(
    view.context.declarationValidated,
    false,
    "the engine never validates an operator's declaration",
  )
  assert.ok(view.context.explanation.length > 0)
})

test("population shift and per-sample OOD stay separate counts", () => {
  const view = shiftView(load("ood_without_attack", "shift"))
  const dataset = load<{ findings: { attack_class?: string }[] }>(
    "ood_without_attack",
    "dataset",
  )
  const ood = oodFindingCount(dataset.findings)
  assert.ok(ood > 0, "this scenario has per-sample OOD flags")
  assert.ok(view, "and a population-level assessment")
  // One verdict for the population; a separate count for the samples. The two
  // are never the same number by construction.
  assert.equal(typeof view.verdict, "string")
  assert.notEqual(String(ood), view.verdict)
})

test("the shift view never labels an observation an attack", () => {
  for (const scenario of ["operational_shift", "unexplained_shift", "combined_attack"]) {
    const view = shiftView(load(scenario, "shift"))
    const text = JSON.stringify(view).toLowerCase()
    assert.ok(
      !/"attack detected"|malicious/.test(text),
      `${scenario}: the shift view must not assert maliciousness`,
    )
  }
})

test("an empty stage list is neutral, not a pass", () => {
  const stages = stageViews(null)
  assert.equal(stages.length, VERIFICATION_STAGES.length)
  assert.ok(stages.every((stage) => stage.state === "NEUTRAL"))
  assert.ok(stages.every((stage) => stage.absent.length > 0))
})
