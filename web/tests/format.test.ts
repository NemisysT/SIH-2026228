import test from "node:test"
import assert from "node:assert/strict"

import {
  asCoverage,
  asDisposition,
  asSeverity,
  checkState,
  confidence,
  count,
  dispositionRank,
  humanise,
  pValue,
  severityRank,
  shortDigest,
  statistic,
  text,
  timestamp,
} from "../lib/analyst/format.ts"

test("an unknown disposition becomes NOT_ASSESSED, never ACCEPT", () => {
  assert.equal(asDisposition("ACCEPT"), "ACCEPT")
  assert.equal(asDisposition("QUARANTINE"), "QUARANTINE")
  for (const bad of [undefined, null, "", "CLEAN", 7, {}, ["REVIEW"]]) {
    assert.equal(asDisposition(bad), "NOT_ASSESSED", `${JSON.stringify(bad)} must not become ACCEPT`)
  }
})

test("strictness order matches the engine's: ACCEPT is weakest, QUARANTINE strictest", () => {
  assert.ok(dispositionRank("ACCEPT") < dispositionRank("NOT_ASSESSED"))
  assert.ok(dispositionRank("NOT_ASSESSED") < dispositionRank("REVIEW"))
  assert.ok(dispositionRank("REVIEW") < dispositionRank("QUARANTINE"))
})

test("an unknown severity is null rather than coerced to INFO", () => {
  assert.equal(asSeverity("CRITICAL"), "CRITICAL")
  assert.equal(asSeverity("APOCALYPTIC"), null)
  assert.equal(severityRank("APOCALYPTIC"), -1)
  assert.ok(severityRank("CRITICAL") > severityRank("HIGH"))
})

test("an unknown coverage level becomes NOT_ASSESSED, never SUPPORTED", () => {
  assert.equal(asCoverage("SUPPORTED"), "SUPPORTED")
  assert.equal(asCoverage("REQUIRES_WHITE_BOX"), "REQUIRES_WHITE_BOX")
  assert.equal(asCoverage("TOTALLY_COVERED"), "NOT_ASSESSED")
  assert.equal(asCoverage(undefined), "NOT_ASSESSED")
})

test("a missing value renders as an em dash, never as zero", () => {
  assert.equal(text(undefined), "—")
  assert.equal(text(""), "—")
  assert.equal(count(undefined), "—")
  assert.equal(count(0), "0")
  assert.equal(confidence(undefined), "—")
  assert.equal(pValue(undefined), "—")
  assert.equal(statistic(undefined), "—")
  assert.equal(shortDigest(undefined), "—")
})

test("confidence always carries its basis, so a bare number cannot read as a probability", () => {
  assert.equal(confidence(0.62, "CALIBRATED"), "0.62 CALIBRATED")
  assert.equal(confidence(0.62, "HEURISTIC_UNCALIBRATED"), "0.62 HEURISTIC_UNCALIBRATED")
  assert.equal(confidence(0.62), "0.62")
})

test("NOT_APPLICABLE and NOT_ASSESSED are neutral, not failures", () => {
  assert.equal(checkState("PASS"), "PASS")
  assert.equal(checkState("FAIL"), "FAIL")
  assert.equal(checkState("NOT_APPLICABLE"), "NEUTRAL")
  assert.equal(checkState("NOT_ASSESSED"), "NEUTRAL")
  assert.equal(checkState(undefined), "NEUTRAL")
})

test("digests are shortened for display but never silently truncated to nothing", () => {
  const digest = "a".repeat(64)
  assert.equal(shortDigest(digest, 12), `${"a".repeat(12)}…`)
  assert.equal(shortDigest("short"), "short")
})

test("formatting is deterministic across repeated calls", () => {
  const values = [0.123456789, 1e-9, 1234567, 0]
  for (const value of values) {
    assert.equal(statistic(value), statistic(value))
    assert.equal(pValue(value), pValue(value))
  }
  assert.equal(timestamp("2026-09-19T03:43:39Z"), timestamp("2026-09-19T03:43:39Z"))
})

test("humanise leaves acronyms alone", () => {
  assert.equal(humanise("DETERMINISTIC"), "DETERMINISTIC")
  assert.equal(humanise("ood_insertion"), "ood insertion")
})
