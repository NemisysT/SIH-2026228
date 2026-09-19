/**
 * Display helpers. Formatting only — nothing here decides anything.
 *
 * The one rule this file exists to enforce: a value the engine did not
 * produce is rendered as NOT_ASSESSED or an em dash, never as a zero, a
 * percentage, or a neutral-looking default. A dash is honest; a 0 is a claim.
 */

import {
  COVERAGE_LEVELS,
  DISPOSITIONS,
  SEVERITY_ORDER,
  type Coverage,
  type Disposition,
  type Severity,
} from "./types.ts"

export const EMPTY = "—"

/** Coerce anything to one of the four dispositions; unknown becomes NOT_ASSESSED. */
export function asDisposition(value: unknown): Disposition {
  return typeof value === "string" && (DISPOSITIONS as readonly string[]).includes(value)
    ? (value as Disposition)
    : "NOT_ASSESSED"
}

export function asSeverity(value: unknown): Severity | null {
  return typeof value === "string" && (SEVERITY_ORDER as readonly string[]).includes(value)
    ? (value as Severity)
    : null
}

export function asCoverage(value: unknown): Coverage {
  return typeof value === "string" && (COVERAGE_LEVELS as readonly string[]).includes(value)
    ? (value as Coverage)
    : "NOT_ASSESSED"
}

export function severityRank(value: unknown): number {
  const severity = asSeverity(value)
  return severity === null ? -1 : SEVERITY_ORDER.indexOf(severity)
}

/** Strictness order, matching the policy engine's own: ACCEPT is weakest. */
const STRICTNESS: Record<Disposition, number> = {
  ACCEPT: 0,
  NOT_ASSESSED: 1,
  REVIEW: 2,
  QUARANTINE: 3,
}

export function dispositionRank(value: unknown): number {
  return STRICTNESS[asDisposition(value)]
}

/** Shorten a digest for display without ever losing the full value elsewhere. */
export function shortDigest(value: unknown, head = 12): string {
  if (typeof value !== "string" || value.length === 0) return EMPTY
  return value.length <= head + 2 ? value : `${value.slice(0, head)}…`
}

export function text(value: unknown, fallback = EMPTY): string {
  if (typeof value === "string" && value.trim().length > 0) return value
  if (typeof value === "number" && Number.isFinite(value)) return String(value)
  return fallback
}

export function count(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString("en-GB")
    : EMPTY
}

/**
 * Confidence as the engine recorded it, with its basis attached.
 *
 * Rendering a bare 0.62 invites the reader to treat it as a probability of
 * compromise. It is not one unless the basis says CALIBRATED, so the basis
 * travels with the number everywhere it is shown.
 */
export function confidence(value: unknown, basis?: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return EMPTY
  const shown = value.toFixed(2)
  return typeof basis === "string" && basis.length > 0 ? `${shown} ${basis}` : shown
}

export function pValue(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return EMPTY
  if (value === 0) return "0"
  return value < 0.0001 ? value.toExponential(2) : String(Number(value.toPrecision(4)))
}

export function statistic(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return EMPTY
  const magnitude = Math.abs(value)
  if (magnitude !== 0 && (magnitude < 0.001 || magnitude >= 1e6)) {
    return value.toExponential(3)
  }
  return String(Number(value.toPrecision(6)))
}

export function timestamp(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return EMPTY
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z")
}

/** Turn a snake_case identifier into words, leaving acronyms alone. */
export function humanise(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return EMPTY
  if (value === value.toUpperCase() && !value.includes("_")) return value
  return value.replace(/_/g, " ")
}

export function titleise(value: unknown): string {
  const words = humanise(value)
  if (words === EMPTY) return EMPTY
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/**
 * Whether a check outcome should read as passed.
 *
 * Module 3 emits PASS / FAIL / NOT_APPLICABLE / NOT_ASSESSED. The last two are
 * not failures, and a UI that renders them red would be lying about coverage.
 */
export type CheckState = "PASS" | "FAIL" | "NEUTRAL"

export function checkState(outcome: unknown): CheckState {
  if (typeof outcome !== "string") return "NEUTRAL"
  const upper = outcome.toUpperCase()
  if (upper === "PASS" || upper === "VALID" || upper === "OK") return "PASS"
  if (upper === "FAIL" || upper === "INVALID" || upper === "BROKEN") return "FAIL"
  return "NEUTRAL"
}
