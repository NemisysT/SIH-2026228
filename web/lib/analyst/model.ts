/**
 * Projections over Module 2's model report.
 *
 * §9 is explicit that the six assessment levels must stay categorical: a level
 * is CONSISTENT, MISMATCH, ANOMALOUS, NO_ANOMALY_DETECTED or NOT_ASSESSED, and
 * turning that into a percentage would invent precision the detector never
 * claimed. Nothing in this file produces a number the report did not contain.
 */

import { asCoverage, text } from "./format.ts"
import type { Coverage, ModelReport } from "./types.ts"

/** The six levels, in the order Module 2 assesses them. */
export const ASSESSMENT_LEVELS = [
  "identity",
  "structure",
  "parameters",
  "behaviour",
  "activation",
  "trigger",
] as const

export type AssessmentLevel = (typeof ASSESSMENT_LEVELS)[number]

const LEVEL_TITLES: Record<AssessmentLevel, string> = {
  identity: "Identity",
  structure: "Structural",
  parameters: "Parameter",
  behaviour: "Behavioural",
  activation: "Activation",
  trigger: "Trigger",
}

/** How a level's status should read. Neutral is neither pass nor fail. */
export type LevelTone = "CLEAN" | "ANOMALOUS" | "NEUTRAL"

const CLEAN_STATUSES = new Set(["CONSISTENT", "MATCH", "NO_ANOMALY_DETECTED", "CLEAN"])
const ANOMALOUS_STATUSES = new Set(["MISMATCH", "ANOMALOUS", "SUSPICIOUS", "TAMPERED"])

export function levelTone(status: unknown): LevelTone {
  if (typeof status !== "string") return "NEUTRAL"
  if (CLEAN_STATUSES.has(status)) return "CLEAN"
  if (ANOMALOUS_STATUSES.has(status)) return "ANOMALOUS"
  return "NEUTRAL"
}

export interface LevelView {
  level: AssessmentLevel
  title: string
  status: string
  tone: LevelTone
  detail: string
  reason: string
  detector: string
  evidenceKeys: string[]
  assessed: boolean
}

/**
 * The six levels as rows.
 *
 * A level missing from the report is returned as NOT_ASSESSED rather than
 * omitted, so a black-box run visibly has the same six rows as a white-box
 * one, with the difference stated instead of hidden.
 */
export function levelViews(report: ModelReport | null): LevelView[] {
  const assessment = report?.assessment ?? {}
  return ASSESSMENT_LEVELS.map((level) => {
    const entry = assessment[level]
    const status = text(entry?.status, "NOT_ASSESSED")
    return {
      level,
      title: LEVEL_TITLES[level],
      status,
      tone: levelTone(entry?.status),
      detail: text(entry?.detail, ""),
      reason: text(entry?.reason, ""),
      detector: text(entry?.detector, ""),
      evidenceKeys: entry?.evidence_keys ?? [],
      assessed: status !== "NOT_ASSESSED",
    }
  })
}

export interface ModelIdentityView {
  modelId: string
  manifestId: string
  format: string
  architectureDeclared: string
  architectureIsUntrusted: boolean
  fileSha256: string
  fileSizeBytes: number | null
  graphDigest: string
  parameterDigest: string
  parameterCount: number | null
  layerCount: number | null
  operators: Record<string, number>
  inputs: Record<string, unknown>[]
  outputs: Record<string, unknown>[]
  declaredMetadata: Record<string, unknown>
  unavailableFields: string[]
  notes: string[]
  path: string
}

export function modelIdentity(report: ModelReport | null): ModelIdentityView | null {
  const model = report?.model
  if (!model) return null
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  const list = (value: unknown) => (Array.isArray(value) ? (value as Record<string, unknown>[]) : [])
  return {
    modelId: text(model.model_id),
    manifestId: text(model.manifest_id),
    format: text(model.format),
    architectureDeclared: text(model.architecture_declared),
    architectureIsUntrusted: model.architecture_declared_is_untrusted === true,
    fileSha256: text(model.file_sha256),
    fileSizeBytes: num(model.file_size_bytes),
    graphDigest: text(model.graph_digest),
    parameterDigest: text(model.parameter_digest),
    parameterCount: num(model.parameter_count),
    layerCount: num(model.layer_count),
    operators:
      model.operators && typeof model.operators === "object"
        ? (model.operators as Record<string, number>)
        : {},
    inputs: list(model.inputs),
    outputs: list(model.outputs),
    declaredMetadata:
      model.declared_metadata && typeof model.declared_metadata === "object"
        ? (model.declared_metadata as Record<string, unknown>)
        : {},
    unavailableFields: Array.isArray(model.unavailable_fields)
      ? (model.unavailable_fields as string[])
      : [],
    notes: Array.isArray(model.notes) ? (model.notes as string[]) : [],
    path: text(model.path),
  }
}

export interface AccessView {
  mode: string
  capabilities: string[]
  capabilitiesAbsent: string[]
  forcedBlackBox: boolean
  adapter: string
  adapterVersion: string
  runtime: Record<string, unknown>
  consequences: string[]
  /** True when a trusted reference artifact was available to compare against. */
  hasReference: boolean
  reference: Record<string, unknown> | null
}

export function accessView(report: ModelReport | null): AccessView {
  const access = report?.access ?? {}
  return {
    mode: text(access.access_mode, "NOT_ASSESSED"),
    capabilities: access.capabilities ?? [],
    capabilitiesAbsent: access.capabilities_absent ?? [],
    forcedBlackBox: access.forced_black_box === true,
    adapter: text(access.adapter, ""),
    adapterVersion: text(access.adapter_version, ""),
    runtime: access.runtime ?? {},
    consequences: access.consequences ?? [],
    hasReference: report?.reference != null,
    reference: report?.reference ?? null,
  }
}

export interface BackdoorCoverageView {
  entries: { attackClass: string; title: string; coverage: Coverage; reason: string }[]
  benchmarkAvailable: boolean
  benchmarkCoverage: Coverage
  benchmarkReason: string
  probeCount: number | null
  probesByCategory: Record<string, number>
  triggerFamily: Record<string, unknown>[]
}

/**
 * What the build can and cannot say about backdoors, for this model.
 *
 * The brief asks for this to be separate from the findings, and it should be:
 * "no backdoor finding" and "no backdoor detector ran" are opposite statements
 * that a findings list alone renders identically.
 */
export function backdoorCoverage(report: ModelReport | null): BackdoorCoverageView {
  const battery = report?.battery ?? {}
  const benchmark = report?.benchmark ?? {}
  const relevant = new Set(["model_backdoor", "model_trigger", "adaptive_backdoor"])
  return {
    entries: (report?.coverage?.entries ?? [])
      .filter((entry) => relevant.has(entry.attack_class ?? "") || (entry.owning_module ?? 0) === 2)
      .map((entry) => ({
        attackClass: text(entry.attack_class, ""),
        title: text(entry.title, ""),
        coverage: asCoverage(entry.coverage),
        reason: text(entry.reason, ""),
      })),
    benchmarkAvailable: benchmark.available === true,
    benchmarkCoverage: asCoverage(benchmark.coverage),
    benchmarkReason: text(benchmark.reason, ""),
    probeCount: typeof battery.total_probes === "number" ? battery.total_probes : null,
    probesByCategory:
      battery.probes_by_category && typeof battery.probes_by_category === "object"
        ? (battery.probes_by_category as Record<string, number>)
        : {},
    triggerFamily: Array.isArray(battery.trigger_family)
      ? (battery.trigger_family as Record<string, unknown>[])
      : [],
  }
}
