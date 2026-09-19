/**
 * Projections over Module 4's distribution-shift assessment.
 *
 * §11's requirement is a framing one, and it is carried by `shiftView.verdict`
 * plus `contextExplanation`: a shift that the declared operating context
 * predicts is an observation, not an accusation. This file never maps a
 * verdict to the word "attack". Whether independent evidence exists is the
 * policy engine's call, and it lives in the decision, not here.
 */

import { pValue as formatP, statistic as formatStat, text } from "./format.ts"
import type { ShiftAssessment, ShiftMetric } from "./types.ts"

export interface PopulationView {
  label: string
  id: string
  digest: string
  sampleCount: number | null
  locator: string
  classes: Record<string, number>
  contributors: Record<string, number>
  /** Reference only: how the corpus was obtained, recorded verbatim. */
  provenance: string
  /** Reference only: UNKNOWN | ASSERTED_BY_OPERATOR | ASSESSED_CLEAN. */
  trust: string
  mode: string
  caveat: string
}

function record(value: unknown): Record<string, number> {
  return value && typeof value === "object" ? (value as Record<string, number>) : {}
}

export function referenceView(assessment: ShiftAssessment | null): PopulationView | null {
  const reference = assessment?.reference
  if (!reference) return null
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  return {
    label: "Reference population",
    id: text(reference.reference_id ?? reference.manifest_id),
    digest: text(reference.digest ?? reference.manifest_digest),
    sampleCount: num(reference.sample_count),
    locator: text(reference.locator),
    classes: {},
    contributors: {},
    provenance: text(reference.provenance, "not declared"),
    trust: text(reference.trust, "UNKNOWN"),
    mode: text(reference.mode),
    caveat: text(reference.caveat, ""),
  }
}

export function currentView(assessment: ShiftAssessment | null): PopulationView | null {
  const current = assessment?.current
  if (!current) return null
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  return {
    label: "Current population",
    id: text(current.manifest_id ?? current.name),
    digest: text(current.digest),
    sampleCount: num(current.sample_count),
    locator: text(current.root),
    classes: record(current.classes),
    contributors: record(current.contributors),
    provenance: "",
    trust: "",
    mode: "",
    caveat: "",
  }
}

export interface MetricView {
  metric: string
  version: string
  status: string
  statistic: string
  pValue: string
  significant: boolean
  interpretation: string
  reason: string
  /** True when the metric did not run — insufficient samples, usually. */
  ran: boolean
  requirement: Record<string, unknown>
  observation: Record<string, unknown>
}

/**
 * Selected metrics, run and not-run alike.
 *
 * A metric that declined to run because the current batch was too small is the
 * most informative row on the page, so it is never filtered out; it is marked
 * `ran: false` and carries the engine's reason.
 */
export function metricViews(assessment: ShiftAssessment | null): MetricView[] {
  return (assessment?.metrics ?? []).map((metric: ShiftMetric) => {
    const ran = typeof metric.statistic === "number"
    return {
      metric: text(metric.metric, ""),
      version: text(metric.version, ""),
      status: text(metric.status, "NOT_ASSESSED"),
      statistic: ran ? formatStat(metric.statistic) : "—",
      pValue: ran ? formatP(metric.p_value) : "—",
      significant: metric.significant === true,
      interpretation: text(metric.interpretation, ""),
      reason: text(metric.reason, ""),
      ran,
      requirement: metric.requirement ?? {},
      observation: metric.observation ?? {},
    }
  })
}

export interface ContextView {
  explanation: string
  statement: string
  changed: string[]
  unchanged: string[]
  declaredOnOneSideOnly: string[]
  explainedBlocks: string[]
  movedBlocks: string[]
  unexplainedBlocks: string[]
  declarationValidated: boolean
  note: string
  limitations: string[]
  referenceDeclared: Record<string, unknown>
  currentDeclared: Record<string, unknown>
}

export function contextView(assessment: ShiftAssessment | null): ContextView | null {
  const context = assessment?.context
  if (!context) return null
  const declared = (assessment?.declared_context ?? {}) as Record<string, unknown>
  const delta = (context.delta ?? {}) as Record<string, unknown>
  const list = (value: unknown) => (Array.isArray(value) ? (value as string[]) : [])
  const obj = (value: unknown) =>
    value && typeof value === "object" ? (value as Record<string, unknown>) : {}
  return {
    explanation: text(context.explanation, "NOT_ASSESSED"),
    statement: text(context.statement, ""),
    changed: list(delta.changed),
    unchanged: list(delta.unchanged),
    declaredOnOneSideOnly: list(delta.declared_only_on_one_side),
    explainedBlocks: list(context.explained_blocks),
    movedBlocks: list(context.moved_blocks),
    unexplainedBlocks: list(context.unexplained_blocks),
    declarationValidated: declared.validated === true,
    note: text(declared.note, ""),
    limitations: list(context.limitations),
    referenceDeclared: obj(declared.reference),
    currentDeclared: obj(declared.current),
  }
}

export interface ShiftView {
  assessmentId: string
  verdict: string
  statement: string
  metricVersion: string
  reference: PopulationView | null
  current: PopulationView | null
  metrics: MetricView[]
  context: ContextView | null
  assumptions: string[]
  limitations: string[]
  unassessed: unknown[]
  /** Metrics that ran and reached significance, for the headline row. */
  significantMetrics: MetricView[]
  /** Metrics that declined to run, with the reason. */
  unrunMetrics: MetricView[]
}

export function shiftView(assessment: ShiftAssessment | null): ShiftView | null {
  if (!assessment) return null
  const metrics = metricViews(assessment)
  return {
    assessmentId: text(assessment.assessment_id),
    verdict: text(assessment.verdict, "NOT_ASSESSED"),
    statement: text(assessment.statement, ""),
    metricVersion: text(assessment.metric_version, ""),
    reference: referenceView(assessment),
    current: currentView(assessment),
    metrics,
    context: contextView(assessment),
    assumptions: assessment.assumptions ?? [],
    limitations: assessment.limitations ?? [],
    unassessed: assessment.unassessed ?? [],
    significantMetrics: metrics.filter((metric) => metric.ran && metric.significant),
    unrunMetrics: metrics.filter((metric) => !metric.ran),
  }
}

/**
 * Per-sample OOD findings, which are a different claim from population shift.
 *
 * §11 asks for the distinction to be visible, so the shift page shows the OOD
 * count next to the population verdict and says what each one means. The count
 * comes from Module 1's findings, untouched.
 */
export function oodFindingCount(findings: { attack_class?: string }[] | undefined): number {
  return (findings ?? []).filter((finding) => finding.attack_class === "ood_insertion").length
}
