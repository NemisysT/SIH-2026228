/**
 * Projections over Module 4's `PipelineAssuranceReport`.
 *
 * Every function here is a *view* of the report: it selects, orders and
 * relabels, and it never combines two of the engine's numbers into a third.
 * There is no aggregate, no weight and no score in this file, and there is not
 * meant to be one — the engine deliberately has no universal score (§7) and a
 * frontend that invented one would be the single worst thing Module 5 could
 * do.
 */

import {
  asCoverage,
  asDisposition,
  dispositionRank,
  severityRank,
  text,
} from "./format.ts"
import type {
  AssuranceReport,
  CapabilityEntry,
  Coverage,
  CoverageEntry,
  Disposition,
  EvidenceGroup,
  FiredRule,
  Finding,
  FusedEvidence,
  LineageEntry,
  ScopeSummary,
  UnassessedArea,
} from "./types.ts"

/** The four scopes, always in this order, always as four separate rows. */
export const SCOPE_ORDER = ["dataset", "model", "provenance", "distribution"] as const
export type ScopeName = (typeof SCOPE_ORDER)[number]

export interface ScopeView {
  scope: ScopeName
  label: string
  disposition: Disposition
  assessed: boolean
  governingRule: string | null
  statement: string
  findings: number
  supportingEvidence: number
  href: string
}

const SCOPE_LABELS: Record<ScopeName, string> = {
  dataset: "Dataset",
  model: "Model",
  provenance: "Provenance",
  distribution: "Distribution",
}

const SCOPE_HREFS: Record<ScopeName, string> = {
  dataset: "/dataset",
  model: "/model",
  provenance: "/provenance",
  distribution: "/shift",
}

function scopeSummary(report: AssuranceReport, scope: ScopeName): ScopeSummary | null {
  const key = `${scope}_assurance` as
    | "dataset_assurance"
    | "model_assurance"
    | "provenance_assurance"
    | "distribution_assurance"
  return (report[key] ?? null) as ScopeSummary | null
}

/**
 * The four scope rows.
 *
 * A scope the report does not carry is still returned, as NOT_ASSESSED with
 * `assessed: false`. Dropping it would let "we checked and found nothing" and
 * "we checked nothing" render identically, which is the exact confusion the
 * whole architecture exists to prevent.
 */
export function scopeViews(report: AssuranceReport | null): ScopeView[] {
  return SCOPE_ORDER.map((scope) => {
    const summary = report ? scopeSummary(report, scope) : null
    return {
      scope,
      label: SCOPE_LABELS[scope],
      disposition: asDisposition(summary?.disposition),
      assessed: summary?.assessed === true,
      governingRule: summary?.governing_rule ?? null,
      statement: text(
        summary?.statement,
        summary === null
          ? "No input was supplied for this scope, so nothing was assessed."
          : "",
      ),
      findings: summary?.findings ?? 0,
      supportingEvidence: summary?.supporting_evidence ?? 0,
      href: SCOPE_HREFS[scope],
    }
  })
}

/** The top-level disposition, taken from the decision and nowhere else. */
export function disposition(report: AssuranceReport | null): Disposition {
  return asDisposition(report?.decision?.disposition)
}

export interface DecisionView {
  disposition: Disposition
  decisionId: string
  reportId: string
  policyVersion: string
  summary: string
  rationale: string
  scopes: ScopeView[]
  firedRules: FiredRule[]
  /** Every rule that fired, deduplicated by id, strictest first. */
  governingRules: FiredRule[]
  unassessed: UnassessedArea[]
  limitations: string[]
  conflicts: unknown[]
  lineage: LineageEntry[]
  generatedAt: string
}

/**
 * Coerce to an array.
 *
 * A corrupted report can put a string or an object where a list belongs.
 * `?? []` does not catch that — it only catches null — and spreading a string
 * would silently produce one "rule" per character. Every list read out of a
 * report goes through this.
 */
function list<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

export function decisionView(report: AssuranceReport | null): DecisionView {
  const decision = report?.decision ?? {}
  const fired = list<FiredRule>(decision.fired_rules)
  const seen = new Set<string>()
  const governing = [...fired]
    .sort((a, b) => dispositionRank(b.disposition) - dispositionRank(a.disposition))
    .filter((rule) => {
      const id = rule.rule_id ?? ""
      if (seen.has(id)) return false
      seen.add(id)
      return true
    })

  return {
    disposition: disposition(report),
    decisionId: text(decision.decision_id),
    reportId: text(report?.report_id),
    policyVersion: text(decision.policy_version ?? report?.policy?.policy_version),
    summary: text(decision.summary, ""),
    rationale: text(decision.rationale, ""),
    scopes: scopeViews(report),
    firedRules: fired,
    governingRules: governing,
    unassessed: list<UnassessedArea>(decision.unassessed_areas),
    limitations: [...list<string>(decision.limitations), ...list<string>(report?.limitations)],
    conflicts: list<unknown>(decision.conflicts),
    lineage: list<LineageEntry>(decision.lineage),
    generatedAt: text(report?.generated_at),
  }
}

/** Which of the four inputs the run actually received. */
export interface InputsView {
  supplied: { key: string; label: string; supplied: boolean }[]
  missing: string[]
  note: string
}

const INPUT_LABELS: Record<string, string> = {
  dataset: "Dataset report (Module 1)",
  model: "Model report (Module 2)",
  provenance: "Provenance log (Module 3)",
  distribution: "Reference population (Module 4)",
}

export function inputsView(report: AssuranceReport | null): InputsView {
  const raw = report?.inputs?.supplied
  const supplied: Record<string, boolean> =
    raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {}
  const keys = Object.keys(INPUT_LABELS)
  return {
    supplied: keys.map((key) => ({
      key,
      label: INPUT_LABELS[key],
      supplied: supplied[key] === true,
    })),
    missing: list<string>(report?.inputs?.missing),
    note: text(report?.inputs?.note, ""),
  }
}

/**
 * Evidence families, as the engine grouped them.
 *
 * §13: correlated findings must not look like independent attacks. The engine
 * has already done that work — `groups` is its answer and `independent_families`
 * is its count. This function reorders for display and nothing else.
 */
export interface FamilyView {
  family: string
  evidenceClass: string
  detectors: string[]
  evidenceIds: string[]
  findingIds: string[]
  corroboration: number
  maxSeverity: string
  bases: string[]
  supporting: number
  contextOnly: number
  confounded: boolean
  activeConfounders: string[]
  assets: string[]
  contributors: string[]
}

export function familyViews(report: AssuranceReport | null): FamilyView[] {
  const groups = list<EvidenceGroup>(report?.evidence?.groups)
  return groups
    .map((group) => ({
      family: text(group.family, "UNKNOWN"),
      evidenceClass: text(group.evidence_class, ""),
      detectors: list<string>(group.detectors),
      evidenceIds: list<string>(group.evidence_ids),
      findingIds: list<string>(group.finding_ids),
      corroboration: group.corroboration ?? 0,
      maxSeverity: text(group.max_severity, ""),
      bases: list<string>(group.bases),
      supporting: group.supporting ?? 0,
      contextOnly: group.context_only ?? 0,
      confounded: group.confounded === true,
      activeConfounders: list<string>(group.active_confounders),
      assets: list<string>(group.assets),
      contributors: list<string>(group.contributors),
    }))
    .sort((a, b) => severityRank(b.maxSeverity) - severityRank(a.maxSeverity))
}

/** Families the engine judged independent — the ones that may be counted separately. */
export function independentFamilies(report: AssuranceReport | null): string[] {
  const summary = report?.evidence_summary as
    | { independent_families?: string[] }
    | undefined
  return summary?.independent_families ?? []
}

export interface EvidenceView extends FusedEvidence {
  /** The upstream finding, verbatim, when the report still carries it. */
  finding: Finding | null
}

/**
 * Fused evidence joined back to its source finding.
 *
 * The join is the point: §12 says the lineage must survive to the screen, and
 * the report keeps `source_findings` precisely so the original observation is
 * still there to link to.
 */
export function evidenceViews(report: AssuranceReport | null): EvidenceView[] {
  const findings = new Map<string, Finding>()
  for (const finding of list<Finding>(report?.source_findings)) {
    if (finding.finding_id) findings.set(finding.finding_id, finding)
  }
  return list<FusedEvidence>(report?.evidence?.evidence).map((item) => ({
    ...item,
    finding: item.finding_id ? findings.get(item.finding_id) ?? null : null,
  }))
}

export function evidenceById(
  report: AssuranceReport | null,
  evidenceId: string,
): EvidenceView | null {
  return evidenceViews(report).find((item) => item.evidence_id === evidenceId) ?? null
}

/** Severity-first ordering, then confidence. Stable for equal keys. */
export function orderEvidence(items: EvidenceView[]): EvidenceView[] {
  return [...items].sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity)
    if (bySeverity !== 0) return bySeverity
    return (b.confidence ?? 0) - (a.confidence ?? 0)
  })
}

export interface CoverageView {
  attackClass: string
  title: string
  coverage: Coverage
  owningModule: number | null
  detector: string | null
  reason: string
  assumptions: string[]
  limitations: string[]
}

const COVERAGE_DISPLAY_ORDER: Coverage[] = [
  "SUPPORTED",
  "PARTIAL",
  "REQUIRES_WHITE_BOX",
  "NOT_SUPPORTED",
  "NOT_ASSESSED",
]

export function coverageViews(report: AssuranceReport | null): CoverageView[] {
  return list<CoverageEntry>(report?.coverage?.entries)
    .map((entry) => ({
      attackClass: text(entry.attack_class, ""),
      title: text(entry.title, ""),
      coverage: asCoverage(entry.coverage),
      owningModule: entry.owning_module ?? null,
      detector: entry.detector ?? null,
      reason: text(entry.reason, ""),
      assumptions: list<string>(entry.assumptions),
      limitations: list<string>(entry.limitations),
    }))
    .sort((a, b) => {
      const byLevel =
        COVERAGE_DISPLAY_ORDER.indexOf(a.coverage) - COVERAGE_DISPLAY_ORDER.indexOf(b.coverage)
      return byLevel !== 0 ? byLevel : a.attackClass.localeCompare(b.attackClass)
    })
}

/**
 * Coverage counted, not scored.
 *
 * §14: coverage is not security. These are counts of attack classes per
 * coverage level so the UI can say "7 of 17 assessed" — a statement about the
 * assessment, not a percentage of safety. Nothing here is divided by anything.
 */
export function coverageTally(report: AssuranceReport | null): Record<Coverage, number> {
  const tally: Record<Coverage, number> = {
    SUPPORTED: 0,
    PARTIAL: 0,
    NOT_SUPPORTED: 0,
    NOT_ASSESSED: 0,
    REQUIRES_WHITE_BOX: 0,
  }
  for (const entry of coverageViews(report)) tally[entry.coverage] += 1
  return tally
}

export function capabilityViews(report: AssuranceReport | null): CoverageView[] {
  return list<CapabilityEntry>(report?.capabilities?.entries)
    .map((entry) => ({
      attackClass: text(entry.capability, ""),
      title: text(entry.title, ""),
      coverage: asCoverage(entry.coverage),
      owningModule: entry.owning_module ?? null,
      detector: null,
      reason: text(entry.reason ?? entry.detail, ""),
      assumptions: [],
      limitations: list<string>(entry.limitations),
    }))
    .sort(
      (a, b) =>
        COVERAGE_DISPLAY_ORDER.indexOf(a.coverage) - COVERAGE_DISPLAY_ORDER.indexOf(b.coverage),
    )
}

/** Evidence counts the report already computed, read back as-is. */
export interface EvidenceTally {
  total: number
  supporting: number
  contextOnly: number
  confounded: number
  byClass: Record<string, number>
  byBasis: Record<string, number>
  bySeverity: Record<string, number>
  familiesPresent: string[]
  independentFamilies: string[]
  note: string
}

export function evidenceTally(report: AssuranceReport | null): EvidenceTally {
  const summary = (report?.evidence_summary ?? {}) as Record<string, unknown>
  const asRecord = (value: unknown): Record<string, number> =>
    value && typeof value === "object" ? (value as Record<string, number>) : {}
  const asList = (value: unknown): string[] => (Array.isArray(value) ? (value as string[]) : [])
  return {
    total: typeof summary.total === "number" ? summary.total : 0,
    supporting: typeof summary.supporting === "number" ? summary.supporting : 0,
    contextOnly: typeof summary.context_only === "number" ? summary.context_only : 0,
    confounded: typeof summary.confounded === "number" ? summary.confounded : 0,
    byClass: asRecord(summary.by_evidence_class),
    byBasis: asRecord(summary.by_confidence_basis),
    bySeverity: asRecord(summary.by_severity),
    familiesPresent: asList(summary.families_present),
    independentFamilies: asList(summary.independent_families),
    note: text(summary.note, ""),
  }
}
