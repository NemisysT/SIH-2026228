/**
 * Projections over Module 1's dataset report.
 *
 * No detection happens here (§8): the frontend consumes what the dataset
 * detectors wrote. The functions below select and order; the findings
 * themselves are passed through unchanged, evidence and all.
 */

import { asCoverage, asSeverity, severityRank, text } from "./format.ts"
import type { Coverage, DatasetReport, Finding, Severity } from "./types.ts"

export interface DatasetIdentity {
  root: string
  manifestId: string
  digest: string
  adapter: string
  task: string
  samples: number | null
  readable: number | null
  unreadable: number | null
  annotations: number | null
  classes: string[]
  contributorCount: number | null
  ingestIssues: number | null
  attribution: Record<string, unknown>
  featureSpace: Record<string, unknown>
  calibrationStatus: string
}

export function datasetIdentity(report: DatasetReport | null): DatasetIdentity | null {
  if (!report?.dataset) return null
  const dataset = report.dataset
  const counts = dataset.counts ?? {}
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  return {
    root: text(dataset.root),
    manifestId: text(dataset.manifest_id),
    digest: text(dataset.digest),
    adapter: text(dataset.adapter),
    task: text(dataset.task),
    samples: num(counts.samples),
    readable: num(counts.readable),
    unreadable: num(counts.unreadable),
    annotations: num(counts.annotations),
    classes: dataset.classes ?? [],
    contributorCount: num(counts.contributors),
    ingestIssues: num(counts.ingest_issues),
    attribution: dataset.attribution ?? {},
    featureSpace: report.feature_space ?? {},
    calibrationStatus: text((report.calibration ?? {}).status, "NOT_SUPPLIED"),
  }
}

export interface ContributorRow {
  contributor: string
  samples: number | null
  flagged: number | null
  rate: number | null
  cohortRate: number | null
  rateRatio: number | null
  pValue: number | null
  qValue: number | null
  significant: boolean
  attackClass: string
  maxChildSeverity: Severity | null
  meanChildConfidence: number | null
  /** Per-contributor counts from the manifest, when the adapter recorded them. */
  manifest: Record<string, unknown>
}

/**
 * One row per contributor, joining the manifest's census to the risk table.
 *
 * A contributor that appears in the manifest but not in `contributor_risk` is
 * still listed — with nothing flagged. Showing only flagged contributors would
 * make the distribution unreadable, and the denominator is the whole point of a
 * multi-contributor pipeline.
 */
export function contributorRows(report: DatasetReport | null): ContributorRow[] {
  const manifest = report?.dataset?.contributors ?? {}
  const risk = report?.contributor_risk ?? []
  const byName = new Map<string, Record<string, unknown>>()
  for (const entry of risk) {
    const name = typeof entry.contributor === "string" ? entry.contributor : ""
    if (name) byName.set(name, entry)
  }
  const names = new Set<string>([...Object.keys(manifest), ...byName.keys()])
  const num = (value: unknown) => (typeof value === "number" ? value : null)

  return [...names]
    .sort()
    .map((contributor) => {
      const entry = byName.get(contributor) ?? {}
      const census = manifest[contributor] ?? {}
      return {
        contributor,
        samples: num(entry.samples) ?? num((census as Record<string, unknown>).samples),
        flagged: num(entry.flagged) ?? 0,
        rate: num(entry.rate),
        cohortRate: num(entry.cohort_rate),
        rateRatio: num(entry.rate_ratio),
        pValue: num(entry.p_value),
        qValue: num(entry.q_value),
        significant: entry.significant === true,
        attackClass: text(entry.attack_class, ""),
        maxChildSeverity: asSeverity(entry.max_child_severity),
        meanChildConfidence: num(entry.mean_child_confidence),
        manifest: census as Record<string, unknown>,
      }
    })
    .sort((a, b) => (b.flagged ?? 0) - (a.flagged ?? 0) || a.contributor.localeCompare(b.contributor))
}

export interface DetectorRow {
  name: string
  version: string
  findings: number
  stats: Record<string, unknown>
}

export function detectorRows(
  report: { detectors?: { name?: string; version?: string; findings?: number; stats?: Record<string, unknown> }[] } | null,
): DetectorRow[] {
  return (report?.detectors ?? []).map((detector) => ({
    name: text(detector.name, ""),
    version: text(detector.version, ""),
    findings: detector.findings ?? 0,
    stats: detector.stats ?? {},
  }))
}

export interface FindingGroup {
  attackClass: string
  findings: Finding[]
  maxSeverity: Severity | null
  coverage: Coverage
}

/**
 * Findings grouped by attack class, strongest class first.
 *
 * Grouping by attack class rather than by severity is what stops 41 OOD flags
 * from reading as 41 separate problems. It is presentation only; the finding
 * objects are untouched.
 */
export function findingsByAttackClass(findings: Finding[]): FindingGroup[] {
  const groups = new Map<string, Finding[]>()
  for (const finding of findings) {
    const key = text(finding.attack_class, "unclassified")
    const bucket = groups.get(key)
    if (bucket) bucket.push(finding)
    else groups.set(key, [finding])
  }
  return [...groups.entries()]
    .map(([attackClass, items]) => {
      const sorted = [...items].sort(
        (a, b) =>
          severityRank(b.severity) - severityRank(a.severity) ||
          (b.confidence ?? 0) - (a.confidence ?? 0),
      )
      return {
        attackClass,
        findings: sorted,
        maxSeverity: asSeverity(sorted[0]?.severity),
        coverage: asCoverage(sorted[0]?.coverage),
      }
    })
    .sort(
      (a, b) =>
        severityRank(b.maxSeverity) - severityRank(a.maxSeverity) ||
        b.findings.length - a.findings.length,
    )
}

export interface SummaryCounts {
  overall: string
  rationale: string
  total: number
  bySeverity: Record<string, number>
  byDisposition: Record<string, number>
  byAttackClass: Record<string, number>
  assetsAffected: number | null
  contributorsAffected: number | null
}

export function summaryCounts(report: DatasetReport | null): SummaryCounts {
  const summary = report?.summary ?? {}
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  return {
    overall: text(summary.overall, "NOT ASSESSED"),
    rationale: text(summary.rationale, ""),
    total: summary.findings_total ?? 0,
    bySeverity: summary.by_severity ?? {},
    byDisposition: summary.by_disposition ?? {},
    byAttackClass: summary.by_attack_class ?? {},
    assetsAffected: num(summary.assets_affected),
    contributorsAffected: num(summary.contributors_affected),
  }
}
