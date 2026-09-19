/**
 * Build the Evidence Explorer's view model.
 *
 * Pure, so the lineage guarantees §12 asks for can be tested directly: an
 * evidence item's basis, coverage and confounders must arrive at the screen
 * exactly as the engine recorded them.
 */

import { confidence as formatConfidence, text } from "./format.ts"
import { evidenceViews, familyViews, decisionView } from "./assurance.ts"
import type { AssuranceReport } from "./types.ts"

export interface ExplorerRule {
  ruleId: string
  scope: string
  disposition: string
  statement: string
  rationale: string
  families: string[]
  evidenceIds: string[]
  observation: Record<string, unknown>
}

export interface ExplorerEvidence {
  evidenceId: string
  findingId: string
  title: string
  module: number | null
  detector: string
  detectorVersion: string
  evidenceClass: string
  attackClass: string
  dependencyGroup: string
  severity: string
  confidence: string
  basis: string
  coverage: string
  supports: boolean
  supportReason: string
  confoundedBy: string[]
  activeConfounders: string[]
  assumptions: string[]
  limitations: string[]
  rawObservation: Record<string, unknown>
  sourceReportId: string
  sourceRunId: string
  refs: string[]
  assetId: string
  assetLocator: string
  contributor: string
  findingStatements: string[]
}

export interface ExplorerFamily {
  family: string
  evidenceClass: string
  detectors: string[]
  evidenceIds: string[]
  corroboration: number
  maxSeverity: string
  supporting: number
  contextOnly: number
  confounded: boolean
  activeConfounders: string[]
  independent: boolean
}

export interface ExplorerModel {
  disposition: string
  decisionId: string
  summary: string
  rules: ExplorerRule[]
  evidence: ExplorerEvidence[]
  families: ExplorerFamily[]
}

export function buildExplorer(report: AssuranceReport | null): ExplorerModel {
  const decision = decisionView(report)
  const independent = new Set(
    ((report?.evidence_summary as { independent_families?: string[] } | undefined)
      ?.independent_families ?? []) as string[],
  )

  return {
    disposition: decision.disposition,
    decisionId: text(decision.decisionId),
    summary: decision.summary || decision.rationale,
    rules: (report?.decision?.fired_rules ?? []).map((rule) => ({
      ruleId: text(rule.rule_id, "—"),
      scope: text(rule.scope, "—"),
      disposition: text(rule.disposition, "—"),
      statement: text(rule.statement, ""),
      rationale: text(rule.rationale, ""),
      families: rule.families ?? [],
      evidenceIds: rule.evidence_ids ?? [],
      observation: rule.observation ?? {},
    })),
    // Every item, in report order. The explorer's whole purpose is that
    // nothing was dropped on the way here.
    evidence: evidenceViews(report).map((item) => ({
      evidenceId: text(item.evidence_id, "—"),
      findingId: text(item.finding_id, "—"),
      title: text(item.title, "Untitled evidence"),
      module: item.source_module ?? null,
      detector: text(item.source_detector, "—"),
      detectorVersion: text(item.source_detector_version, ""),
      evidenceClass: text(item.evidence_class, "—"),
      attackClass: text(item.attack_class, "—"),
      dependencyGroup: text(item.dependency_group, "—"),
      severity: text(item.severity, "NO SEVERITY"),
      confidence: formatConfidence(item.confidence),
      // The basis travels with the number, always. A 0.62 with no basis reads
      // as a probability of compromise, and it is not one.
      basis: text(item.confidence_basis, "basis not recorded"),
      coverage: text(item.coverage, "NOT_ASSESSED"),
      supports: item.supports === true,
      supportReason: text(item.support_reason, ""),
      confoundedBy: item.confounded_by ?? [],
      activeConfounders: item.active_confounders ?? [],
      assumptions: item.assumptions ?? [],
      limitations: item.limitations ?? [],
      rawObservation: item.raw_observation ?? {},
      sourceReportId: text(item.lineage?.source_report_id, "—"),
      sourceRunId: text(item.lineage?.source_run_id, "—"),
      refs: item.lineage?.refs ?? [],
      assetId: text(item.asset?.id, "—"),
      assetLocator: text(item.asset?.locator, ""),
      contributor: text(item.contributor, "—"),
      findingStatements: (item.finding?.evidence ?? [])
        .map((evidence) => text(evidence.statement, ""))
        .filter((statement) => statement.length > 0),
    })),
    families: familyViews(report).map((family) => ({
      family: family.family,
      evidenceClass: family.evidenceClass,
      detectors: family.detectors,
      evidenceIds: family.evidenceIds,
      corroboration: family.corroboration,
      maxSeverity: family.maxSeverity || "—",
      supporting: family.supporting,
      contextOnly: family.contextOnly,
      confounded: family.confounded,
      activeConfounders: family.activeConfounders,
      independent: independent.has(family.family),
    })),
  }
}
