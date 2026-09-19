/**
 * The Overview dashboard's view model.
 *
 * Kept out of the page component so it can be tested without React (§32) and
 * so the one rule that matters is enforceable in one place: every number here
 * is copied from a report, and none is derived by combining two others.
 */

import {
  count,
  humanise,
  shortDigest,
  text,
  titleise,
  confidence as formatConfidence,
} from "./format.ts"
import {
  coverageTally,
  coverageViews,
  decisionView,
  evidenceTally,
  evidenceViews,
  inputsView,
  orderEvidence,
  scopeViews,
  type ScopeView,
} from "./assurance.ts"
import { shiftView } from "./shift.ts"
import { levelViews, accessView } from "./model.ts"
import { linkSuffix } from "./page-data.ts"
import type { ScenarioBundle } from "./source.ts"
import type { SourceKind } from "./types.ts"

export interface OverviewModel {
  hero: {
    eyebrow: string
    lead: string
    disposition: string
    statement: string
    stats: { value: string; label: string }[]
  }
  scopes: {
    disposition: string
    summary: string
    reportId: string
    policyVersion: string
    cards: (ScopeView & { href: string })[]
  }
  pipeline: {
    number: string
    title: string
    subtitle: string
    description: string
    status: string
    href: string
  }[]
  shift: {
    verdict: string
    statement: string
    headlineValue: string
    headlineUnit: string
    headlineNote: string
    stats: { value: string; label: string }[]
    rows: { name: string; status: string; detail: string }[]
  } | null
  evidence: {
    metrics: { value: number; suffix?: string; prefix?: string; label: string; sublabel: string }[]
    families: string[]
    note: string
  }
  coverage: {
    cards: { attackClass: string; title: string; coverage: string; reason: string; module: number | null }[]
    counts: { value: string; label: string }[]
    lede: string
  }
  model: {
    levels: { title: string; status: string; detail: string; assessed: boolean }[]
    headline: string
    headlineLabel: string
    accessMode: string
    coverageChips: string[]
    lede: string
  }
  why: {
    disposition: string
    rationale: string
    reasons: { title: string; description: string }[]
  }
  findings: {
    findingId: string
    statement: string
    title: string
    detector: string
    module: string
    severity: string
    confidence: string
    basis: string
    attackClass: string
  }[]
  suffix: string
}

/** The highest-signal findings, for the carousel. Ordered, never summarised. */
const HEADLINE_FINDING_LIMIT = 6

export function buildOverview(
  bundle: ScenarioBundle | null,
  source: SourceKind,
): OverviewModel {
  const assurance = bundle?.assurance ?? null
  const decision = decisionView(assurance)
  const scopes = scopeViews(assurance)
  const inputs = inputsView(assurance)
  const tally = evidenceTally(assurance)
  const coverage = coverageViews(assurance)
  const coverageCounts = coverageTally(assurance)
  const shift = shiftView(bundle?.shift ?? assurance?.distribution_shift ?? null)
  const suffix = linkSuffix(source, bundle?.scenario.name)

  const modelLevels = levelViews(bundle?.model ?? null)
  const access = accessView(bundle?.model ?? null)

  const evidence = orderEvidence(evidenceViews(assurance))
  const headline = evidence.slice(0, HEADLINE_FINDING_LIMIT).map((item) => ({
    findingId: text(item.finding_id, "—"),
    statement: text(
      item.finding?.evidence?.[0]?.statement ?? item.title,
      "The detector recorded no statement for this finding.",
    ),
    title: text(item.title, ""),
    detector: text(item.source_detector, ""),
    module: item.source_module ? `M${item.source_module}` : "—",
    severity: text(item.severity, "NO SEVERITY"),
    confidence: formatConfidence(item.confidence),
    basis: text(item.confidence_basis, "basis not recorded"),
    attackClass: humanise(item.attack_class),
  }))

  return {
    hero: {
      eyebrow: "SIH26228 · Trustworthy CV integrity assurance",
      lead: "The pipeline is",
      disposition: decision.disposition,
      statement:
        decision.summary ||
        "No assurance decision is available for this selection.",
      stats: [
        { value: text(decision.reportId, "—"), label: "assurance report" },
        { value: text(decision.policyVersion, "—"), label: "policy version" },
        {
          value: `${inputs.supplied.filter((input) => input.supplied).length}/4`,
          label: "inputs supplied to the run",
        },
        { value: count(tally.total), label: "evidence items carried" },
      ],
    },
    scopes: {
      disposition: decision.disposition,
      summary: decision.summary || decision.rationale,
      reportId: text(decision.reportId, "—"),
      policyVersion: text(decision.policyVersion, "—"),
      cards: scopes.map((scope) => ({ ...scope, href: `${scope.href}${suffix}` })),
    },
    pipeline: [
      {
        number: "01",
        title: "Dataset",
        subtitle: "Module 1",
        description: describeScope(scopes[0], bundle?.dataset != null),
        status: scopes[0].disposition,
        href: `/dataset${suffix}`,
      },
      {
        number: "02",
        title: "Model",
        subtitle: "Module 2",
        description: describeScope(scopes[1], bundle?.model != null),
        status: scopes[1].disposition,
        href: `/model${suffix}`,
      },
      {
        number: "03",
        title: "Provenance",
        subtitle: "Module 3",
        description: describeScope(scopes[2], bundle?.provenance != null),
        status: scopes[2].disposition,
        href: `/provenance${suffix}`,
      },
      {
        number: "04",
        title: "Shift & fusion",
        subtitle: "Module 4",
        description: describeScope(scopes[3], shift != null),
        status: scopes[3].disposition,
        href: `/shift${suffix}`,
      },
    ],
    shift: shift
      ? {
          verdict: humanise(shift.verdict).toLowerCase(),
          statement: shift.statement,
          headlineValue: count(shift.current?.sampleCount ?? null),
          headlineUnit: "samples assessed",
          headlineNote: `Compared against a ${count(
            shift.reference?.sampleCount ?? null,
          )}-sample reference population (${shift.reference?.trust ?? "UNKNOWN"} trust). ${
            shift.reference?.caveat ?? ""
          }`,
          stats: [
            {
              value: `${shift.significantMetrics.length}/${shift.metrics.length}`,
              label: "selected metrics reaching significance",
            },
            {
              value: humanise(shift.context?.explanation ?? "NOT_ASSESSED"),
              label: "operational-context explanation",
            },
          ],
          rows: shift.metrics.slice(0, 8).map((metric) => ({
            name: humanise(metric.metric),
            status: metric.ran ? metric.status : "DID NOT RUN",
            detail: metric.ran
              ? `statistic ${metric.statistic} · p ${metric.pValue}`
              : metric.reason || "the metric declined to run",
          })),
        }
      : null,
    evidence: {
      metrics: [
        {
          value: tally.total,
          label: "Evidence items carried into the decision",
          sublabel: `${tally.supporting} supporting · ${tally.contextOnly} context only`,
        },
        {
          value: tally.confounded,
          label: "Items with an active confounder",
          sublabel: "correlated, so not counted again",
        },
        {
          value: tally.independentFamilies.length,
          label: "Independent phenomena",
          sublabel: `${tally.familiesPresent.length} families present`,
        },
      ],
      families: tally.independentFamilies,
      note:
        tally.note ||
        "Evidence is grouped into families before it is counted, so that several detectors observing one phenomenon do not read as several independent attacks.",
    },
    coverage: {
      cards: coverage.slice(0, 12).map((entry) => ({
        attackClass: entry.attackClass,
        title: entry.title,
        coverage: entry.coverage,
        reason: entry.reason,
        module: entry.owningModule,
      })),
      counts: [
        { value: String(coverageCounts.SUPPORTED), label: "classes supported" },
        { value: String(coverageCounts.PARTIAL), label: "partial" },
        { value: String(coverageCounts.NOT_ASSESSED), label: "not assessed in this run" },
      ],
      lede:
        "Each attack class carries the coverage its detector claimed for this run, and the reason. A class nothing reported on is NOT_ASSESSED — which is a statement about the assessment, not a clean bill of health.",
    },
    model: {
      levels: modelLevels.map((level) => ({
        title: level.title,
        status: level.status,
        detail: level.detail || level.reason || "No detail was recorded for this level.",
        assessed: level.assessed,
      })),
      headline: text(scopes[1].disposition, "NOT_ASSESSED"),
      headlineLabel: scopes[1].assessed
        ? "model scope disposition"
        : "no model artifact was supplied to this run",
      accessMode: access.mode,
      coverageChips: modelLevels.map((level) => `${level.title}: ${level.status}`),
      lede:
        "Module 2 answers six questions about the artifact and keeps the answers apart. A model can be structurally identical to its reference and still behave differently, so identity, structure, parameters, behaviour, activation and trigger each get their own verdict.",
    },
    why: {
      disposition: decision.disposition,
      rationale:
        decision.rationale ||
        decision.summary ||
        "No rationale was recorded for this decision.",
      reasons: decision.governingRules.slice(0, 4).map((rule) => ({
        title: text(rule.rule_id, "—"),
        description: text(rule.statement ?? rule.rationale, ""),
      })),
    },
    findings: headline,
    suffix,
  }
}

function describeScope(scope: ScopeView, hasReport: boolean): string {
  if (!scope.assessed || !hasReport) {
    return (
      scope.statement ||
      "No input was supplied for this scope, so nothing was assessed. That is different from finding nothing."
    )
  }
  return scope.statement
}

/** The featured scenarios, as cards for the demo section. */
export function scenarioCards(
  rows: {
    name: string
    status: string
    featured?: boolean
    observed_disposition?: string | null
    note?: string
    reason?: string | null
    summary?: { fired_rules?: string[]; evidence_total?: number; independent_families?: string[]; inputs_supplied?: Record<string, boolean> }
  }[],
  source: SourceKind,
  limit = 3,
): {
  name: string
  label: string
  description: string
  disposition: string
  status: string
  facts: string[]
  href: string
  highlight: boolean
}[] {
  const featured = rows.filter((row) => row.featured)
  const chosen = (featured.length > 0 ? featured : rows).slice(0, limit)
  return chosen.map((row, index) => {
    const summary = row.summary ?? {}
    const supplied = Object.entries(summary.inputs_supplied ?? {})
      .filter(([, value]) => value)
      .map(([key]) => key)
    return {
      name: row.name,
      label: titleise(row.name),
      description: row.status === "RUN" ? text(row.note, "") : text(row.reason, ""),
      disposition: text(row.observed_disposition, "NOT_ASSESSED"),
      status: row.status,
      facts: [
        `${supplied.length} of 4 inputs supplied${supplied.length ? `: ${supplied.join(", ")}` : ""}`,
        `${summary.evidence_total ?? 0} evidence item(s)`,
        `${(summary.independent_families ?? []).length} independent phenomenon/phenomena`,
        `rules: ${(summary.fired_rules ?? []).join(", ") || "none fired"}`,
      ],
      href: `/demo${linkSuffix(source, row.name)}`,
      highlight: index === 1 && chosen.length > 1,
    }
  })
}

export { shortDigest }
