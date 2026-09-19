import Link from "next/link"

import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import {
  CheckMark,
  CoverageBadge,
  DispositionBadge,
  EmptyState,
  Eyebrow,
  Field,
  FieldGrid,
  NoteList,
  Panel,
  SectionTitle,
  SeverityBadge,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import {
  decisionView,
  evidenceTally,
  inputsView,
  scopeViews,
} from "@/lib/analyst/assurance"
import { count, humanise, text, timestamp } from "@/lib/analyst/format"
import { artifactHref } from "@/lib/analyst/links"
import { linkSuffix, loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import type { UnassessedArea } from "@/lib/analyst/types"

export const dynamic = "force-dynamic"

/**
 * Assurance Decision (§15).
 *
 * The structure the brief specifies — disposition, why, what was assessed,
 * what was not, supporting evidence, limitations, policy — built entirely out
 * of the Module 4 report. Every sentence of explanation on this page is a
 * string the engine wrote; none is composed by the frontend.
 */
export default async function DecisionPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.assurance ?? null
  const decision = decisionView(report)
  const scopes = scopeViews(report)
  const inputs = inputsView(report)
  const tally = evidenceTally(report)
  const suffix = linkSuffix(data.source, data.scenario?.name)
  const coverageSummary = (report?.decision?.coverage_summary ?? {}) as Record<string, unknown>
  const severitySummary = (report?.decision?.severity_summary ?? {}) as Record<string, unknown>
  const confidenceSummary = (report?.decision?.confidence_summary ?? {}) as Record<string, unknown>
  const policy = report?.policy ?? {}

  const unassessedColumns: Column<UnassessedArea>[] = [
    { key: "area", header: "Area", render: (row) => <span className="font-mono text-xs">{text(row.area)}</span> },
    { key: "kind", header: "Kind", render: (row) => <Tag>{text(row.kind)}</Tag> },
    { key: "reason", header: "Why it was not assessed", render: (row) => <span className="text-sm text-muted-foreground">{text(row.reason)}</span> },
    { key: "remedy", header: "What would assess it", render: (row) => <span className="text-sm font-mono text-muted-foreground break-all">{text(row.remedy)}</span> },
  ]

  return (
    <PageShell
      data={data}
      eyebrow="Assurance decision"
      title={
        <>
          <span className="block">{decision.disposition}</span>
          <span className="block text-white/40">and the reasons for it.</span>
        </>
      }
      lede="Four scopes, one policy, no score. The disposition below is the strictest scope result the rule table produced — not an average, not a weighting, and not a judgement the frontend made."
      stats={[
        { value: decision.decisionId, label: "decision id" },
        { value: decision.policyVersion, label: "policy version" },
        { value: count(decision.governingRules.length), label: "distinct rules fired" },
        { value: count(decision.unassessed.length), label: "areas not assessed" },
      ]}
    >
      {!report ? (
        <Section>
          <EmptyState
            title="No assurance decision for this selection"
            reason="Without a Module 4 report there is no decision, no policy trace and no evidence to show."
          />
        </Section>
      ) : (
        <>
          <Section>
            <Panel className="p-8 lg:p-12 mb-6">
              <div className="flex flex-wrap items-center gap-5 mb-8">
                <DispositionBadge value={decision.disposition} size="lg" />
                <span className="font-mono text-xs text-muted-foreground">
                  {decision.reportId} · generated {timestamp(decision.generatedAt)}
                </span>
              </div>
              <p className="text-xl lg:text-2xl font-display leading-snug max-w-4xl mb-6">
                {decision.summary}
              </p>
              {decision.rationale && decision.rationale !== decision.summary ? (
                <p className="text-muted-foreground leading-relaxed max-w-4xl">
                  {decision.rationale}
                </p>
              ) : null}
            </Panel>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {scopes.map((scope) => (
                <Panel key={scope.scope} className="p-6 flex flex-col">
                  <div className="flex items-center justify-between gap-3 mb-4">
                    <h3 className="text-xl font-display">{scope.label}</h3>
                    <Tag active={!scope.assessed}>{scope.assessed ? "assessed" : "not assessed"}</Tag>
                  </div>
                  <DispositionBadge value={scope.disposition} />
                  <p className="mt-4 text-sm text-muted-foreground leading-relaxed flex-1">
                    {scope.statement}
                  </p>
                  <div className="mt-6 flex items-center justify-between text-xs font-mono text-muted-foreground">
                    <span>{scope.governingRule ?? "no rule"}</span>
                    <Link href={`${scope.href}${suffix}`} className="hover:text-foreground transition-colors">
                      open &rarr;
                    </Link>
                  </div>
                </Panel>
              ))}
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Why</Eyebrow>
              <SectionTitle lead="The rules" trail="that fired." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                Each rule below is reproduced from the policy table the engine executed, with the
                evidence it named. An ACCEPT rule that fired is bookkeeping; a rule carrying
                anything stricter is what moved the outcome.
              </p>
            </div>

            {decision.firedRules.length === 0 ? (
              <EmptyState
                title="No rule fired"
                reason="Nothing was supplied for any rule to match against, so the decision is NOT_ASSESSED rather than ACCEPT. The system will not treat an absence of input as an absence of risk."
              />
            ) : (
              <div className="space-y-4">
                {decision.firedRules.map((rule, index) => (
                  <Panel key={`${rule.rule_id}-${rule.scope}-${index}`} className="p-6 lg:p-8">
                    <div className="flex flex-wrap items-center gap-3 mb-4">
                      <span className="text-xl font-display">{text(rule.rule_id)}</span>
                      <DispositionBadge value={rule.disposition} />
                      <Tag>scope {text(rule.scope)}</Tag>
                      {(rule.families ?? []).map((family) => (
                        <Tag key={family}>{family}</Tag>
                      ))}
                    </div>
                    <p className="text-base leading-relaxed mb-3">{text(rule.statement, "")}</p>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {text(rule.rationale, "")}
                    </p>
                    <div className="mt-5 flex flex-wrap gap-4 text-xs font-mono text-muted-foreground">
                      <span>{(rule.evidence_ids ?? []).length} evidence item(s)</span>
                      <span>{(rule.finding_ids ?? []).length} finding(s)</span>
                      <Link
                        href={`/evidence${suffix}`}
                        className="hover:text-foreground transition-colors underline underline-offset-4"
                      >
                        trace this rule in the evidence explorer &rarr;
                      </Link>
                    </div>
                    {rule.observation && Object.keys(rule.observation).length > 0 ? (
                      <pre className="mt-5 text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-4 overflow-x-auto max-h-56">
                        {JSON.stringify(rule.observation, null, 2)}
                      </pre>
                    ) : null}
                  </Panel>
                ))}
              </div>
            )}
          </Section>

          <Section>
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel className="p-8">
                <Eyebrow>What was assessed</Eyebrow>
                <div className="mt-8 space-y-3">
                  {inputs.supplied.map((input) => (
                    <div key={input.key} className="flex items-center gap-3">
                      <CheckMark state={input.supplied ? "PASS" : "NEUTRAL"} />
                      <span className={input.supplied ? "" : "text-muted-foreground"}>
                        {input.label}
                      </span>
                      <span className="ml-auto text-xs font-mono text-muted-foreground">
                        {input.supplied ? "supplied" : "not supplied"}
                      </span>
                    </div>
                  ))}
                </div>
                <FieldGrid columns={2}>
                  <Field
                    label="Attack classes assessed"
                    value={`${count(coverageSummary.attack_classes_assessed)} of ${count(
                      coverageSummary.attack_classes_total,
                    )}`}
                  />
                  <Field
                    label="Scopes assessed"
                    value={
                      Array.isArray(coverageSummary.scopes_assessed)
                        ? (coverageSummary.scopes_assessed as string[]).join(", ") || "none"
                        : "—"
                    }
                    mono
                  />
                </FieldGrid>
                {inputs.note ? (
                  <p className="mt-6 text-sm text-muted-foreground leading-relaxed">{inputs.note}</p>
                ) : null}
              </Panel>

              <Panel className="p-8">
                <Eyebrow>What was not assessed</Eyebrow>
                <p className="mt-8 text-sm text-muted-foreground leading-relaxed">
                  {text(coverageSummary.note, "")}
                </p>
                <div className="mt-6 flex flex-wrap gap-2">
                  {(Array.isArray(coverageSummary.not_assessed)
                    ? (coverageSummary.not_assessed as string[])
                    : []
                  ).map((item) => (
                    <Tag key={item}>{humanise(item)}</Tag>
                  ))}
                </div>
                <div className="mt-8 flex flex-wrap gap-4">
                  <Stat value={count(decision.unassessed.length)} label="Unassessed areas" />
                  <Stat
                    value={
                      Array.isArray(coverageSummary.scopes_not_assessed)
                        ? String((coverageSummary.scopes_not_assessed as string[]).length)
                        : "—"
                    }
                    label="Scopes not assessed"
                  />
                </div>
              </Panel>
            </div>

            <div className="mt-10">
              <DataTable
                columns={unassessedColumns}
                rows={decision.unassessed}
                rowKey={(row, index) => `${row.area ?? index}`}
                empty="Every area this build covers was assessed in this run."
                caption="Areas the engine explicitly recorded as not assessed, with what would assess them."
              />
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Supporting evidence</Eyebrow>
              <SectionTitle lead="What the decision" trail="rested on." className="mt-6" />
            </div>

            <div className="grid gap-6 lg:grid-cols-3">
              <Panel className="p-8">
                <h3 className="text-lg font-display mb-6">Counts</h3>
                <dl className="space-y-3 text-sm">
                  <Row label="Evidence carried" value={count(tally.total)} />
                  <Row label="Supporting" value={count(tally.supporting)} />
                  <Row label="Context only" value={count(tally.contextOnly)} />
                  <Row label="Confounded" value={count(tally.confounded)} />
                  <Row label="Families present" value={count(tally.familiesPresent.length)} />
                  <Row
                    label="Independent phenomena"
                    value={count(tally.independentFamilies.length)}
                  />
                </dl>
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  {tally.note}
                </p>
              </Panel>

              <Panel className="p-8">
                <h3 className="text-lg font-display mb-6">Severity</h3>
                <div className="flex flex-wrap gap-3 mb-6">
                  {Object.entries(tally.bySeverity).map(([severity, n]) => (
                    <span key={severity} className="inline-flex items-center gap-2">
                      <SeverityBadge value={severity} />
                      <span className="font-mono text-sm">{n}</span>
                    </span>
                  ))}
                </div>
                <FieldGrid columns={1}>
                  <Field label="Highest severity" value={text(severitySummary.highest, "—")} />
                  <Field
                    label="Highest-severity finding"
                    value={text(severitySummary.highest_finding_id, "—")}
                    mono
                  />
                </FieldGrid>
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  {text(severitySummary.note, "")}
                </p>
              </Panel>

              <Panel className="p-8">
                <h3 className="text-lg font-display mb-6">Confidence</h3>
                <div className="flex flex-wrap gap-3 mb-6">
                  {Object.entries(tally.byBasis).map(([basis, n]) => (
                    <span key={basis} className="inline-flex items-center gap-2">
                      <Tag active={basis === "DETERMINISTIC"}>{basis}</Tag>
                      <span className="font-mono text-sm">{n}</span>
                    </span>
                  ))}
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {text(confidenceSummary.note, "")}
                </p>
                <Link
                  href={`/evidence${suffix}`}
                  className="mt-6 inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors group"
                >
                  Walk the lineage
                  <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">
                    &rarr;
                  </span>
                </Link>
              </Panel>
            </div>

            {decision.conflicts.length > 0 ? (
              <Panel className="mt-10 p-8 border-[#fbbf24]/40">
                <h3 className="text-xl font-display mb-4">
                  {decision.conflicts.length} conflict(s) between evidence streams
                </h3>
                <pre className="text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-4 overflow-x-auto max-h-72">
                  {JSON.stringify(decision.conflicts, null, 2)}
                </pre>
              </Panel>
            ) : null}
          </Section>

          <Section>
            <div className="grid gap-10 lg:grid-cols-2">
              <div>
                <Eyebrow>Policy</Eyebrow>
                <div className="mt-8">
                  <FieldGrid columns={2}>
                    <Field label="Version" value={text(policy.policy_version)} mono />
                    <Field label="Combination" value={text(policy.combination)} mono />
                    <Field label="Counting unit" value={text(policy.counting_unit)} mono />
                    <Field
                      label="Strictness order"
                      value={(policy.strictness_order ?? []).join(" < ")}
                      mono
                    />
                    <Field label="Rules in table" value={count((policy.rules ?? []).length)} />
                    <Field
                      label="Accept requires"
                      value={text(policy.accept_requires_full_coverage, "—")}
                    />
                  </FieldGrid>
                  {policy.no_scoring ? (
                    <p className="mt-8 text-sm text-muted-foreground leading-relaxed border-l border-foreground/15 pl-4">
                      {policy.no_scoring}
                    </p>
                  ) : null}
                </div>
                <p className="mt-8 text-sm font-mono text-muted-foreground">
                  <a
                    href={artifactHref(data.source, data.scenario?.name ?? "", "assurance")}
                    target="_blank"
                    rel="noreferrer"
                    className="underline underline-offset-4 hover:text-foreground transition-colors"
                  >
                    read the full policy table in the report JSON
                  </a>
                </p>
              </div>
              <div className="space-y-8">
                <NoteList title="Decision limitations" items={decision.limitations} />
                <div>
                  <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                    Coverage of this build
                  </h4>
                  <div className="flex flex-wrap gap-3">
                    <CoverageBadge value="SUPPORTED" />
                    <CoverageBadge value="PARTIAL" />
                    <CoverageBadge value="NOT_ASSESSED" />
                  </div>
                  <p className="mt-4 text-sm text-muted-foreground leading-relaxed">
                    The{" "}
                    <Link href={`/coverage${suffix}`} className="underline underline-offset-4">
                      coverage page
                    </Link>{" "}
                    lists every attack class at its level, with the reason. Coverage describes the
                    assessment, not the safety of the system being assessed.
                  </p>
                </div>
              </div>
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-mono">{value}</dd>
    </div>
  )
}
