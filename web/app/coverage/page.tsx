import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import {
  CoverageBadge,
  EmptyState,
  Eyebrow,
  NoteList,
  Panel,
  SectionTitle,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import {
  capabilityViews,
  coverageTally,
  coverageViews,
  decisionView,
  type CoverageView,
} from "@/lib/analyst/assurance"
import { count, humanise, text } from "@/lib/analyst/format"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import { loadCapabilities } from "@/lib/analyst/source"

export const dynamic = "force-dynamic"

/**
 * Coverage / Limitations (§14).
 *
 * Coverage is not security, and this page is built so that it cannot be read
 * as if it were. There is no percentage anywhere on it. There are counts of
 * attack classes per level, and each class carries the engine's own reason for
 * its level — which is what an analyst actually needs in order to know what
 * the assessment did not look at.
 *
 * Three different things are kept apart, because they answer different
 * questions:
 *
 *   Build capabilities — what this build implements at all.
 *   Run coverage      — what this particular run actually reported on.
 *   Unassessed areas  — what the decision itself recorded as not assessed.
 */
export default async function CoveragePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.assurance ?? null
  const runCoverage = coverageViews(report)
  const tally = coverageTally(report)
  const capabilities = capabilityViews(report)
  const decision = decisionView(report)
  const buildStatement = (await loadCapabilities(data.source)) as
    | { coverage?: { entries?: unknown[] }; capabilities?: { entries?: unknown[] } }
    | null

  const columns: Column<CoverageView>[] = [
    {
      key: "class",
      header: "Attack class",
      render: (row) => (
        <div className="min-w-0">
          <span className="block font-medium break-words">{row.title || humanise(row.attackClass)}</span>
          <span className="block font-mono text-xs text-muted-foreground break-words">
            {row.attackClass}
          </span>
        </div>
      ),
    },
    { key: "coverage", header: "Coverage", render: (row) => <CoverageBadge value={row.coverage} /> },
    {
      key: "module",
      header: "Module",
      render: (row) => <Tag>{row.owningModule === null ? "—" : `M${row.owningModule}`}</Tag>,
    },
    {
      key: "detector",
      header: "Detector",
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground">{row.detector ?? "none"}</span>
      ),
    },
    {
      key: "reason",
      header: "Why this level",
      render: (row) => (
        <span className="text-sm text-muted-foreground break-words">{row.reason}</span>
      ),
    },
  ]

  return (
    <PageShell
      data={data}
      eyebrow="Coverage and limitations"
      title={
        <>
          <span className="block">Coverage is</span>
          <span className="block text-white/40">not security.</span>
        </>
      }
      lede="What was assessed, what was not, and why. A class nobody examined is NOT_ASSESSED — a statement about this assessment, never a clean bill of health, and never a percentage."
      stats={[
        { value: count(tally.SUPPORTED), label: "classes supported in this run" },
        { value: count(tally.PARTIAL), label: "partial" },
        { value: count(tally.NOT_ASSESSED), label: "not assessed" },
        { value: count(decision.unassessed.length), label: "areas the decision flagged" },
      ]}
    >
      {!report ? (
        <Section>
          <EmptyState
            title="No coverage statement for this selection"
            reason="Coverage is recorded per run. Without a Module 4 report there is no run to describe."
          />
        </Section>
      ) : (
        <>
          <Section>
            <Panel className="p-8 lg:p-12">
              <Eyebrow>The distinction that matters</Eyebrow>
              <div className="mt-8 grid gap-8 lg:grid-cols-3">
                <div>
                  <h3 className="text-xl font-display mb-3">SUPPORTED</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    A detector examined this class and its result is in the report. It does not mean
                    the class is impossible — it means somebody looked.
                  </p>
                </div>
                <div>
                  <h3 className="text-xl font-display mb-3">PARTIAL</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    A detector examined this class under stated assumptions, and the reason column
                    says which. The result is bounded by those assumptions.
                  </p>
                </div>
                <div>
                  <h3 className="text-xl font-display mb-3">NOT_ASSESSED</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    Nothing examined this class in this run. An absence of findings here carries no
                    information at all, and treating it as reassurance is the mistake this page
                    exists to prevent.
                  </p>
                </div>
              </div>
              <p className="mt-10 text-sm text-muted-foreground leading-relaxed max-w-4xl">
                None of these levels is a number, and this page will not produce one by dividing
                them. A percentage of classes assessed would be meaningless as a measure of
                safety: the classes are not interchangeable, and the ones nothing examined are
                precisely the ones whose weight cannot be known.
              </p>
            </Panel>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>This build</Eyebrow>
              <SectionTitle lead="What the engine" trail="implements at all." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                A capability the build supports can still be NOT_ASSESSED in a given run, because
                the run was not given the input it needs. Both facts are true at once, and mixing
                them is how a tool ends up overstating what it checked.
              </p>
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {capabilities.map((capability) => (
                <Panel key={capability.attackClass} className="p-6 flex flex-col">
                  <div className="mb-4">
                    <CoverageBadge value={capability.coverage} />
                  </div>
                  <h3 className="text-lg font-display mb-2 break-words">
                    {capability.title || humanise(capability.attackClass)}
                  </h3>
                  <span className="font-mono text-[11px] text-muted-foreground mb-4 break-words">
                    {capability.attackClass}
                  </span>
                  <p className="text-sm text-muted-foreground leading-relaxed flex-1">
                    {capability.reason || "No reason recorded."}
                  </p>
                  {capability.limitations.length > 0 ? (
                    <p className="mt-4 text-xs text-muted-foreground border-l border-foreground/15 pl-3">
                      {capability.limitations.join(" ")}
                    </p>
                  ) : null}
                </Panel>
              ))}
            </div>

            {buildStatement?.capabilities?.entries ? (
              <p className="mt-8 text-sm font-mono text-muted-foreground">
                The build-wide statement (
                {(buildStatement.capabilities.entries as unknown[]).length} capabilities,{" "}
                {(buildStatement.coverage?.entries ?? []).length} attack classes) is exported
                alongside the scenarios as capabilities.json.
              </p>
            ) : null}
          </Section>

          <Section>
            <div className="mb-12">
              <Eyebrow>This run</Eyebrow>
              <SectionTitle lead="What was actually" trail="reported on." className="mt-6" />
            </div>

            <div className="flex flex-wrap gap-8 mb-10">
              <Stat value={count(tally.SUPPORTED)} label="SUPPORTED" />
              <Stat value={count(tally.PARTIAL)} label="PARTIAL" />
              <Stat value={count(tally.REQUIRES_WHITE_BOX)} label="REQUIRES_WHITE_BOX" />
              <Stat value={count(tally.NOT_SUPPORTED)} label="NOT_SUPPORTED" />
              <Stat value={count(tally.NOT_ASSESSED)} label="NOT_ASSESSED" />
            </div>

            <DataTable
              columns={columns}
              rows={runCoverage}
              rowKey={(row) => row.attackClass}
              empty="This run recorded no coverage statement."
              caption={`Modules implemented in this report: ${(report.coverage?.implemented_modules ?? []).join(", ") || "—"}`}
            />
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Assumptions carried</Eyebrow>
              <SectionTitle lead="What each PARTIAL" trail="depends on." className="mt-6" />
            </div>

            <div className="space-y-6">
              {runCoverage
                .filter(
                  (entry) =>
                    entry.assumptions.length > 0 || entry.limitations.length > 0,
                )
                .map((entry) => (
                  <Panel key={entry.attackClass} className="p-6 lg:p-8">
                    <div className="flex flex-wrap items-center gap-3 mb-5">
                      <span className="text-lg font-display">
                        {entry.title || humanise(entry.attackClass)}
                      </span>
                      <CoverageBadge value={entry.coverage} />
                    </div>
                    <div className="grid gap-8 sm:grid-cols-2">
                      <NoteList title="Assumptions" items={entry.assumptions} />
                      <NoteList title="Limitations" items={entry.limitations} />
                    </div>
                  </Panel>
                ))}
              {runCoverage.every(
                (entry) => entry.assumptions.length === 0 && entry.limitations.length === 0,
              ) ? (
                <p className="text-sm text-muted-foreground">
                  No coverage entry in this run carried assumptions or limitations of its own. The
                  report-level limitations below still apply.
                </p>
              ) : null}
            </div>
          </Section>

          <Section>
            <div className="grid gap-10 lg:grid-cols-2">
              <NoteList
                title="Report limitations"
                items={report.limitations ?? []}
                emptyLabel="The report recorded no limitations, which would be unusual."
              />
              <NoteList
                title="Decision limitations"
                items={decision.limitations}
                emptyLabel="The decision recorded no limitations of its own."
              />
            </div>

            <div className="mt-12">
              <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-4">
                Areas the decision explicitly recorded as not assessed
              </h4>
              {decision.unassessed.length === 0 ? (
                <p className="text-sm text-muted-foreground">None.</p>
              ) : (
                <ul className="grid gap-4 md:grid-cols-2">
                  {decision.unassessed.map((area, index) => (
                    <li key={`${area.area}-${index}`}>
                      <Panel className="p-5 h-full">
                        <div className="flex flex-wrap items-center gap-3 mb-2">
                          <span className="font-mono text-sm">{text(area.area)}</span>
                          <Tag>{text(area.kind)}</Tag>
                        </div>
                        <p className="text-sm text-muted-foreground leading-relaxed">
                          {text(area.reason)}
                        </p>
                        {area.remedy ? (
                          <p className="mt-3 text-xs font-mono text-muted-foreground break-all">
                            {area.remedy}
                          </p>
                        ) : null}
                      </Panel>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}
