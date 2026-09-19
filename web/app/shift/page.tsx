import Link from "next/link"

import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import {
  Digest,
  DispositionBadge,
  EmptyState,
  Eyebrow,
  Field,
  FieldGrid,
  NoteList,
  Panel,
  SectionTitle,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import { scopeViews } from "@/lib/analyst/assurance"
import { count, humanise, text } from "@/lib/analyst/format"
import { linkSuffix, loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import { oodFindingCount, shiftView, type MetricView } from "@/lib/analyst/shift"

export const dynamic = "force-dynamic"

/**
 * Distribution Shift (§11) — Module 4's population characterisation.
 *
 * Two things this page must keep visible and does:
 *
 * 1. Population shift and per-sample OOD are different claims. The counter at
 *    the top states both side by side and says what each one means.
 * 2. A shift is an observation, never an accusation. The page reports the
 *    verdict and the declared operating context that may explain it, and it
 *    does not print the word "attack" anywhere. Whether independent evidence
 *    exists is the policy engine's call, and it lives on the decision page.
 */
export default async function ShiftPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const assessment = data.bundle?.shift ?? data.bundle?.assurance?.distribution_shift ?? null
  const view = shiftView(assessment)
  const scope = scopeViews(data.bundle?.assurance ?? null)[3]
  const oodCount = oodFindingCount(data.bundle?.dataset?.findings)
  const suffix = linkSuffix(data.source, data.scenario?.name)

  const metricColumns: Column<MetricView>[] = [
    { key: "metric", header: "Metric", render: (row) => <span className="font-mono text-xs">{row.metric}</span> },
    { key: "status", header: "Status", render: (row) => <Tag active={row.significant}>{row.status}</Tag> },
    { key: "stat", header: "Statistic", numeric: true, render: (row) => <span className="font-mono text-xs">{row.statistic}</span> },
    { key: "p", header: "p-value", numeric: true, render: (row) => <span className="font-mono text-xs">{row.pValue}</span> },
    {
      key: "interpretation",
      header: "What the engine says it means",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.ran ? row.interpretation : row.reason || "the metric declined to run"}
        </span>
      ),
    },
  ]

  return (
    <PageShell
      data={data}
      eyebrow="Module 4 · Distribution shift"
      title={
        <>
          <span className="block">Has the population</span>
          <span className="block text-white/40">moved?</span>
        </>
      }
      lede="A population can shift without any single image being remarkable, and a handful of remarkable images do not make a population shift. This page answers the population question only."
      stats={
        view
          ? [
              { value: humanise(view.verdict), label: "population verdict" },
              { value: count(view.current?.sampleCount ?? null), label: "current samples" },
              { value: count(view.reference?.sampleCount ?? null), label: "reference samples" },
              {
                value: `${view.significantMetrics.length}/${view.metrics.length}`,
                label: "metrics reaching significance",
              },
            ]
          : undefined
      }
    >
      {!view ? (
        <Section>
          <EmptyState
            title="No reference population was supplied"
            reason={
              scope.statement ||
              "Distribution shift needs a reference population to compare against. None was supplied to this run, so the question was not asked. The engine will not self-reference a population against itself and call the result a baseline."
            }
            remedy="cvtrust assurance shift <current_root> --reference <reference_root> --out reports/live/shift.json"
          />
        </Section>
      ) : (
        <>
          <Section>
            <Panel className="p-8 lg:p-12 mb-6">
              <div className="flex flex-wrap items-center gap-4 mb-6">
                <DispositionBadge value={scope.disposition} size="lg" />
                <span className="text-2xl lg:text-3xl font-display">{humanise(view.verdict)}</span>
                <span className="font-mono text-xs text-muted-foreground">
                  {scope.governingRule ?? "no rule fired"}
                </span>
              </div>
              <p className="text-lg text-muted-foreground leading-relaxed max-w-4xl">
                {view.statement}
              </p>
            </Panel>

            {/* The distinction §11 asks to be made visible. */}
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel className="p-8">
                <Eyebrow>Population level</Eyebrow>
                <h3 className="text-2xl font-display mt-6 mb-4">Distribution shift</h3>
                <Stat
                  value={humanise(view.verdict)}
                  label="One verdict for the whole current population"
                  sublabel={`assessment ${view.assessmentId} · metrics ${view.metricVersion}`}
                />
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  Computed by comparing the current population against a separately declared
                  reference. It says the operating conditions moved. It does not, on its own, say
                  anybody moved them on purpose.
                </p>
              </Panel>
              <Panel className="p-8">
                <Eyebrow>Per sample</Eyebrow>
                <h3 className="text-2xl font-display mt-6 mb-4">Out-of-distribution flags</h3>
                <Stat
                  value={count(oodCount)}
                  label="Individual samples Module 1 flagged as unusual"
                  sublabel={
                    data.bundle?.dataset
                      ? "from this run's dataset report"
                      : "no dataset report was supplied to this run"
                  }
                />
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  A different question with a different unit. Forty OOD flags from one new sensor
                  domain are one phenomenon, and the evidence engine treats them as one — see the{" "}
                  <Link href={`/evidence${suffix}`} className="underline underline-offset-4">
                    evidence explorer
                  </Link>
                  .
                </p>
              </Panel>
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Populations</Eyebrow>
              <SectionTitle lead="Reference" trail="and current." className="mt-6" />
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <Panel className="p-8">
                <h3 className="text-xl font-display mb-6">{view.reference?.label}</h3>
                <FieldGrid columns={2}>
                  <Field label="Identity" value={view.reference?.id ?? "—"} mono />
                  <Field
                    label="Digest"
                    value={<Digest value={view.reference?.digest} head={20} />}
                    title={view.reference?.digest}
                  />
                  <Field label="Samples" value={count(view.reference?.sampleCount ?? null)} />
                  <Field label="Mode" value={view.reference?.mode ?? "—"} mono />
                  <Field label="Trust" value={view.reference?.trust ?? "UNKNOWN"} mono />
                  <Field label="Provenance" value={view.reference?.provenance ?? "not declared"} />
                </FieldGrid>
                {view.reference?.caveat ? (
                  <p className="mt-8 text-sm text-muted-foreground leading-relaxed border-l border-foreground/15 pl-4">
                    {view.reference.caveat}
                  </p>
                ) : null}
              </Panel>

              <Panel className="p-8">
                <h3 className="text-xl font-display mb-6">{view.current?.label}</h3>
                <FieldGrid columns={2}>
                  <Field label="Identity" value={view.current?.id ?? "—"} mono />
                  <Field
                    label="Digest"
                    value={<Digest value={view.current?.digest} head={20} />}
                    title={view.current?.digest}
                  />
                  <Field label="Samples" value={count(view.current?.sampleCount ?? null)} />
                  <Field
                    label="Root"
                    value={<span className="break-all">{view.current?.locator ?? "—"}</span>}
                    mono
                  />
                </FieldGrid>
                <div className="mt-8 grid gap-6 sm:grid-cols-2">
                  <div>
                    <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                      Class counts
                    </h4>
                    <dl className="space-y-1 text-sm">
                      {Object.entries(view.current?.classes ?? {}).map(([name, n]) => (
                        <div key={name} className="flex justify-between gap-4">
                          <dt className="text-muted-foreground">{name}</dt>
                          <dd className="font-mono">{n}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                  <div>
                    <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                      Contributor counts
                    </h4>
                    <dl className="space-y-1 text-sm">
                      {Object.entries(view.current?.contributors ?? {}).map(([name, n]) => (
                        <div key={name} className="flex justify-between gap-4">
                          <dt className="text-muted-foreground">{name}</dt>
                          <dd className="font-mono">{n}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                </div>
              </Panel>
            </div>
          </Section>

          <Section>
            <div className="mb-12">
              <Eyebrow>Selected metrics</Eyebrow>
              <SectionTitle lead="Every metric," trail="including the ones that declined." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                A metric that refused to run because the current batch was too small is often the
                most informative row here, so it is never hidden — it is listed with the
                engine&rsquo;s own reason.
              </p>
            </div>
            <DataTable
              columns={metricColumns}
              rows={view.metrics}
              rowKey={(row) => row.metric}
              empty="No metric was selected for this comparison."
              caption={`Metric suite ${view.metricVersion} · ${view.unrunMetrics.length} metric(s) declined to run`}
            />
          </Section>

          {view.context ? (
            <Section className="bg-foreground/[0.015]">
              <div className="mb-12">
                <Eyebrow>Operational context</Eyebrow>
                <SectionTitle lead="Does the declared context" trail="explain it?" className="mt-6" />
              </div>

              <Panel className="p-8 lg:p-10">
                <div className="flex flex-wrap items-center gap-4 mb-6">
                  <Tag active>{humanise(view.context.explanation)}</Tag>
                  <Tag>
                    {view.context.declarationValidated
                      ? "declaration validated"
                      : "declaration NOT validated"}
                  </Tag>
                </div>
                <p className="text-lg text-muted-foreground leading-relaxed max-w-4xl mb-8">
                  {view.context.statement}
                </p>
                {view.context.note ? (
                  <p className="text-sm text-muted-foreground leading-relaxed max-w-4xl mb-8 border-l border-foreground/15 pl-4">
                    {view.context.note}
                  </p>
                ) : null}

                <FieldGrid columns={3}>
                  <Field
                    label="Declared changes"
                    value={view.context.changed.join(", ") || "none"}
                    mono
                  />
                  <Field
                    label="Declared unchanged"
                    value={view.context.unchanged.join(", ") || "none"}
                    mono
                  />
                  <Field
                    label="Declared on one side only"
                    value={view.context.declaredOnOneSideOnly.join(", ") || "none"}
                    mono
                  />
                  <Field
                    label="Explained feature blocks"
                    value={view.context.explainedBlocks.join(", ") || "none"}
                    mono
                  />
                  <Field
                    label="Blocks that moved"
                    value={view.context.movedBlocks.join(", ") || "none"}
                    mono
                  />
                  <Field
                    label="Unexplained blocks"
                    value={view.context.unexplainedBlocks.join(", ") || "none"}
                    mono
                  />
                </FieldGrid>

                <div className="mt-10 grid gap-6 lg:grid-cols-2">
                  <div>
                    <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                      Reference conditions, as declared
                    </h4>
                    <dl className="space-y-1 text-sm">
                      {Object.entries(view.context.referenceDeclared)
                        .filter(([key]) => key !== "extra" && key !== "source")
                        .map(([key, value]) => (
                          <div key={key} className="flex justify-between gap-4">
                            <dt className="text-muted-foreground font-mono">{key}</dt>
                            <dd>{value === null ? "not declared" : String(value)}</dd>
                          </div>
                        ))}
                    </dl>
                  </div>
                  <div>
                    <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                      Current conditions, as declared
                    </h4>
                    <dl className="space-y-1 text-sm">
                      {Object.entries(view.context.currentDeclared)
                        .filter(([key]) => key !== "extra" && key !== "source")
                        .map(([key, value]) => (
                          <div key={key} className="flex justify-between gap-4">
                            <dt className="text-muted-foreground font-mono">{key}</dt>
                            <dd>{value === null ? "not declared" : String(value)}</dd>
                          </div>
                        ))}
                    </dl>
                  </div>
                </div>

                <p className="mt-10 text-sm text-muted-foreground leading-relaxed max-w-4xl">
                  A declared context is a claim made by an operator. The engine records it and uses
                  it to ask whether the observed movement is the movement that claim predicts. It
                  never verifies that the claim is true, and it never treats a convenient
                  declaration as evidence of innocence.
                </p>

                <NoteList title="Context limitations" items={view.context.limitations} />
              </Panel>
            </Section>
          ) : null}

          <Section>
            <div className="grid gap-10 lg:grid-cols-2">
              <NoteList title="Assumptions" items={view.assumptions} />
              <NoteList title="Limitations" items={view.limitations} />
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}
