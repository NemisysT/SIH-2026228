import { PageShell, Section } from "@/components/platform/page-shell"
import { EvidenceExplorer } from "@/components/platform/evidence-explorer"
import {
  EmptyState,
  Eyebrow,
  Panel,
  SectionTitle,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import { evidenceTally } from "@/lib/analyst/assurance"
import { buildExplorer } from "@/lib/analyst/explorer"
import { count, humanise } from "@/lib/analyst/format"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"

export const dynamic = "force-dynamic"

/**
 * Evidence Explorer (§12) — "why did the system produce this disposition?"
 *
 * The one screen where an analyst who distrusts the fusion can still get all
 * the way back to an image. Every hop is preserved: decision, rule, evidence,
 * module, detector, raw observation, assumptions, limitations.
 */
export default async function EvidencePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.assurance ?? null
  const model = buildExplorer(report)
  const tally = evidenceTally(report)

  return (
    <PageShell
      data={data}
      eyebrow="Evidence lineage"
      title={
        <>
          <span className="block">Follow the decision</span>
          <span className="block text-white/40">back to the pixel.</span>
        </>
      }
      lede="Nothing is summarised away. Each hop keeps what the previous one recorded, so a claim on the dashboard can be traced to the detector that made it and the measurement it made."
      stats={[
        { value: count(tally.total), label: "evidence items" },
        { value: count(tally.supporting), label: "supporting" },
        { value: count(tally.confounded), label: "with an active confounder" },
        { value: count(tally.independentFamilies.length), label: "independent phenomena" },
      ]}
    >
      {!report ? (
        <Section>
          <EmptyState
            title="No assurance report for this selection"
            reason="Without a Module 4 report there is no decision to explain and no evidence graph to walk."
          />
        </Section>
      ) : (
        <>
          <Section>
            <div className="mb-12 grid gap-6 lg:grid-cols-4">
              <Panel className="p-8 lg:col-span-2">
                <Eyebrow>Confidence bases present</Eyebrow>
                <div className="mt-6 flex flex-wrap gap-3">
                  {Object.keys(tally.byBasis).length === 0 ? (
                    <span className="text-sm text-muted-foreground">
                      No evidence carried a confidence basis in this run.
                    </span>
                  ) : (
                    Object.entries(tally.byBasis).map(([basis, n]) => (
                      <span key={basis} className="inline-flex items-center gap-2">
                        <Tag active={basis === "DETERMINISTIC"}>{basis}</Tag>
                        <span className="font-mono text-sm">{n}</span>
                      </span>
                    ))
                  )}
                </div>
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  The basis is never rewritten on the way to the screen. DETERMINISTIC stays
                  deterministic, CALIBRATED stays calibrated, HEURISTIC_UNCALIBRATED stays
                  uncalibrated — and an uncalibrated 0.9 is not a 90% chance of anything.
                </p>
              </Panel>
              <Panel className="p-8">
                <Eyebrow>Evidence classes</Eyebrow>
                <dl className="mt-6 space-y-2">
                  {Object.entries(tally.byClass).map(([evidenceClass, n]) => (
                    <div key={evidenceClass} className="flex justify-between gap-4 text-sm">
                      <dt className="text-muted-foreground font-mono text-xs">
                        {humanise(evidenceClass)}
                      </dt>
                      <dd className="font-mono">{n}</dd>
                    </div>
                  ))}
                </dl>
              </Panel>
              <Panel className="p-8 flex flex-col gap-8">
                <Stat
                  value={count(tally.contextOnly)}
                  label="Context only"
                  sublabel="carried, not counted as support"
                />
                <Stat
                  value={count(tally.familiesPresent.length)}
                  label="Families present"
                  sublabel={`${tally.independentFamilies.length} judged independent`}
                />
              </Panel>
            </div>

            <div className="mb-12">
              <Eyebrow>Drill-down</Eyebrow>
              <SectionTitle lead="Decision" trail="to raw observation." className="mt-6" />
            </div>

            <EvidenceExplorer
              disposition={model.disposition}
              decisionId={model.decisionId}
              summary={model.summary}
              rules={model.rules}
              evidence={model.evidence}
              families={model.families}
            />
          </Section>
        </>
      )}
    </PageShell>
  )
}
