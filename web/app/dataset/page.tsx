import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import { FindingCard } from "@/components/platform/finding-card"
import {
  CoverageBadge,
  Digest,
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

import { scopeViews } from "@/lib/analyst/assurance"
import {
  contributorRows,
  datasetIdentity,
  detectorRows,
  findingsByAttackClass,
  summaryCounts,
  type ContributorRow,
  type DetectorRow,
} from "@/lib/analyst/dataset"
import { count, humanise, pValue, text } from "@/lib/analyst/format"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"

export const dynamic = "force-dynamic"

/**
 * Dataset Forensics (§8) — Module 1's report, rendered.
 *
 * No detection happens on this page. Everything shown was computed by the
 * dataset detectors and written to the report; the page selects and orders.
 */
export default async function DatasetPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.dataset ?? null
  const identity = datasetIdentity(report)
  const summary = summaryCounts(report)
  const scope = scopeViews(data.bundle?.assurance ?? null)[0]
  const contributors = contributorRows(report)
  const detectors = detectorRows(report)
  const groups = findingsByAttackClass(report?.findings ?? [])

  const contributorColumns: Column<ContributorRow>[] = [
    { key: "name", header: "Contributor", render: (row) => <span className="font-mono">{row.contributor}</span> },
    { key: "samples", header: "Samples", numeric: true, render: (row) => count(row.samples) },
    { key: "flagged", header: "Flagged", numeric: true, render: (row) => count(row.flagged) },
    {
      key: "rate",
      header: "Rate vs cohort",
      numeric: true,
      render: (row) =>
        row.rate === null
          ? "—"
          : `${row.rate.toFixed(3)} vs ${row.cohortRate === null ? "—" : row.cohortRate.toFixed(3)}`,
    },
    {
      key: "ratio",
      header: "Ratio",
      numeric: true,
      render: (row) => (row.rateRatio === null ? "—" : row.rateRatio.toFixed(2)),
    },
    { key: "q", header: "q-value", numeric: true, render: (row) => pValue(row.qValue) },
    {
      key: "significant",
      header: "Significant",
      render: (row) => <Tag active={row.significant}>{row.significant ? "YES" : "NO"}</Tag>,
    },
    {
      key: "severity",
      header: "Max child severity",
      render: (row) => <SeverityBadge value={row.maxChildSeverity} />,
    },
  ]

  const detectorColumns: Column<DetectorRow>[] = [
    { key: "name", header: "Detector", render: (row) => <span className="font-mono">{row.name}</span> },
    { key: "version", header: "Version", render: (row) => <span className="font-mono text-xs">{row.version}</span> },
    { key: "findings", header: "Findings", numeric: true, render: (row) => count(row.findings) },
    {
      key: "stats",
      header: "Reported statistics",
      render: (row) => (
        <pre className="text-[11px] font-mono text-muted-foreground max-w-xl overflow-x-auto">
          {JSON.stringify(row.stats)}
        </pre>
      ),
    },
  ]

  return (
    <PageShell
      data={data}
      eyebrow="Module 1 · Dataset forensics"
      title={
        <>
          <span className="block">What the corpus</span>
          <span className="block text-white/40">actually contains.</span>
        </>
      }
      lede="Multi-contributor datasets fail in ways a single-owner dataset cannot: duplicated floods, systematically flipped labels, a contributor whose samples sit outside the reference distribution. Module 1 looks for each of them and keeps every observation."
      stats={
        identity
          ? [
              { value: count(identity.samples), label: "samples ingested" },
              { value: count(identity.contributorCount), label: "contributors" },
              { value: count(summary.total), label: "findings recorded" },
              { value: text(identity.digest).slice(0, 12), label: "dataset digest" },
            ]
          : undefined
      }
    >
      {!report || !identity ? (
        <Section>
          <EmptyState
            title="No dataset was assessed in this run"
            reason={
              scope.statement ||
              "This scenario supplied no dataset report to the assurance pipeline, so Module 1 contributed nothing. That is not the same as a clean dataset: nothing was examined."
            }
            remedy="cvtrust dataset scan <root> --out reports/live/dataset.json"
          />
        </Section>
      ) : (
        <>
          <Section>
            <div className="mb-12">
              <Eyebrow>Dataset identity</Eyebrow>
              <SectionTitle lead="Identity" trail="and census." className="mt-6" />
            </div>

            <Panel className="p-8 lg:p-10 mb-6">
              <FieldGrid columns={3}>
                <Field label="Manifest id" value={identity.manifestId} mono />
                <Field
                  label="Dataset digest"
                  value={<Digest value={identity.digest} head={24} />}
                  title={identity.digest}
                />
                <Field label="Adapter / task" value={`${identity.adapter} · ${identity.task}`} />
                <Field label="Root" value={<span className="break-all">{identity.root}</span>} mono />
                <Field label="Samples" value={count(identity.samples)} />
                <Field
                  label="Readable / unreadable"
                  value={`${count(identity.readable)} / ${count(identity.unreadable)}`}
                />
                <Field label="Annotations" value={count(identity.annotations)} />
                <Field label="Classes" value={identity.classes.join(", ") || "—"} />
                <Field label="Ingest issues" value={count(identity.ingestIssues)} />
                <Field
                  label="Feature space"
                  value={`${text(identity.featureSpace.name)} ${text(identity.featureSpace.version, "")} · dim ${count(identity.featureSpace.dim)}`}
                  mono
                />
                <Field
                  label="Deterministic features"
                  value={identity.featureSpace.deterministic === true ? "yes" : "no"}
                />
                <Field label="Calibration" value={identity.calibrationStatus} mono />
              </FieldGrid>
            </Panel>

            <div className="grid gap-6 lg:grid-cols-3">
              <Panel className="p-8 lg:col-span-2">
                <h3 className="text-xl font-display mb-2">Module 1 disposition</h3>
                <div className="flex flex-wrap items-center gap-4 mb-4">
                  <DispositionBadge value={scope.disposition} size="lg" />
                  <span className="font-mono text-xs text-muted-foreground">
                    {scope.governingRule ?? "no rule fired"}
                  </span>
                </div>
                <p className="text-muted-foreground leading-relaxed">
                  {scope.statement || summary.rationale}
                </p>
                <p className="mt-4 text-sm font-mono text-muted-foreground">
                  Module 1 own summary: {summary.overall}
                </p>
              </Panel>
              <Panel className="p-8 flex flex-col gap-8">
                <Stat value={count(summary.total)} label="Findings" sublabel="every one preserved" />
                <Stat
                  value={count(summary.assetsAffected)}
                  label="Assets affected"
                  sublabel={`${count(summary.contributorsAffected)} contributor(s)`}
                />
              </Panel>
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Contributor distribution</Eyebrow>
              <SectionTitle lead="Who supplied" trail="what." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                Every contributor is listed, including the ones with nothing flagged. A table of
                only the flagged contributors would hide the denominator, and the denominator is
                the entire point of a multi-contributor pipeline.
              </p>
            </div>
            <DataTable
              columns={contributorColumns}
              rows={contributors}
              rowKey={(row) => row.contributor}
              empty="The manifest recorded no contributor attribution for this dataset."
              caption={`Attribution resolver ${text(identity.attribution.resolver_version)} · precedence ${
                Array.isArray(identity.attribution.precedence)
                  ? (identity.attribution.precedence as string[]).join(" → ")
                  : "—"
              }`}
            />
          </Section>

          <Section>
            <div className="mb-12">
              <Eyebrow>Detectors</Eyebrow>
              <SectionTitle lead="What ran," trail="and what it saw." className="mt-6" />
            </div>
            <DataTable
              columns={detectorColumns}
              rows={detectors}
              rowKey={(row) => row.name}
              empty="No detector reported in this run."
            />
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Findings</Eyebrow>
              <SectionTitle lead="Grouped by" trail="attack class." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                Grouping is what stops forty out-of-distribution flags from reading as forty
                separate problems. The grouping is presentational — each finding below is the
                object the detector emitted, with its evidence, assumptions and limitations intact.
              </p>
            </div>

            {groups.length === 0 ? (
              <EmptyState
                title="No findings"
                reason={`The detectors ran and recorded nothing actionable. ${summary.rationale}`}
                tone="ACCEPT"
              />
            ) : (
              <div className="space-y-12">
                {groups.map((group) => (
                  <div key={group.attackClass}>
                    <div className="flex flex-wrap items-center gap-4 mb-6">
                      <h3 className="text-2xl lg:text-3xl font-display">
                        {humanise(group.attackClass)}
                      </h3>
                      <SeverityBadge value={group.maxSeverity} />
                      <CoverageBadge value={group.coverage} />
                      <Tag>{group.findings.length} finding(s)</Tag>
                    </div>
                    <div className="space-y-4">
                      {group.findings.slice(0, 8).map((finding, index) => (
                        <FindingCard
                          key={finding.finding_id ?? index}
                          finding={finding}
                          defaultOpen={index === 0 && group === groups[0]}
                        />
                      ))}
                    </div>
                    {group.findings.length > 8 ? (
                      <p className="mt-4 text-sm font-mono text-muted-foreground">
                        {group.findings.length - 8} further finding(s) in this class are in the
                        report JSON; none has been discarded.
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </Section>

          <Section>
            <div className="grid gap-10 lg:grid-cols-2">
              <NoteList title="Module 1 limitations" items={report.limitations ?? []} />
              <div>
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                  Severity distribution
                </h4>
                <div className="flex flex-wrap gap-3">
                  {Object.entries(summary.bySeverity).map(([severity, value]) => (
                    <span key={severity} className="inline-flex items-center gap-2">
                      <SeverityBadge value={severity} />
                      <span className="font-mono text-sm">{value}</span>
                    </span>
                  ))}
                </div>
                <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
                  These are counts, not a score. A dataset with nine LOW findings is not
                  &ldquo;worse&rdquo; than one with a single CRITICAL, and the platform never adds
                  them up to claim otherwise.
                </p>
              </div>
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}
