import Link from "next/link"

import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import {
  CheckMark,
  DispositionBadge,
  EmptyState,
  Eyebrow,
  Field,
  FieldGrid,
  Panel,
  SectionTitle,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import { decisionView, scopeViews } from "@/lib/analyst/assurance"
import { count, text, timestamp, titleise } from "@/lib/analyst/format"
import { artifactHref } from "@/lib/analyst/links"
import { linkSuffix, loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import { listScenarios, sourceStatus } from "@/lib/analyst/source"
import type { ScenarioRow } from "@/lib/analyst/types"

export const dynamic = "force-dynamic"

/**
 * Demo Scenarios (§17, §18).
 *
 * Every row here is a scenario the attack lab ran end to end through Modules
 * 1, 2, 3 and 4. Nothing on this page is authored for the demo: the
 * dispositions, rules, evidence counts and statements are what the policy
 * engine produced, exported by `cvtrust analyst export`.
 *
 * The matrix keeps the lab's own declared expectation beside the observed
 * disposition. When they agree that is worth showing; when they disagree the
 * page says so rather than hiding it, because a demo that can only agree with
 * itself demonstrates nothing.
 */
export default async function DemoPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const rows = await listScenarios(data.source)
  const other = await sourceStatus(data.source === "DEMO" ? "LIVE" : "DEMO")
  const report = data.bundle?.assurance ?? null
  const decision = decisionView(report)
  const scopes = scopeViews(report)
  const scenario = data.scenario
  const suffix = linkSuffix(data.source, scenario?.name)

  const columns: Column<ScenarioRow>[] = [
    {
      key: "name",
      header: "Scenario",
      render: (row) => (
        <Link
          href={`/demo${linkSuffix(data.source, row.name)}`}
          className="group inline-flex flex-col"
        >
          <span className="font-medium group-hover:underline underline-offset-4">
            {titleise(row.name)}
          </span>
          <span className="font-mono text-xs text-muted-foreground">{row.name}</span>
        </Link>
      ),
    },
    {
      key: "inputs",
      header: "Inputs",
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground">
          {Object.entries(row.summary?.inputs_supplied ?? {})
            .filter(([, value]) => value)
            .map(([key]) => key[0].toUpperCase())
            .join(" ") || "none"}
        </span>
      ),
    },
    {
      key: "expected",
      header: "Lab expectation",
      render: (row) => <Tag>{text(row.expected_disposition, "—")}</Tag>,
    },
    {
      key: "observed",
      header: "Engine produced",
      render: (row) =>
        row.status === "RUN" ? (
          <DispositionBadge value={row.observed_disposition} />
        ) : (
          <Tag active>NOT_RUN</Tag>
        ),
    },
    {
      key: "agree",
      header: "Agrees",
      render: (row) => (
        <CheckMark
          state={
            row.status !== "RUN"
              ? "NEUTRAL"
              : row.observed_disposition === row.expected_disposition
                ? "PASS"
                : "FAIL"
          }
        />
      ),
    },
    {
      key: "evidence",
      header: "Evidence",
      numeric: true,
      render: (row) => count(row.summary?.evidence_total),
    },
    {
      key: "families",
      header: "Independent",
      numeric: true,
      render: (row) => count((row.summary?.independent_families ?? []).length),
    },
    {
      key: "rules",
      header: "Rules fired",
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground break-words">
          {(row.summary?.fired_rules ?? []).join(", ") || "none"}
        </span>
      ),
    },
  ]

  const agreed = rows.filter(
    (row) => row.status === "RUN" && row.observed_disposition === row.expected_disposition,
  ).length
  const notRun = rows.filter((row) => row.status !== "RUN").length

  return (
    <PageShell
      data={data}
      eyebrow={data.source === "LIVE" ? "Live assessments" : "Demo scenarios · attack lab"}
      title={
        <>
          <span className="block">Every scenario,</span>
          <span className="block text-white/40">actually run.</span>
        </>
      }
      lede="Input, then Module 1, Module 2, Module 3, Module 4, then a disposition. Select a scenario and every page in this application changes to show that run — nothing here is a mock-up of a result."
      stats={[
        { value: count(rows.length), label: "scenarios in the matrix" },
        { value: `${agreed}/${rows.length - notRun}`, label: "agree with the lab expectation" },
        { value: count(notRun), label: "not run in this environment" },
        { value: timestamp(data.status.generatedAt), label: "feed generated" },
      ]}
    >
      {rows.length === 0 ? (
        <Section>
          <EmptyState
            title={`The ${data.source} source is empty`}
            reason={
              data.source === "LIVE"
                ? `Nothing has been published to ${data.status.directory}. Demo scenarios are not shown here in their place.${
                    other.available ? ` The demo feed holds ${other.scenarioCount} scenario(s).` : ""
                  }`
                : `Nothing has been exported to ${data.status.directory}.`
            }
            remedy={data.status.remedy}
          />
        </Section>
      ) : (
        <>
          {scenario ? (
            <Section>
              <div className="mb-12">
                <Eyebrow>Selected scenario</Eyebrow>
                <SectionTitle lead={titleise(scenario.name)} className="mt-6" />
              </div>

              {scenario.status !== "RUN" ? (
                <EmptyState
                  title="This scenario did not run in this environment"
                  reason={
                    text(scenario.reason) ||
                    "A required upstream lab was not available. The scenario is kept in the matrix rather than dropped, because a demo that hides its own missing inputs teaches the wrong lesson."
                  }
                  remedy="cvtrust lab generate && cvtrust lab model-build && cvtrust lab provenance-build && cvtrust lab assurance-build"
                />
              ) : (
                <>
                  <Panel className="p-8 lg:p-12 mb-6">
                    <div className="flex flex-wrap items-center gap-5 mb-6">
                      <DispositionBadge value={decision.disposition} size="lg" />
                      <Tag>lab expected {text(scenario.expected_disposition)}</Tag>
                      <CheckMark
                        state={
                          scenario.observed_disposition === scenario.expected_disposition
                            ? "PASS"
                            : "FAIL"
                        }
                      />
                      <span className="font-mono text-xs text-muted-foreground">
                        {decision.reportId}
                      </span>
                    </div>
                    <p className="text-lg text-muted-foreground leading-relaxed max-w-4xl mb-6">
                      {decision.summary}
                    </p>
                    {scenario.note ? (
                      <p className="text-sm text-muted-foreground leading-relaxed max-w-4xl border-l border-foreground/15 pl-4">
                        <span className="font-mono text-xs uppercase tracking-wider block mb-2">
                          Why this scenario is in the matrix
                        </span>
                        {scenario.note}
                      </p>
                    ) : null}
                  </Panel>

                  {/* INPUT → M1 → M2 → M3 → M4 → DISPOSITION */}
                  <div className="grid gap-4 lg:grid-cols-6">
                    <Panel className="p-6 flex flex-col">
                      <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-4">
                        Input
                      </span>
                      <h3 className="text-lg font-display mb-4">Lab artifacts</h3>
                      <dl className="space-y-2 text-xs font-mono text-muted-foreground flex-1">
                        {Object.entries(scenario.summary?.lab_inputs ?? {}).map(([key, value]) => (
                          <div key={key} className="flex justify-between gap-2">
                            <dt>{key}</dt>
                            <dd className="text-right break-all">{value ?? "—"}</dd>
                          </div>
                        ))}
                      </dl>
                    </Panel>

                    {scopes.map((scope, index) => (
                      <Panel key={scope.scope} className="p-6 flex flex-col">
                        <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-4">
                          Module {index + 1}
                        </span>
                        <h3 className="text-lg font-display mb-4">{scope.label}</h3>
                        <div className="mb-4">
                          <DispositionBadge value={scope.disposition} />
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed flex-1 line-clamp-6">
                          {scope.statement}
                        </p>
                        <Link
                          href={`${scope.href}${suffix}`}
                          className="mt-4 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors"
                        >
                          open &rarr;
                        </Link>
                      </Panel>
                    ))}

                    <Panel className="p-6 flex flex-col border-foreground/30">
                      <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-4">
                        Disposition
                      </span>
                      <h3 className="text-lg font-display mb-4">{decision.disposition}</h3>
                      <p className="text-xs text-muted-foreground leading-relaxed flex-1">
                        {decision.governingRules
                          .slice(0, 3)
                          .map((rule) => rule.rule_id)
                          .join(", ")}
                      </p>
                      <Link
                        href={`/decision${suffix}`}
                        className="mt-4 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors"
                      >
                        why &rarr;
                      </Link>
                    </Panel>
                  </div>

                  <div className="mt-6 grid gap-6 lg:grid-cols-3">
                    <Panel className="p-8 lg:col-span-2">
                      <Eyebrow>Run identity</Eyebrow>
                      <FieldGrid columns={3}>
                        <Field label="Report" value={decision.reportId} mono />
                        <Field label="Decision" value={decision.decisionId} mono />
                        <Field label="Policy" value={decision.policyVersion} mono />
                        <Field
                          label="Evidence"
                          value={count(scenario.summary?.evidence_total)}
                        />
                        <Field
                          label="Source findings"
                          value={count(scenario.summary?.source_findings_total)}
                        />
                        <Field
                          label="Confounded"
                          value={count(scenario.summary?.confounded_evidence)}
                        />
                      </FieldGrid>
                      <div className="mt-8 flex flex-wrap gap-4">
                        {["assurance", "dataset", "model", "provenance", "shift"].map(
                          (artifact) =>
                            scenario.files?.[artifact] ? (
                              <a
                                key={artifact}
                                href={artifactHref(data.source, scenario.name, artifact)}
                                target="_blank"
                                rel="noreferrer"
                                className="text-sm font-mono text-muted-foreground hover:text-foreground transition-colors underline underline-offset-4"
                              >
                                {artifact}.json
                              </a>
                            ) : (
                              <span
                                key={artifact}
                                className="text-sm font-mono text-muted-foreground/40"
                              >
                                {artifact}.json (not produced)
                              </span>
                            ),
                        )}
                      </div>
                    </Panel>
                    <Panel className="p-8 flex flex-col gap-8">
                      <Stat
                        value={count((scenario.summary?.independent_families ?? []).length)}
                        label="Independent phenomena"
                        sublabel={
                          (scenario.summary?.independent_families ?? []).join(", ") || "none"
                        }
                      />
                      <Stat
                        value={count((scenario.summary?.fired_rules ?? []).length)}
                        label="Rules fired"
                        sublabel={(scenario.summary?.fired_rules ?? []).join(", ") || "none"}
                      />
                    </Panel>
                  </div>
                </>
              )}
            </Section>
          ) : null}

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>The matrix</Eyebrow>
              <SectionTitle lead="Nineteen scenarios," trail="one engine." className="mt-6" />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                The lab expectation column is what the scenario was written to demonstrate. The
                engine column is what the policy engine actually produced when it ran. They are
                separate columns on purpose — a demonstration where the two cannot disagree is not
                a demonstration.
              </p>
            </div>

            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(row) => row.name}
              empty="No scenarios in this source."
              caption={`Feed ${text(data.status.softwareVersion)} generated ${timestamp(
                data.status.generatedAt,
              )} · every row produced by running the real Module 1–4 pipelines`}
            />
          </Section>

          <Section>
            <div className="grid gap-6 lg:grid-cols-2">
              <Panel className="p-8">
                <h3 className="text-xl font-display mb-4">
                  {data.source === "DEMO" ? "You are looking at demo data" : "You are looking at live data"}
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  {data.source === "DEMO"
                    ? "These scenarios come from the synthetic attack lab. The forensics are real — the detectors, the cryptography and the policy engine all ran for each one — but the datasets, models and logs were generated to exercise them. Nothing here is output from a deployed system."
                    : `These results were published to ${data.status.directory} by an operator running a real assessment. The platform does not generate them, and it will not substitute demo data if they are missing.`}
                </p>
              </Panel>
              <Panel className="p-8">
                <h3 className="text-xl font-display mb-4">
                  {other.available
                    ? `The ${other.kind} source has ${other.scenarioCount} entr${other.scenarioCount === 1 ? "y" : "ies"}`
                    : `The ${other.kind} source is empty`}
                </h3>
                <p className="text-muted-foreground leading-relaxed mb-6">
                  {other.available
                    ? "Switching sources reloads every page against the other body of data. The two are never blended in one view."
                    : other.remedy}
                </p>
                {other.available ? (
                  <Link
                    href={other.kind === "LIVE" ? "/demo?source=live" : "/demo"}
                    className="group inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
                  >
                    Switch to {other.kind}
                    <span
                      aria-hidden="true"
                      className="group-hover:translate-x-1 transition-transform"
                    >
                      &rarr;
                    </span>
                  </Link>
                ) : null}
              </Panel>
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}
