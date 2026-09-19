import { PageShell, Section } from "@/components/platform/page-shell"
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
  SectionTitle as Title,
  Stat,
  Tag,
} from "@/components/platform/primitives"

import { scopeViews } from "@/lib/analyst/assurance"
import { count, humanise, text, titleise } from "@/lib/analyst/format"
import {
  accessView,
  backdoorCoverage,
  levelViews,
  modelIdentity,
  type LevelTone,
} from "@/lib/analyst/model"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"

export const dynamic = "force-dynamic"

const TONE_DOT: Record<LevelTone, string> = {
  CLEAN: "bg-[#eca8d6]",
  ANOMALOUS: "bg-destructive",
  NEUTRAL: "bg-foreground/30",
}

/**
 * Model Forensics (§9) — Module 2's report, rendered.
 *
 * The six levels stay categorical. Turning CONSISTENT / MISMATCH /
 * ANOMALOUS / NO_ANOMALY_DETECTED / NOT_ASSESSED into a percentage would
 * invent precision the detectors never claimed, so nothing on this page is a
 * percentage and nothing is averaged.
 */
export default async function ModelPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.model ?? null
  const identity = modelIdentity(report)
  const access = accessView(report)
  const levels = levelViews(report)
  const backdoor = backdoorCoverage(report)
  const scope = scopeViews(data.bundle?.assurance ?? null)[1]
  const findings = report?.findings ?? []
  const summary = (report?.summary ?? {}) as Record<string, unknown>

  return (
    <PageShell
      data={data}
      eyebrow="Module 2 · Model forensics"
      title={
        <>
          <span className="block">Is this the model</span>
          <span className="block text-white/40">you assured?</span>
        </>
      }
      lede="Module 2 asks six separate questions about the artifact and refuses to merge the answers. A model can be structurally identical to its reference and still behave differently on a trigger, so identity, structure, parameters, behaviour, activation and trigger each keep their own verdict."
      stats={
        identity
          ? [
              { value: identity.modelId, label: "model id" },
              { value: identity.format, label: "format" },
              { value: count(identity.parameterCount), label: "parameters" },
              { value: access.mode, label: "access mode" },
            ]
          : undefined
      }
    >
      {!report || !identity ? (
        <Section>
          <EmptyState
            title="No model was assessed in this run"
            reason={
              scope.statement ||
              "This scenario supplied no model report to the assurance pipeline. Module 2 contributed nothing, which is different from Module 2 finding nothing."
            }
            remedy="cvtrust model assess <model.onnx> --reference <reference.onnx> --out reports/live/model.json"
          />
        </Section>
      ) : (
        <>
          <Section>
            <div className="mb-12">
              <Eyebrow>Artifact identity</Eyebrow>
              <SectionTitle lead="What was" trail="examined." className="mt-6" />
            </div>

            <Panel className="p-8 lg:p-10 mb-6">
              <FieldGrid columns={3}>
                <Field label="Model id" value={identity.modelId} mono />
                <Field label="Manifest id" value={identity.manifestId} mono />
                <Field label="Format" value={identity.format} />
                <Field
                  label="File SHA-256"
                  value={<Digest value={identity.fileSha256} head={24} />}
                  title={identity.fileSha256}
                />
                <Field
                  label="Graph digest"
                  value={<Digest value={identity.graphDigest} head={24} />}
                  title={identity.graphDigest}
                />
                <Field
                  label="Parameter digest"
                  value={<Digest value={identity.parameterDigest} head={24} />}
                  title={identity.parameterDigest}
                />
                <Field
                  label="Declared architecture"
                  value={
                    <span className="flex flex-wrap items-center gap-2">
                      {identity.architectureDeclared}
                      {identity.architectureIsUntrusted ? <Tag>untrusted claim</Tag> : null}
                    </span>
                  }
                />
                <Field label="Parameters / layers" value={`${count(identity.parameterCount)} · ${count(identity.layerCount)}`} />
                <Field label="File size" value={`${count(identity.fileSizeBytes)} bytes`} />
                <Field
                  label="Inputs"
                  value={identity.inputs
                    .map((input) => `${text(input.name)} ${JSON.stringify(input.shape ?? [])}`)
                    .join(", ")}
                  mono
                />
                <Field
                  label="Outputs"
                  value={identity.outputs
                    .map((output) => `${text(output.name)} ${JSON.stringify(output.shape ?? [])}`)
                    .join(", ")}
                  mono
                />
                <Field
                  label="Operators"
                  value={Object.entries(identity.operators)
                    .map(([op, n]) => `${op}×${n}`)
                    .join(" · ")}
                  mono
                />
              </FieldGrid>

              {identity.architectureIsUntrusted ? (
                <p className="mt-8 text-sm text-muted-foreground leading-relaxed max-w-3xl">
                  The declared architecture is metadata the artifact carries about itself. It is
                  recorded because it is useful, and marked untrusted because an attacker who can
                  replace a model can also write whatever they like in its metadata. Nothing on
                  this page relies on it.
                </p>
              ) : null}
            </Panel>

            <div className="grid gap-6 lg:grid-cols-3">
              <Panel className="p-8 lg:col-span-2">
                <h3 className="text-xl font-display mb-4">Module 2 disposition</h3>
                <div className="flex flex-wrap items-center gap-4 mb-4">
                  <DispositionBadge value={scope.disposition} size="lg" />
                  <span className="font-mono text-xs text-muted-foreground">
                    {scope.governingRule ?? "no rule fired"}
                  </span>
                </div>
                <p className="text-muted-foreground leading-relaxed">
                  {scope.statement || text(summary.rationale, "")}
                </p>
              </Panel>
              <Panel className="p-8 flex flex-col gap-8">
                <Stat
                  value={count(summary.assessed_levels)}
                  label="Levels assessed"
                  sublabel={`${count(summary.unassessed_levels)} not assessed`}
                />
                <Stat value={count(findings.length)} label="Findings" />
              </Panel>
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Assessment levels</Eyebrow>
              <Title lead="Six questions," trail="six answers." className="mt-6" />
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {levels.map((level) => (
                <Panel key={level.level} className="p-6 lg:p-8 flex flex-col">
                  <div className="flex items-center gap-3 mb-4">
                    <span aria-hidden="true" className={`w-2 h-2 rounded-full ${TONE_DOT[level.tone]}`} />
                    <h3 className="text-xl font-display">{level.title}</h3>
                  </div>
                  <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground mb-4">
                    {level.status}
                  </span>
                  <p className="text-sm text-muted-foreground leading-relaxed flex-1">
                    {level.detail || "No detail was recorded for this level."}
                  </p>
                  {level.reason ? (
                    <p className="mt-4 text-sm text-muted-foreground leading-relaxed border-l border-foreground/15 pl-4">
                      {level.reason}
                    </p>
                  ) : null}
                  <div className="mt-6 flex flex-wrap items-center gap-2">
                    <Tag>{level.detector || "no detector"}</Tag>
                    {level.evidenceKeys.map((key) => (
                      <Tag key={key}>{humanise(key)}</Tag>
                    ))}
                  </div>
                </Panel>
              ))}
            </div>
          </Section>

          <Section>
            <div className="mb-12">
              <Eyebrow>Access and capability</Eyebrow>
              <SectionTitle lead="What this access" trail="makes possible." className="mt-6" />
            </div>

            <div className="grid gap-6 lg:grid-cols-2">
              <Panel className="p-8">
                <FieldGrid columns={2}>
                  <Field label="Access mode" value={access.mode} mono />
                  <Field label="Forced black box" value={access.forcedBlackBox ? "yes" : "no"} />
                  <Field label="Adapter" value={`${access.adapter} ${access.adapterVersion}`} mono />
                  <Field
                    label="Trusted reference"
                    value={access.hasReference ? "supplied" : "not supplied"}
                  />
                </FieldGrid>
                <div className="mt-8">
                  <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                    Capabilities present
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {access.capabilities.length === 0 ? (
                      <span className="text-sm text-muted-foreground">None recorded.</span>
                    ) : (
                      access.capabilities.map((capability) => (
                        <Tag key={capability} active>
                          {humanise(capability)}
                        </Tag>
                      ))
                    )}
                  </div>
                </div>
                <div className="mt-6">
                  <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                    Capabilities absent
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {access.capabilitiesAbsent.length === 0 ? (
                      <span className="text-sm text-muted-foreground">None.</span>
                    ) : (
                      access.capabilitiesAbsent.map((capability) => (
                        <Tag key={capability}>{humanise(capability)}</Tag>
                      ))
                    )}
                  </div>
                </div>
                <NoteList
                  title="Consequences of this access mode"
                  items={access.consequences}
                  emptyLabel="None recorded."
                />
              </Panel>

              <Panel className="p-8">
                <h3 className="text-xl font-display mb-2">Backdoor coverage</h3>
                <p className="text-sm text-muted-foreground leading-relaxed mb-6">
                  &ldquo;No backdoor finding&rdquo; and &ldquo;no backdoor detector ran&rdquo; are
                  opposite statements that a findings list alone renders identically. This block
                  keeps them apart.
                </p>
                <FieldGrid columns={2}>
                  <Field label="Probe battery" value={`${count(backdoor.probeCount)} probes`} />
                  <Field
                    label="Probe categories"
                    value={Object.entries(backdoor.probesByCategory)
                      .map(([category, n]) => `${category}×${n}`)
                      .join(" · ")}
                    mono
                  />
                  <Field
                    label="Declared trigger family"
                    value={`${backdoor.triggerFamily.length} variant(s) probed`}
                  />
                  <Field
                    label="External benchmark"
                    value={backdoor.benchmarkAvailable ? "available" : "not available"}
                  />
                </FieldGrid>
                {backdoor.benchmarkReason ? (
                  <p className="mt-6 text-sm text-muted-foreground leading-relaxed border-l border-foreground/15 pl-4">
                    {backdoor.benchmarkReason}
                  </p>
                ) : null}
                <div className="mt-8 space-y-4">
                  {backdoor.entries.map((entry) => (
                    <div key={entry.attackClass} className="border-t border-foreground/10 pt-4">
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <span className="font-medium">{entry.title || titleise(entry.attackClass)}</span>
                        <CoverageBadge value={entry.coverage} />
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{entry.reason}</p>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Findings</Eyebrow>
              <SectionTitle lead="What Module 2" trail="recorded." className="mt-6" />
            </div>
            {findings.length === 0 ? (
              <EmptyState
                title="No model findings"
                reason={`Module 2 ran and recorded nothing actionable for this artifact. ${text(summary.rationale, "")}`}
                tone="ACCEPT"
              />
            ) : (
              <div className="space-y-4">
                {findings.map((finding, index) => (
                  <FindingCard
                    key={finding.finding_id ?? index}
                    finding={finding}
                    defaultOpen={index === 0}
                  />
                ))}
              </div>
            )}
          </Section>

          <Section>
            <NoteList title="Module 2 limitations" items={report.limitations ?? []} />
          </Section>
        </>
      )}
    </PageShell>
  )
}
