import Link from "next/link"

import { PageShell, Section } from "@/components/platform/page-shell"
import { FindingCard } from "@/components/platform/finding-card"
import { VerificationChain } from "@/components/platform/verification-chain"
import {
  CheckMark,
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
import { count, humanise, text, timestamp } from "@/lib/analyst/format"
import { linkSuffix, loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import { chainView, firstFailure, provenanceSummary, recordViews } from "@/lib/analyst/provenance"

export const dynamic = "force-dynamic"

/**
 * Inference Provenance (§10) — Module 3's report, rendered.
 *
 * The page opens on the first record that failed, if there is one, because
 * that is the record an analyst wants. Every record's full verification is
 * reachable, passing checks included: a chain of eight green ticks is a
 * finding too.
 */
export default async function ProvenancePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.provenance ?? null
  const summary = provenanceSummary(report)
  const chain = chainView(report)
  const records = recordViews(report)
  const failure = firstFailure(report)
  const focus = failure ?? records[0] ?? null
  const scope = scopeViews(data.bundle?.assurance ?? null)[2]
  const suffix = linkSuffix(data.source, data.scenario?.name)

  return (
    <PageShell
      data={data}
      eyebrow="Module 3 · Inference provenance"
      title={
        <>
          <span className="block">Did this output</span>
          <span className="block text-white/40">come from this model?</span>
        </>
      }
      lede="Provenance binds an input, its preprocessing, the model, the inference configuration and the output into one signed record, then links the records into a chain. Each binding is verified separately, and each one can fail on its own."
      stats={
        report
          ? [
              { value: count(summary.recordsTotal), label: "records in the log" },
              { value: count(summary.recordsValid), label: "records fully valid" },
              { value: summary.chainStatus, label: "chain status" },
              { value: summary.signatureAlgorithm || "—", label: "signature algorithm" },
            ]
          : undefined
      }
    >
      {!report ? (
        <Section>
          <EmptyState
            title="No provenance log was verified in this run"
            reason={
              scope.statement ||
              "This scenario supplied no provenance report. Nothing binds the observed outputs to the assured model, and nothing has been checked — which is not the same as a chain that verified."
            }
            remedy="cvtrust provenance verify-log <log.jsonl> --trust-store <trust_store.json> --out reports/live/provenance.json"
          />
        </Section>
      ) : (
        <>
          <Section>
            <div className="grid gap-6 lg:grid-cols-3 mb-12">
              <Panel className="p-8 lg:col-span-2">
                <h3 className="text-xl font-display mb-4">Module 3 disposition</h3>
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
                  Module 3 own summary: {summary.overall}
                </p>
              </Panel>
              <Panel className="p-8 flex flex-col gap-8">
                <Stat
                  value={`${count(summary.recordsValid)}/${count(summary.recordsTotal)}`}
                  label="Records valid"
                  sublabel={`${count(summary.recordsIntact)} cryptographically intact`}
                />
                <Stat
                  value={count(summary.replayDetected)}
                  label="Replays detected"
                  sublabel={
                    summary.replayDatabaseSupplied
                      ? "against the supplied replay database"
                      : "no replay database was supplied"
                  }
                />
              </Panel>
            </div>

            <Panel className="p-8 lg:p-10">
              <Eyebrow>Cryptographic model</Eyebrow>
              <FieldGrid columns={4}>
                <Field label="Hash" value={summary.hashAlgorithm} mono />
                <Field label="Signature" value={summary.signatureAlgorithm} mono />
                <Field label="Validity policy" value={summary.validityPolicy} mono />
                <Field
                  label="Trust store"
                  value={
                    summary.trustStoreSupplied
                      ? `${count(summary.trustedKeyCount)} trusted · ${count(summary.revokedKeyCount)} revoked`
                      : "not supplied"
                  }
                />
                <Field label="Anchor supplied" value={summary.anchorSupplied ? "yes" : "no"} />
                <Field
                  label="Replay database"
                  value={summary.replayDatabaseSupplied ? "supplied" : "not supplied"}
                />
                <Field label="Malformed lines" value={count(summary.malformedLines)} />
                <Field label="Truncation" value={summary.truncationStatus} mono />
              </FieldGrid>
              {!summary.anchorSupplied ? (
                <p className="mt-8 text-sm text-muted-foreground leading-relaxed max-w-3xl">
                  No external anchor was supplied, so front-truncation of the log cannot be
                  detected: a chain that is internally consistent is still consistent after its
                  first N entries are removed. The coverage statement records this as a gap rather
                  than letting the chain status imply more than it establishes.
                </p>
              ) : null}
            </Panel>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Binding verification</Eyebrow>
              <SectionTitle
                lead={failure ? "Where it broke." : "Every link,"}
                trail={failure ? undefined : "verified."}
                className="mt-6"
              />
              <p className="mt-8 text-muted-foreground max-w-3xl leading-relaxed">
                {failure
                  ? `Record ${failure.recordId} at position ${failure.position} is the first that failed. Below is its full verification — the checks that failed, the checks that passed, and the observation the verifier recorded for each.`
                  : "No record failed. The stages below are the checks that were actually performed; a stage marked NOT ASSESSED did not run, and its absence is not a pass."}
              </p>
            </div>

            {focus ? (
              <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
                <Panel className="p-8 h-fit">
                  <h3 className="text-xl font-display mb-6">Record under inspection</h3>
                  <FieldGrid columns={2}>
                    <Field label="Record id" value={focus.recordId} mono />
                    <Field label="Position" value={`${focus.position} · seq ${count(focus.sequenceNumber)}`} />
                    <Field
                      label="Entry digest"
                      value={<Digest value={focus.entryDigest} head={20} />}
                      title={focus.entryDigest}
                    />
                    <Field label="Timestamp" value={timestamp(focus.timestamp)} mono />
                    <Field label="Signing key" value={focus.signingKeyId} mono />
                    <Field label="Key status" value={focus.keyStatus} mono />
                    <Field
                      label="Input digest"
                      value={<Digest value={focus.inputDigest} head={20} />}
                      title={focus.inputDigest}
                    />
                    <Field label="Model id" value={focus.modelId} mono />
                    <Field
                      label="Model SHA-256"
                      value={<Digest value={focus.modelSha256} head={20} />}
                      title={focus.modelSha256}
                    />
                    <Field label="Replay verdict" value={focus.replayVerdict} mono />
                    <Field label="Output" value={focus.outputSummary} mono />
                    <Field
                      label="Overall"
                      value={
                        <span className="inline-flex items-center gap-2">
                          <CheckMark state={focus.valid ? "PASS" : "FAIL"} />
                          {focus.valid ? "valid" : "failed verification"}
                        </span>
                      }
                    />
                  </FieldGrid>
                  {focus.failures.length > 0 ? (
                    <div className="mt-8">
                      <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                        Failure codes
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {focus.failures.map((code) => (
                          <Tag key={code} active>
                            {code}
                          </Tag>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </Panel>

                <div>
                  <VerificationChain stages={focus.stages} />
                </div>
              </div>
            ) : (
              <EmptyState
                title="The log contained no records"
                reason="Module 3 parsed the log and found nothing to verify."
              />
            )}
          </Section>

          <Section>
            <div className="mb-12 flex flex-wrap items-end justify-between gap-6">
              <div>
                <Eyebrow>Chain</Eyebrow>
                <SectionTitle lead="Record to record." className="mt-6" />
              </div>
              <Link
                href={`/audit${suffix}`}
                className="group inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
              >
                Open the full audit trail
                <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">
                  &rarr;
                </span>
              </Link>
            </div>

            <Panel className="p-8">
              <FieldGrid columns={4}>
                <Field label="Chain status" value={chain.status} mono />
                <Field label="Entries" value={count(chain.entryCount)} />
                <Field
                  label="Head digest"
                  value={<Digest value={chain.headDigest} head={20} />}
                  title={chain.headDigest}
                />
                <Field
                  label="First break"
                  value={
                    chain.firstBreakPosition === null
                      ? "none"
                      : `position ${chain.firstBreakPosition}`
                  }
                />
              </FieldGrid>
              {chain.detail ? (
                <p className="mt-8 text-sm text-muted-foreground leading-relaxed max-w-3xl">
                  {chain.detail}
                </p>
              ) : null}
              {Object.keys(chain.guarantees).length > 0 ? (
                <div className="mt-8">
                  <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                    What this chain construction does and does not guarantee
                  </h4>
                  <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2">
                    {Object.entries(chain.guarantees).map(([guarantee, value]) => (
                      <div key={guarantee} className="flex gap-3 text-sm">
                        <dt className="font-mono text-muted-foreground w-44 shrink-0">
                          {humanise(guarantee)}
                        </dt>
                        <dd className="text-muted-foreground">{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ) : null}
            </Panel>
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Findings</Eyebrow>
              <SectionTitle lead="What Module 3" trail="recorded." className="mt-6" />
            </div>
            {(report.findings ?? []).length === 0 ? (
              <EmptyState
                title="No provenance findings"
                reason={`Every record the log contained verified against the supplied trust store and policy. ${summary.rationale}`}
                tone="ACCEPT"
              />
            ) : (
              <div className="space-y-4">
                {(report.findings ?? []).map((finding, index) => (
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
            <NoteList title="Module 3 limitations" items={report.limitations ?? []} />
          </Section>
        </>
      )}
    </PageShell>
  )
}
