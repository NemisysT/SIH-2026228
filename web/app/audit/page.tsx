import { PageShell, Section } from "@/components/platform/page-shell"
import { DataTable, type Column } from "@/components/platform/data-table"
import {
  CheckMark,
  Digest,
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

import { count, humanise, text, timestamp } from "@/lib/analyst/format"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"
import {
  chainView,
  provenanceSummary,
  recordViews,
  type ChainEntryView,
  type RecordView,
} from "@/lib/analyst/provenance"

export const dynamic = "force-dynamic"

/**
 * Audit / Provenance Trail (§16).
 *
 * The one semantic this page exists to get right: **a chain break localises to
 * the successor link.** Module 3 establishes that one link does not match its
 * predecessor. It does not establish that every later record is forged, and a
 * timeline that painted everything after the break red would claim exactly
 * that. So the break is marked, and later entries are rendered as *unverified
 * beyond the break* — visibly different from both "verified" and "failed".
 */
export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const data = await loadPageData(await searchParams)
  const report = data.bundle?.provenance ?? null
  const chain = chainView(report)
  const records = recordViews(report)
  const summary = provenanceSummary(report)

  const recordColumns: Column<RecordView>[] = [
    { key: "seq", header: "Seq", numeric: true, render: (row) => count(row.sequenceNumber) },
    { key: "id", header: "Record", render: (row) => <span className="font-mono text-xs">{row.recordId}</span> },
    {
      key: "digest",
      header: "Entry digest",
      render: (row) => <Digest value={row.entryDigest} head={14} />,
    },
    { key: "time", header: "Timestamp", render: (row) => <span className="font-mono text-xs">{timestamp(row.timestamp)}</span> },
    { key: "key", header: "Signer", render: (row) => <span className="font-mono text-xs">{row.signingKeyId}</span> },
    { key: "keystatus", header: "Key status", render: (row) => <Tag>{row.keyStatus}</Tag> },
    { key: "replay", header: "Replay", render: (row) => <Tag>{row.replayVerdict}</Tag> },
    {
      key: "valid",
      header: "Verification",
      render: (row) => (
        <span className="inline-flex items-center gap-2">
          <CheckMark state={row.valid ? "PASS" : "FAIL"} />
          <span className="font-mono text-xs">
            {row.valid ? "VALID" : row.failures.join(", ") || "FAILED"}
          </span>
        </span>
      ),
    },
  ]

  return (
    <PageShell
      data={data}
      eyebrow="Module 3 · Audit and provenance trail"
      title={
        <>
          <span className="block">The chain,</span>
          <span className="block text-white/40">link by link.</span>
        </>
      }
      lede="Each entry commits to its predecessor's digest. A break therefore localises to one link — the one whose declared predecessor does not match what the log actually holds — and this page marks that link and no other."
      stats={
        report
          ? [
              { value: count(chain.entryCount), label: "entries" },
              { value: chain.status, label: "chain status" },
              {
                value:
                  chain.firstBreakPosition === null ? "none" : `#${chain.firstBreakPosition}`,
                label: "first break position",
              },
              { value: chain.truncationStatus, label: "truncation" },
            ]
          : undefined
      }
    >
      {!report ? (
        <Section>
          <EmptyState
            title="No provenance log to audit"
            reason="This scenario supplied no provenance report, so there is no chain, no signing trail and no replay history to show."
            remedy="cvtrust provenance verify-log <log.jsonl> --out reports/live/provenance.json"
          />
        </Section>
      ) : (
        <>
          <Section>
            <div className="grid gap-6 lg:grid-cols-3 mb-12">
              <Panel className="p-8 lg:col-span-2">
                <Eyebrow>Chain state</Eyebrow>
                <FieldGrid columns={2}>
                  <Field label="Log id" value={chain.logId} mono />
                  <Field
                    label="Head digest"
                    value={<Digest value={chain.headDigest} head={22} />}
                    title={chain.headDigest}
                  />
                  <Field label="Anchor supplied" value={chain.anchorSupplied ? "yes" : "no"} />
                  <Field
                    label="Mixed log ids"
                    value={chain.mixedLogIds.length === 0 ? "none" : chain.mixedLogIds.join(", ")}
                  />
                </FieldGrid>
                {chain.truncationDetail ? (
                  <p className="mt-8 text-sm text-muted-foreground leading-relaxed">
                    {chain.truncationDetail}
                  </p>
                ) : null}
              </Panel>
              <Panel className="p-8 flex flex-col gap-8">
                <Stat
                  value={count(summary.recordsIntact)}
                  label="Cryptographically intact"
                  sublabel={`of ${count(summary.recordsTotal)} records`}
                />
                <Stat value={count(summary.malformedLines)} label="Malformed lines" />
              </Panel>
            </div>

            {chain.firstBreakPosition !== null ? (
              <Panel className="p-8 border-destructive/40 bg-destructive/[0.04]">
                <h3 className="text-xl font-display mb-3">
                  The break localises to position {chain.firstBreakPosition}
                </h3>
                <p className="text-muted-foreground leading-relaxed max-w-3xl">
                  The verifier establishes that this link&rsquo;s declared predecessor digest does
                  not match the entry before it. It does <strong>not</strong> establish that the
                  records after it are forged — only that the chain no longer vouches for their
                  ordering. Entries beyond the break are marked unverified rather than invalid,
                  because that is what the verification result actually supports.
                </p>
              </Panel>
            ) : null}
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="mb-12">
              <Eyebrow>Chain timeline</Eyebrow>
              <SectionTitle lead="Entry" trail="to entry." className="mt-6" />
            </div>

            <ol className="space-y-0">
              {chain.entries.map((entry, index) => (
                <ChainEntry key={entry.recordId || index} entry={entry} last={index === chain.entries.length - 1} />
              ))}
            </ol>
          </Section>

          <Section>
            <div className="mb-12">
              <Eyebrow>Signing trail</Eyebrow>
              <SectionTitle lead="Every record," trail="every signer." className="mt-6" />
            </div>
            <DataTable
              columns={recordColumns}
              rows={records}
              rowKey={(row, index) => row.recordId || String(index)}
              empty="The log held no records."
              caption={`Validity policy ${summary.validityPolicy} · ${
                summary.trustStoreSupplied
                  ? `${count(summary.trustedKeyCount)} trusted key(s), ${count(summary.revokedKeyCount)} revoked`
                  : "no trust store supplied, so key trust could not be established"
              }`}
            />

            {Object.keys(summary.byFailureCode).length > 0 ? (
              <div className="mt-10">
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                  Failure codes observed
                </h4>
                <div className="flex flex-wrap gap-3">
                  {Object.entries(summary.byFailureCode).map(([code, n]) => (
                    <span key={code} className="inline-flex items-center gap-2">
                      <Tag active={code !== "VALID"}>{code}</Tag>
                      <span className="font-mono text-sm">{n}</span>
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </Section>

          <Section className="bg-foreground/[0.015]">
            <div className="grid gap-10 lg:grid-cols-2">
              <div>
                <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                  Chain guarantees
                </h4>
                <dl className="space-y-2">
                  {Object.entries(chain.guarantees).map(([guarantee, value]) => (
                    <div key={guarantee} className="flex gap-3 text-sm">
                      <dt className="font-mono text-muted-foreground w-48 shrink-0">
                        {humanise(guarantee)}
                      </dt>
                      <dd className="text-muted-foreground">{value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
              <NoteList title="Module 3 limitations" items={report.limitations ?? []} />
            </div>
          </Section>
        </>
      )}
    </PageShell>
  )
}

/** One link. Break, verified, or unverified-beyond-the-break — three states, not two. */
function ChainEntry({ entry, last }: { entry: ChainEntryView; last: boolean }) {
  const tone = entry.isBreak
    ? "border-destructive/50 bg-destructive/[0.05]"
    : entry.afterBreak
      ? "border-foreground/10 bg-foreground/[0.01] opacity-80"
      : "border-foreground/10 bg-foreground/[0.02]"

  return (
    <li>
      <div className={`border ${tone} p-6`}>
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <span className="font-mono text-2xl font-display text-muted-foreground">
            {String(entry.position).padStart(3, "0")}
          </span>
          <CheckMark state={entry.isBreak ? "FAIL" : entry.afterBreak ? "NEUTRAL" : entry.state} />
          <span className="font-mono text-sm break-all">{entry.recordId}</span>
          <Tag active={entry.isBreak}>
            {entry.isBreak
              ? "CHAIN BREAK"
              : entry.afterBreak
                ? "UNVERIFIED BEYOND BREAK"
                : entry.linkStatus}
          </Tag>
          {entry.sequenceValid ? null : <Tag active>SEQUENCE {entry.sequenceNumber} ≠ {entry.sequenceExpected}</Tag>}
        </div>

        <FieldGrid columns={3}>
          <Field
            label="Entry digest"
            value={<Digest value={entry.entryDigest} head={18} />}
            title={entry.entryDigest}
          />
          <Field
            label="Declared previous"
            value={<Digest value={entry.declaredPrevious ?? "—"} head={18} />}
            title={entry.declaredPrevious ?? undefined}
          />
          <Field
            label="Expected previous"
            value={<Digest value={entry.expectedPrevious ?? "—"} head={18} />}
            title={entry.expectedPrevious ?? undefined}
          />
        </FieldGrid>

        {entry.detail ? (
          <p className="mt-4 text-sm text-muted-foreground leading-relaxed">{entry.detail}</p>
        ) : null}

        {entry.afterBreak ? (
          <p className="mt-4 text-xs font-mono text-muted-foreground">
            This entry&rsquo;s own signature and bindings were still checked; what the chain no
            longer vouches for is its position relative to the break.
          </p>
        ) : null}

        {entry.record ? (
          <div className="mt-4 flex flex-wrap gap-3 text-xs font-mono text-muted-foreground">
            <span>signer {entry.record.signing_key_id}</span>
            <span>key {entry.record.key_status}</span>
            <span>replay {entry.record.replay_verdict}</span>
            <span>{timestamp(entry.record.timestamp)}</span>
          </div>
        ) : null}
      </div>
      {last ? null : (
        <div aria-hidden="true" className="flex justify-center py-2">
          <span className="font-mono text-muted-foreground">↓</span>
        </div>
      )}
    </li>
  )
}
