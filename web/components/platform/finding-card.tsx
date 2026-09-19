import { confidence, humanise, text, titleise } from "@/lib/analyst/format"
import type { Finding } from "@/lib/analyst/types"

import { CoverageBadge, Digest, NoteList, Panel, SeverityBadge, Tag } from "./primitives"

/**
 * One finding, complete.
 *
 * The rule this component exists to hold: a finding is shown with its
 * evidence, its method, its assumptions, its limitations and the basis of its
 * confidence — never summarised down to a title and a colour. §12 puts it
 * plainly: do not summarise away the original finding. The `observation`
 * object each evidence item carries is the detector's raw measurement, and it
 * is rendered as the detector wrote it.
 */
export function FindingCard({
  finding,
  defaultOpen = false,
}: {
  finding: Finding
  defaultOpen?: boolean
}) {
  const evidence = finding.evidence ?? []
  return (
    <Panel as="article" className="p-6 lg:p-8">
      <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-3 mb-2">
            <SeverityBadge value={finding.severity} />
            <Tag>{humanise(finding.attack_class)}</Tag>
            <Tag>{humanise(finding.category)}</Tag>
          </div>
          <h3 className="text-xl lg:text-2xl font-display break-words">
            {text(finding.title, "Untitled finding")}
          </h3>
        </div>
        <div className="text-right shrink-0">
          <span className="block font-mono text-xs text-muted-foreground">
            {text(finding.finding_id)}
          </span>
          <span className="block font-mono text-xs text-muted-foreground mt-1">
            {confidence(finding.confidence, finding.confidence_basis)}
          </span>
        </div>
      </div>

      <dl className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6 text-sm">
        <div>
          <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
            Asset
          </dt>
          <dd className="break-words">
            {text(finding.asset?.id)}
            <span className="block text-xs text-muted-foreground font-mono break-all">
              {text(finding.asset?.locator, "")}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
            Digest
          </dt>
          <dd>
            <Digest value={finding.asset?.digest} />
          </dd>
        </div>
        <div>
          <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
            Contributor
          </dt>
          <dd className="break-words">{text(finding.contributor)}</dd>
        </div>
        <div>
          <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
            Method
          </dt>
          <dd className="font-mono text-xs break-words">
            {text(finding.method)} {text(finding.method_version, "")}
          </dd>
        </div>
      </dl>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <CoverageBadge value={finding.coverage} />
        <Tag>{text(finding.disposition, "NO DISPOSITION")}</Tag>
        <Tag>{text(finding.disposition_rule, "no rule")}</Tag>
      </div>

      <details open={defaultOpen} className="group">
        <summary className="cursor-pointer text-sm font-mono text-muted-foreground hover:text-foreground transition-colors list-none flex items-center gap-2">
          <span aria-hidden="true" className="group-open:rotate-90 transition-transform">
            &rsaquo;
          </span>
          {evidence.length} evidence item(s), with the detector&rsquo;s raw observation
        </summary>
        <div className="mt-6 space-y-6">
          {evidence.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              This finding carries no evidence items. That is unusual and worth questioning.
            </p>
          ) : (
            evidence.map((item, index) => (
              <div key={index} className="border-l border-foreground/15 pl-5">
                <div className="flex flex-wrap items-center gap-3 mb-2">
                  <Tag>{titleise(item.kind)}</Tag>
                  {(item.refs ?? []).length > 0 ? (
                    <span className="text-[11px] font-mono text-muted-foreground">
                      {(item.refs ?? []).length} reference(s)
                    </span>
                  ) : null}
                </div>
                <p className="text-sm leading-relaxed mb-3">{text(item.statement, "")}</p>
                {item.observation && Object.keys(item.observation).length > 0 ? (
                  <pre className="text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-4 overflow-x-auto max-h-72">
                    {JSON.stringify(item.observation, null, 2)}
                  </pre>
                ) : null}
              </div>
            ))
          )}

          <div className="grid gap-6 sm:grid-cols-2 pt-2">
            <NoteList title="Assumptions" items={finding.assumptions ?? []} />
            <NoteList title="Limitations" items={finding.limitations ?? []} />
          </div>
        </div>
      </details>
    </Panel>
  )
}
