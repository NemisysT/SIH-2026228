"use client"

import { useMemo, useState } from "react"

import { AsciiScene } from "@/components/landing/ascii-scene"

/**
 * The Evidence Explorer (§12).
 *
 * The drill-down the brief specifies, as a client component so an analyst can
 * walk it without a round trip:
 *
 *   DECISION → POLICY RULE → SUPPORTING EVIDENCE → SOURCE MODULE →
 *   DETECTOR → RAW OBSERVATION → ASSUMPTIONS → LIMITATIONS
 *
 * The panel behind the header is the reference's ASCII torus-knot scene,
 * reused unchanged.
 *
 * Two rules hold throughout. Evidence is never rewritten on its way to the
 * screen: DETERMINISTIC stays deterministic, CALIBRATED stays calibrated,
 * NOT_ASSESSED stays NOT_ASSESSED. And a confounded item keeps its confounder
 * attached, so several detectors watching one phenomenon never read as several
 * independent attacks.
 */

export interface ExplorerRule {
  ruleId: string
  scope: string
  disposition: string
  statement: string
  rationale: string
  families: string[]
  evidenceIds: string[]
  observation: Record<string, unknown>
}

export interface ExplorerEvidence {
  evidenceId: string
  findingId: string
  title: string
  module: number | null
  detector: string
  detectorVersion: string
  evidenceClass: string
  attackClass: string
  dependencyGroup: string
  severity: string
  confidence: string
  basis: string
  coverage: string
  supports: boolean
  supportReason: string
  confoundedBy: string[]
  activeConfounders: string[]
  assumptions: string[]
  limitations: string[]
  rawObservation: Record<string, unknown>
  sourceReportId: string
  sourceRunId: string
  refs: string[]
  assetId: string
  assetLocator: string
  contributor: string
  findingStatements: string[]
}

export interface ExplorerFamily {
  family: string
  evidenceClass: string
  detectors: string[]
  evidenceIds: string[]
  corroboration: number
  maxSeverity: string
  supporting: number
  contextOnly: number
  confounded: boolean
  activeConfounders: string[]
  independent: boolean
}

export function EvidenceExplorer({
  disposition,
  decisionId,
  summary,
  rules,
  evidence,
  families,
}: {
  disposition: string
  decisionId: string
  summary: string
  rules: ExplorerRule[]
  evidence: ExplorerEvidence[]
  families: ExplorerFamily[]
}) {
  const [ruleIndex, setRuleIndex] = useState(0)
  const [evidenceId, setEvidenceId] = useState<string | null>(null)

  const byId = useMemo(() => {
    const map = new Map<string, ExplorerEvidence>()
    for (const item of evidence) map.set(item.evidenceId, item)
    return map
  }, [evidence])

  const rule = rules[ruleIndex] ?? null
  const ruleEvidence = useMemo(() => {
    if (!rule) return []
    return rule.evidenceIds
      .map((id) => byId.get(id))
      .filter((item): item is ExplorerEvidence => item !== undefined)
  }, [rule, byId])

  const selected =
    (evidenceId ? byId.get(evidenceId) ?? null : null) ?? ruleEvidence[0] ?? evidence[0] ?? null

  return (
    <div className="relative">
      {/* Step 1: the decision */}
      <div className="relative border border-foreground/10 bg-black overflow-hidden mb-6 min-h-[280px]">
        <AsciiScene />
        <div className="relative z-10 p-8 lg:p-12">
          <span className="font-mono text-xs uppercase tracking-widest text-white/40">
            Step 1 · Decision
          </span>
          <h3 className="mt-4 text-4xl lg:text-5xl font-display text-white">{disposition}</h3>
          <p className="mt-2 font-mono text-xs text-white/40">{decisionId}</p>
          <p className="mt-6 max-w-3xl text-white/70 leading-relaxed">{summary}</p>
        </div>
      </div>

      {/* Step 2: the rules that produced it */}
      <div className="border border-foreground/10 bg-foreground/[0.02] p-6 lg:p-8 mb-6">
        <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Step 2 · Policy rule
        </span>
        {rules.length === 0 ? (
          <p className="mt-6 text-muted-foreground">
            No rule fired for this decision. With no input supplied there is nothing for a rule to
            match, and the disposition is NOT_ASSESSED rather than ACCEPT.
          </p>
        ) : (
          <>
            <div className="mt-6 flex flex-wrap gap-2">
              {rules.map((entry, index) => (
                <button
                  key={entry.ruleId + entry.scope}
                  type="button"
                  onClick={() => {
                    setRuleIndex(index)
                    setEvidenceId(null)
                  }}
                  aria-pressed={index === ruleIndex}
                  className={`px-4 py-2 text-xs font-mono border transition-all ${
                    index === ruleIndex
                      ? "border-foreground bg-foreground text-background"
                      : "border-foreground/15 text-muted-foreground hover:border-foreground/40"
                  }`}
                >
                  {entry.ruleId}
                  <span className="opacity-60"> · {entry.scope}</span>
                </button>
              ))}
            </div>

            {rule ? (
              <div className="mt-8 grid gap-8 lg:grid-cols-[1.2fr_1fr]">
                <div>
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <span className="text-2xl font-display">{rule.ruleId}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                      {rule.disposition}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                      scope {rule.scope}
                    </span>
                  </div>
                  <p className="text-base leading-relaxed mb-4">{rule.statement}</p>
                  <p className="text-sm text-muted-foreground leading-relaxed">{rule.rationale}</p>
                  {rule.families.length > 0 ? (
                    <p className="mt-4 text-xs font-mono text-muted-foreground">
                      families: {rule.families.join(", ")}
                    </p>
                  ) : null}
                </div>
                {Object.keys(rule.observation).length > 0 ? (
                  <pre className="text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-4 overflow-auto max-h-64">
                    {JSON.stringify(rule.observation, null, 2)}
                  </pre>
                ) : null}
              </div>
            ) : null}
          </>
        )}
      </div>

      {/* Step 3: the evidence the rule rested on */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,320px)_1fr]">
        <div className="border border-foreground/10 bg-foreground/[0.02] p-6">
          <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
            Step 3 · Supporting evidence
          </span>
          <p className="mt-3 text-xs text-muted-foreground">
            {ruleEvidence.length} item(s) named by this rule
          </p>
          <ul className="mt-6 space-y-1 max-h-[520px] overflow-y-auto pr-1">
            {(ruleEvidence.length > 0 ? ruleEvidence : evidence).map((item) => {
              const active = selected?.evidenceId === item.evidenceId
              return (
                <li key={item.evidenceId}>
                  <button
                    type="button"
                    onClick={() => setEvidenceId(item.evidenceId)}
                    aria-pressed={active}
                    className={`w-full text-left px-3 py-3 border transition-all ${
                      active
                        ? "border-foreground/40 bg-foreground/[0.05]"
                        : "border-transparent hover:border-foreground/20"
                    }`}
                  >
                    <span className="block font-mono text-[11px] text-muted-foreground">
                      {item.evidenceId}
                    </span>
                    <span className="block text-sm mt-1 break-words">{item.title}</span>
                    <span className="mt-2 flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                        {item.severity}
                      </span>
                      {item.activeConfounders.length > 0 ? (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                          confounded
                        </span>
                      ) : null}
                      {!item.supports ? (
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                          context only
                        </span>
                      ) : null}
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </div>

        {/* Steps 4-8: module, detector, observation, assumptions, limitations */}
        <div className="border border-foreground/10 bg-foreground/[0.02] p-6 lg:p-8">
          {!selected ? (
            <p className="text-muted-foreground">
              No evidence was carried into this decision. That is an outcome, not a gap: the
              coverage statement records what was examined to reach it.
            </p>
          ) : (
            <div className="space-y-8">
              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                  Step 4 · Source module
                </span>
                <h3 className="mt-3 text-2xl lg:text-3xl font-display break-words">
                  {selected.title}
                </h3>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Chip>
                    module {selected.module === null ? "—" : selected.module}
                  </Chip>
                  <Chip>{selected.evidenceClass}</Chip>
                  <Chip>{selected.attackClass}</Chip>
                  <Chip>{selected.severity}</Chip>
                  <Chip>{selected.coverage}</Chip>
                </div>
              </div>

              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                  Step 5 · Detector
                </span>
                <dl className="mt-3 grid gap-4 sm:grid-cols-2">
                  <Fact label="Detector" value={`${selected.detector} ${selected.detectorVersion}`} />
                  <Fact label="Confidence" value={`${selected.confidence} · ${selected.basis}`} />
                  <Fact label="Finding" value={selected.findingId} />
                  <Fact label="Source report" value={selected.sourceReportId} />
                  <Fact label="Source run" value={selected.sourceRunId} />
                  <Fact label="Dependency group" value={selected.dependencyGroup} />
                  <Fact label="Asset" value={selected.assetId} />
                  <Fact label="Contributor" value={selected.contributor} />
                </dl>
                <p className="mt-4 text-sm text-muted-foreground leading-relaxed">
                  {selected.supports
                    ? `Counted as supporting evidence. ${selected.supportReason}`
                    : `Carried as context rather than support. ${selected.supportReason}`}
                </p>
                {selected.activeConfounders.length > 0 ? (
                  <p className="mt-3 text-sm text-muted-foreground leading-relaxed border-l border-foreground/20 pl-4">
                    Confounded by {selected.activeConfounders.join(", ")}. The same physical change
                    would produce this observation, so it is not counted as an independent
                    phenomenon.
                  </p>
                ) : selected.confoundedBy.length > 0 ? (
                  <p className="mt-3 text-sm text-muted-foreground leading-relaxed border-l border-foreground/20 pl-4">
                    Could be confounded by {selected.confoundedBy.join(", ")}, but none of those
                    phenomena is active in this run.
                  </p>
                ) : null}
              </div>

              <div>
                <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                  Step 6 · Raw observation
                </span>
                {selected.findingStatements.length > 0 ? (
                  <ul className="mt-3 space-y-2">
                    {selected.findingStatements.map((statement, index) => (
                      <li key={index} className="text-sm leading-relaxed flex gap-3">
                        <span aria-hidden="true" className="text-foreground/30 font-mono shrink-0">
                          —
                        </span>
                        <span>{statement}</span>
                      </li>
                    ))}
                  </ul>
                ) : null}
                {Object.keys(selected.rawObservation).length > 0 ? (
                  <pre className="mt-4 text-[11px] font-mono text-muted-foreground bg-foreground/[0.03] border border-foreground/10 p-4 overflow-auto max-h-80">
                    {JSON.stringify(selected.rawObservation, null, 2)}
                  </pre>
                ) : (
                  <p className="mt-3 text-sm text-muted-foreground">
                    The detector recorded no raw observation for this item.
                  </p>
                )}
                {selected.refs.length > 0 ? (
                  <p className="mt-3 text-xs font-mono text-muted-foreground break-all">
                    refs: {selected.refs.slice(0, 12).join(", ")}
                    {selected.refs.length > 12 ? ` … +${selected.refs.length - 12}` : ""}
                  </p>
                ) : null}
              </div>

              <div className="grid gap-8 sm:grid-cols-2">
                <div>
                  <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                    Step 7 · Assumptions
                  </span>
                  <NoteBullets items={selected.assumptions} />
                </div>
                <div>
                  <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                    Step 8 · Limitations
                  </span>
                  <NoteBullets items={selected.limitations} />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Families: §13's anti-double-counting view */}
      <div className="mt-6 border border-foreground/10 bg-foreground/[0.02] p-6 lg:p-8">
        <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
          Evidence families
        </span>
        <h3 className="mt-3 text-2xl font-display">One phenomenon, many detectors</h3>
        <p className="mt-3 text-sm text-muted-foreground leading-relaxed max-w-3xl">
          Findings are grouped into families before anything is counted. A family with an active
          confounder is not counted as an independent phenomenon, which is what stops three
          detectors observing one legitimate sensor change from reading as three separate attacks.
        </p>

        {families.length === 0 ? (
          <p className="mt-6 text-sm text-muted-foreground">No evidence family is present.</p>
        ) : (
          <ul className="mt-8 space-y-6">
            {families.map((family) => (
              <li key={family.family} className="border-t border-foreground/10 pt-6">
                <div className="flex flex-wrap items-center gap-3 mb-3">
                  <span className="text-xl font-display">{family.family}</span>
                  <Chip>{family.maxSeverity}</Chip>
                  <Chip>{family.evidenceIds.length} item(s)</Chip>
                  <Chip>
                    {family.independent ? "independent" : family.confounded ? "confounded" : "not independent"}
                  </Chip>
                </div>
                <ul className="ml-1 space-y-1">
                  {family.detectors.map((detector, index) => (
                    <li key={detector} className="text-sm text-muted-foreground font-mono">
                      <span aria-hidden="true">
                        {index === family.detectors.length - 1 ? "└── " : "├── "}
                      </span>
                      {detector}
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-sm text-muted-foreground">
                  {family.supporting} supporting · {family.contextOnly} context only
                  {family.activeConfounders.length > 0
                    ? ` · confounded by ${family.activeConfounders.join(", ")}`
                    : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function Chip({ children }: { children: React.ReactNode }) {
  return (
    <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider whitespace-nowrap">
      {children}
    </span>
  )
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
        {label}
      </dt>
      <dd className="text-sm font-mono break-words">{value}</dd>
    </div>
  )
}

function NoteBullets({ items }: { items: string[] }) {
  if (items.length === 0) {
    return <p className="mt-3 text-sm text-muted-foreground">None recorded.</p>
  }
  return (
    <ul className="mt-3 space-y-2">
      {items.map((item, index) => (
        <li key={index} className="text-sm text-muted-foreground leading-relaxed flex gap-3">
          <span aria-hidden="true" className="text-foreground/30 font-mono shrink-0">
            —
          </span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}
