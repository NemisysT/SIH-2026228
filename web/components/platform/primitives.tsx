import Link from "next/link"
import type { ReactNode } from "react"

import { EMPTY, asCoverage, asDisposition, asSeverity, shortDigest, text } from "@/lib/analyst/format"
import type { Coverage, Disposition } from "@/lib/analyst/types"

/**
 * The reference's own visual atoms, extracted so every page speaks the same
 * language instead of re-deriving it.
 *
 * Nothing here is new design. The eyebrow is the `w-12 h-px` rule plus mono
 * label the reference repeats at the top of every section; the panel is its
 * `border-foreground/10 bg-foreground/[0.02]` card; the tag is the category
 * chip from the integrations grid; the status dot is the region dot from the
 * infrastructure list. They are reproduced with the same classes.
 *
 * One rule runs through all of them: status is never carried by colour alone
 * (§27). Every badge prints its word, and the dot is decoration beside the
 * word, never instead of it.
 */

export function Eyebrow({
  children,
  tone = "default",
  centered = false,
}: {
  children: ReactNode
  tone?: "default" | "inverted"
  centered?: boolean
}) {
  const rule = tone === "inverted" ? "bg-white/20" : "bg-foreground/20"
  const label = tone === "inverted" ? "text-white/40" : "text-muted-foreground"
  return (
    <span
      className={`inline-flex items-center gap-4 text-sm font-mono ${label} ${
        centered ? "justify-center" : ""
      }`}
    >
      <span className={`w-12 h-px ${rule}`} />
      {children}
      {centered ? <span className={`w-12 h-px ${rule}`} /> : null}
    </span>
  )
}

/** The reference's section title: display serif, huge, with a muted second line. */
export function SectionTitle({
  lead,
  trail,
  className = "",
}: {
  lead: string
  trail?: string
  className?: string
}) {
  return (
    <h2
      className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9] ${className}`}
    >
      {lead}
      {trail ? (
        <>
          <br />
          <span className="text-muted-foreground">{trail}</span>
        </>
      ) : null}
    </h2>
  )
}

export function Panel({
  children,
  className = "",
  as: Component = "div",
}: {
  children: ReactNode
  className?: string
  as?: "div" | "section" | "li" | "article"
}) {
  return (
    <Component className={`border border-foreground/10 bg-foreground/[0.02] ${className}`}>
      {children}
    </Component>
  )
}

/** The integrations grid's category chip. */
export function Tag({
  children,
  active = false,
  className = "",
}: {
  children: ReactNode
  active?: boolean
  className?: string
}) {
  return (
    <span
      className={`text-[10px] font-mono px-2 py-0.5 whitespace-nowrap ${
        active ? "bg-foreground text-background" : "bg-foreground/10 text-muted-foreground"
      } ${className}`}
    >
      {children}
    </span>
  )
}

const DISPOSITION_DOT: Record<Disposition, string> = {
  ACCEPT: "bg-[#eca8d6]",
  REVIEW: "bg-[#fbbf24]",
  QUARANTINE: "bg-destructive",
  NOT_ASSESSED: "bg-foreground/30",
}

const DISPOSITION_BORDER: Record<Disposition, string> = {
  ACCEPT: "border-[#eca8d6]/50",
  REVIEW: "border-[#fbbf24]/50",
  QUARANTINE: "border-destructive/60",
  NOT_ASSESSED: "border-foreground/20",
}

/**
 * One of the four dispositions, spelled out.
 *
 * There is no score here and there will not be one. A disposition is a
 * decision the policy engine made; a number would imply it interpolated.
 */
export function DispositionBadge({
  value,
  size = "sm",
}: {
  value: unknown
  size?: "sm" | "lg"
}) {
  const disposition = asDisposition(value)
  return (
    <span
      className={`inline-flex items-center gap-2 border ${DISPOSITION_BORDER[disposition]} font-mono uppercase tracking-wider ${
        size === "lg" ? "px-4 py-2 text-sm" : "px-3 py-1 text-xs"
      }`}
    >
      <span aria-hidden="true" className={`w-2 h-2 rounded-full ${DISPOSITION_DOT[disposition]}`} />
      {disposition}
    </span>
  )
}

const COVERAGE_DOT: Record<Coverage, string> = {
  SUPPORTED: "bg-[#eca8d6]",
  PARTIAL: "bg-[#fbbf24]",
  REQUIRES_WHITE_BOX: "bg-[#67e8f9]",
  NOT_SUPPORTED: "bg-foreground/40",
  NOT_ASSESSED: "bg-foreground/25",
}

/** Coverage as a category. Never a percentage — coverage is not security (§14). */
export function CoverageBadge({ value }: { value: unknown }) {
  const coverage = asCoverage(value)
  return (
    <span className="inline-flex items-center gap-2 border border-foreground/15 px-3 py-1 text-xs font-mono uppercase tracking-wider text-muted-foreground">
      <span aria-hidden="true" className={`w-2 h-2 rounded-full ${COVERAGE_DOT[coverage]}`} />
      {coverage}
    </span>
  )
}

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "border-destructive/60 text-foreground",
  HIGH: "border-destructive/40 text-foreground",
  MEDIUM: "border-[#fbbf24]/50 text-foreground",
  LOW: "border-foreground/20 text-muted-foreground",
  INFO: "border-foreground/10 text-muted-foreground",
}

export function SeverityBadge({ value }: { value: unknown }) {
  const severity = asSeverity(value)
  if (severity === null) {
    return <Tag>NO SEVERITY</Tag>
  }
  return (
    <span
      className={`inline-block border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider ${SEVERITY_CLASS[severity]}`}
    >
      {severity}
    </span>
  )
}

/** PASS / FAIL / neutral, from the infrastructure section's status row. */
export function CheckMark({ state }: { state: "PASS" | "FAIL" | "NEUTRAL" }) {
  const glyph = state === "PASS" ? "✓" : state === "FAIL" ? "✗" : "·"
  const tone =
    state === "PASS"
      ? "text-[#eca8d6]"
      : state === "FAIL"
        ? "text-destructive"
        : "text-muted-foreground"
  return (
    <span aria-hidden="true" className={`font-mono text-base leading-none ${tone}`}>
      {glyph}
    </span>
  )
}

/** A labelled fact. The workhorse of every identity panel. */
export function Field({
  label,
  value,
  mono = false,
  title,
}: {
  label: string
  value: ReactNode
  mono?: boolean
  title?: string
}) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <dt className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground">
        {label}
      </dt>
      <dd
        className={`text-sm break-words ${mono ? "font-mono" : ""}`}
        title={title}
      >
        {value}
      </dd>
    </div>
  )
}

export function FieldGrid({
  children,
  columns = 3,
}: {
  children: ReactNode
  columns?: 1 | 2 | 3 | 4
}) {
  const cols =
    columns === 1
      ? ""
      : columns === 2
      ? "sm:grid-cols-2"
      : columns === 4
        ? "sm:grid-cols-2 lg:grid-cols-4"
        : "sm:grid-cols-2 lg:grid-cols-3"
  return <dl className={`grid grid-cols-1 ${cols} gap-6`}>{children}</dl>
}

/** A full digest, shortened on screen, complete in the title attribute. */
export function Digest({ value, head = 16 }: { value: unknown; head?: number }) {
  const full = text(value)
  if (full === EMPTY) return <span className="text-muted-foreground">{EMPTY}</span>
  return (
    <span className="font-mono" title={full}>
      {shortDigest(full, head)}
    </span>
  )
}

/**
 * The state a page shows when there is nothing to show.
 *
 * §28 asks for these to be polished rather than blank, and for a reason. The
 * reason is that "no model report" is a finding about the assessment, and the
 * analyst needs to know which of the many ways to have no data this was.
 */
export function EmptyState({
  title,
  reason,
  remedy,
  tone = "NOT_ASSESSED",
}: {
  title: string
  reason: string
  remedy?: string
  tone?: Disposition
}) {
  return (
    <Panel className="p-8 lg:p-12">
      <div className="flex flex-wrap items-center gap-4 mb-6">
        <DispositionBadge value={tone} />
        <h3 className="text-2xl lg:text-3xl font-display">{title}</h3>
      </div>
      <p className="text-muted-foreground leading-relaxed max-w-2xl">{reason}</p>
      {remedy ? (
        <p className="mt-6 text-sm font-mono text-muted-foreground break-words">{remedy}</p>
      ) : null}
    </Panel>
  )
}

/** A bullet list of the engine's own prose — assumptions, limitations, notes. */
export function NoteList({
  title,
  items,
  emptyLabel = "None recorded.",
}: {
  title: string
  items: string[]
  emptyLabel?: string
}) {
  return (
    <div>
      <h4 className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
        {title}
      </h4>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{emptyLabel}</p>
      ) : (
        <ul className="space-y-2">
          {items.map((item, index) => (
            <li key={index} className="text-sm text-muted-foreground leading-relaxed flex gap-3">
              <span aria-hidden="true" className="text-foreground/30 font-mono shrink-0">
                —
              </span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** A count with its label. Deliberately not a gauge and not a percentage. */
export function Stat({
  value,
  label,
  sublabel,
  className = "",
}: {
  value: ReactNode
  label: string
  sublabel?: string
  className?: string
}) {
  return (
    <div className={`flex flex-col gap-2 ${className}`}>
      <span className="text-4xl lg:text-5xl font-display leading-none">{value}</span>
      <span className="text-sm text-foreground">{label}</span>
      {sublabel ? (
        <span className="text-xs font-mono text-muted-foreground">{sublabel}</span>
      ) : null}
    </div>
  )
}

/** The reference's underlined text link with the arrow that slides on hover. */
export function ArrowLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link
      href={href}
      className="group inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
    >
      {children}
      <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">
        &rarr;
      </span>
    </Link>
  )
}
