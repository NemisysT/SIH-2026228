import type { ReactNode } from "react"

import { linkSuffix, type PageData } from "@/lib/analyst/page-data"
import { text } from "@/lib/analyst/format"

import { Navigation } from "./navigation"
import { PageHeader, ScenarioBar } from "./page-header"
import { PlatformFooter } from "./footer"
import { EmptyState } from "./primitives"

/**
 * Nav, header, source bar, content, footer — the frame every route shares.
 *
 * Keeping the frame in one place is what stops the source indicator from
 * drifting off a page, which would be the one failure mode that actually
 * misleads an analyst.
 */
export function PageShell({
  data,
  eyebrow,
  title,
  lede,
  video = false,
  stats,
  children,
}: {
  data: PageData
  eyebrow: string
  title: ReactNode
  lede?: string
  video?: boolean
  stats?: { value: ReactNode; label: string }[]
  children: ReactNode
}) {
  const { source, status, scenario, options, other } = data
  const suffix = linkSuffix(source, scenario?.name)
  const assurance = data.bundle?.assurance ?? null

  return (
    <main className="relative min-h-screen overflow-x-hidden">
      <Navigation scenario={scenario?.name} source={source} />

      <PageHeader
        eyebrow={eyebrow}
        title={title}
        lede={lede}
        video={video}
        stats={stats}
        scenarioBar={
          scenario ? (
            <ScenarioBar
              source={source}
              scenarioName={scenario.name}
              scenarioLabel={scenario.name}
              disposition={scenario.observed_disposition ?? "NOT_ASSESSED"}
              status={scenario.status}
              options={options}
              generatedAt={status.generatedAt}
            />
          ) : null
        }
      />

      {scenario ? (
        <>
          {/* §28: a report that would not parse is a different state from a
              report that was never produced, and the difference matters —
              one means the module had nothing to assess, the other means the
              file on disk is damaged. */}
          {(data.bundle?.malformed ?? []).length > 0 ? (
            <section className="relative pt-20 lg:pt-28">
              <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
                <EmptyState
                  title={`${data.bundle?.malformed.length} report file(s) could not be parsed`}
                  reason={`The catalogue names ${data.bundle?.malformed.join(", ")} for this scenario, but the file on disk is not valid JSON. The screens below render what did load; nothing has been substituted for what did not.`}
                  remedy={`Rebuild the feed: ${data.status.remedy}`}
                  tone="REVIEW"
                />
              </div>
            </section>
          ) : null}
          {children}
        </>
      ) : (
        <section className="relative py-24 lg:py-32">
          <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
            <EmptyState
              title={`No ${source === "LIVE" ? "live assessment" : "demo feed"} is present`}
              reason={
                source === "LIVE"
                  ? `Nothing has been published to ${status.directory}. The platform will not show demo data in its place, because an analyst must never mistake a laboratory scenario for a live assessment.` +
                    (other.available
                      ? ` The demo feed is available and holds ${other.scenarioCount} scenario(s).`
                      : "")
                  : `Nothing has been exported to ${status.directory}. The frontend reads real Module 1–4 reports from disk and does not fabricate any.`
              }
              remedy={status.remedy}
            />
          </div>
        </section>
      )}

      <PlatformFooter
        suffix={suffix}
        softwareVersion={status.softwareVersion}
        generatedAt={status.generatedAt}
        policyVersion={text(assurance?.decision?.policy_version, "—")}
      />
    </main>
  )
}

/** The standard content section: the reference's `py-24 lg:py-32` + 1400px rail. */
export function Section({
  children,
  className = "",
  id,
}: {
  children: ReactNode
  className?: string
  id?: string
}) {
  return (
    <section id={id} className={`relative py-20 lg:py-28 overflow-hidden ${className}`}>
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">{children}</div>
    </section>
  )
}
