import { Navigation } from "@/components/platform/navigation"
import { ScenarioBar } from "@/components/platform/page-header"
import { PlatformFooter } from "@/components/platform/footer"
import { EmptyState } from "@/components/platform/primitives"
import { HeroSection } from "@/components/landing/hero-section"
import { FeaturesSection } from "@/components/landing/features-section"
import { HowItWorksSection } from "@/components/landing/how-it-works-section"
import { InfrastructureSection } from "@/components/landing/infrastructure-section"
import { MetricsSection } from "@/components/landing/metrics-section"
import { IntegrationsSection } from "@/components/landing/integrations-section"
import { SecuritySection } from "@/components/landing/security-section"
import { DevelopersSection } from "@/components/landing/developers-section"
import { TestimonialsSection } from "@/components/landing/testimonials-section"
import { PricingSection } from "@/components/landing/pricing-section"
import { CtaSection } from "@/components/landing/cta-section"

import { text, timestamp } from "@/lib/analyst/format"
import { artifactHref } from "@/lib/analyst/links"
import { buildOverview, scenarioCards } from "@/lib/analyst/overview"
import { loadPageData, type SearchParams } from "@/lib/analyst/page-data"

export const dynamic = "force-dynamic"

/**
 * The Overview / Assurance Dashboard (§6).
 *
 * It is the reference's landing page, section for section and in the same
 * order, with each section carrying the part of the assurance state it is
 * shaped for. What it deliberately does not carry is a headline number: there
 * is no trust score, no security score and no 0-100 gauge anywhere on this
 * page, because the engine has no such value and inventing one in the UI would
 * misrepresent the whole architecture.
 */
export default async function OverviewPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>
}) {
  const params = await searchParams
  const data = await loadPageData(params)
  const { source, status, bundle, scenario, options, other } = data

  if (!scenario || !bundle) {
    return (
      <main className="relative min-h-screen overflow-x-hidden">
        <Navigation source={source} />
        <section className="relative pt-40 pb-24 lg:pt-52 lg:pb-32 bg-black">
          <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
            <EmptyState
              title={`No ${source === "LIVE" ? "live assessment" : "demo feed"} is present`}
              reason={
                source === "LIVE"
                  ? `Nothing has been published to ${status.directory}. Demo data is not shown in its place: an analyst must never mistake a laboratory scenario for a live assessment.${
                      other.available
                        ? ` The demo feed holds ${other.scenarioCount} scenario(s).`
                        : ""
                    }`
                  : `Nothing has been exported to ${status.directory}. The frontend reads real Module 1–4 reports from disk and fabricates none.`
              }
              remedy={status.remedy}
            />
          </div>
        </section>
        <PlatformFooter />
      </main>
    )
  }

  const model = buildOverview(bundle, source)
  const rows = await (async () => {
    const { listScenarios } = await import("@/lib/analyst/source")
    return listScenarios(source)
  })()

  const scenarioBar = (
    <ScenarioBar
      source={source}
      scenarioName={scenario.name}
      scenarioLabel={scenario.name}
      disposition={scenario.observed_disposition ?? "NOT_ASSESSED"}
      status={scenario.status}
      options={options}
      generatedAt={status.generatedAt}
    />
  )

  const reportLinks = [
    {
      label: "assurance.json",
      description: "Module 4 pipeline assurance report: decision, evidence graph and every upstream finding verbatim.",
      href: artifactHref(source, scenario.name, "assurance", true),
      available: Boolean(scenario.files?.assurance),
    },
    {
      label: "dataset.json",
      description: "Module 1 dataset report.",
      href: artifactHref(source, scenario.name, "dataset", true),
      available: Boolean(scenario.files?.dataset),
    },
    {
      label: "model.json",
      description: "Module 2 model report.",
      href: artifactHref(source, scenario.name, "model", true),
      available: Boolean(scenario.files?.model),
    },
    {
      label: "provenance.json",
      description: "Module 3 provenance verification report.",
      href: artifactHref(source, scenario.name, "provenance", true),
      available: Boolean(scenario.files?.provenance),
    },
    {
      label: "shift.json",
      description: "Module 4 distribution-shift assessment.",
      href: artifactHref(source, scenario.name, "shift", true),
      available: Boolean(scenario.files?.shift),
    },
  ]

  return (
    <main className="relative min-h-screen overflow-x-hidden">
      <Navigation scenario={scenario.name} source={source} />

      <HeroSection
        eyebrow={model.hero.eyebrow}
        lead={model.hero.lead}
        disposition={model.hero.disposition}
        statement={model.hero.statement}
        stats={model.hero.stats}
        scenarioBar={scenarioBar}
      />

      <FeaturesSection
        disposition={model.scopes.disposition}
        summary={model.scopes.summary}
        reportId={model.scopes.reportId}
        policyVersion={model.scopes.policyVersion}
        scopes={model.scopes.cards}
        decisionHref={`/decision${model.suffix}`}
      />

      <HowItWorksSection steps={model.pipeline} />

      {model.shift ? (
        <InfrastructureSection
          verdict={model.shift.verdict}
          statement={model.shift.statement}
          headlineValue={model.shift.headlineValue}
          headlineUnit={model.shift.headlineUnit}
          headlineNote={model.shift.headlineNote}
          stats={model.shift.stats}
          rows={model.shift.rows}
          href={`/shift${model.suffix}`}
        />
      ) : null}

      <MetricsSection
        source={source}
        metrics={model.evidence.metrics}
        families={model.evidence.families}
        note={model.evidence.note}
        generatedAt={timestamp(status.generatedAt)}
      />

      <IntegrationsSection
        cards={model.coverage.cards}
        counts={model.coverage.counts}
        href={`/coverage${model.suffix}`}
        lede={model.coverage.lede}
      />

      <SecuritySection
        levels={model.model.levels}
        headline={model.model.headline}
        headlineLabel={model.model.headlineLabel}
        accessMode={model.model.accessMode}
        coverageChips={model.model.coverageChips}
        href={`/model${model.suffix}`}
        lede={model.model.lede}
      />

      <DevelopersSection
        disposition={model.why.disposition}
        rationale={model.why.rationale}
        reasons={model.why.reasons}
        href={`/decision${model.suffix}`}
      />

      <TestimonialsSection
        findings={model.findings}
        emptyStatement="No detector reported a finding for this run. That is an outcome, not an absence of assessment — the coverage statement says exactly which attack classes were examined to reach it."
      />

      <PricingSection
        scenarios={scenarioCards(rows, source)}
        allHref={`/demo${model.suffix}`}
        eyebrow={source === "LIVE" ? "Live assessments" : "Demo scenarios"}
        titleLead={source === "LIVE" ? "Assessments" : "Run the"}
        titleTrail={source === "LIVE" ? "on record." : "attack lab."}
        lede={
          source === "LIVE"
            ? "Each card is an assessment published to the live source. The disposition shown is the one the policy engine produced for it."
            : "Each card is a scenario the attack lab actually ran end to end, through Modules 1, 2, 3 and 4. The disposition shown is the one the policy engine produced — none of it is authored for the demo."
        }
        facts={
          source === "LIVE"
            ? [
                "Real Module 1–4 output",
                "Published by an operator to reports/live",
                "Not laboratory data",
              ]
            : [
                "Real Module 1–4 output",
                "Deterministic, regenerable from the engine",
                "Never confused with a live assessment",
              ]
        }
      />

      <CtaSection reports={reportLinks} scenarioLabel={scenario.name} />

      <PlatformFooter
        suffix={model.suffix}
        softwareVersion={status.softwareVersion}
        generatedAt={status.generatedAt}
        policyVersion={text(bundle.assurance?.decision?.policy_version, "—")}
      />
    </main>
  )
}
