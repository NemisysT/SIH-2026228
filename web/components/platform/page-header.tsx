import type { ReactNode } from "react"

import { ScenarioSwitcher, type SwitcherOption } from "./scenario-switcher"

/**
 * The hero, reused as every page's header.
 *
 * The composition is the reference's: black plate, the 8×12 grid of hairlines,
 * the two gradient washes, the mono eyebrow with its leading rule, the display
 * headline at `clamp(2rem,6vw,7rem)`, and the stat row pinned along the
 * bottom. The landing page runs it at full height with the video behind; inner
 * pages run the same thing shorter and without the video, which is what the
 * reference's own section backgrounds look like underneath.
 */
export function PageHeader({
  eyebrow,
  title,
  lede,
  video = false,
  stats,
  scenarioBar,
  children,
}: {
  eyebrow: string
  title: ReactNode
  lede?: string
  video?: boolean
  stats?: { value: ReactNode; label: string }[]
  scenarioBar?: ReactNode
  children?: ReactNode
}) {
  return (
    <section
      className={`relative flex flex-col justify-center items-start overflow-hidden bg-black ${
        video ? "min-h-screen" : "min-h-[62vh] lg:min-h-[68vh]"
      }`}
    >
      {video ? (
        <div className="absolute inset-0 z-0">
          <video
            autoPlay
            muted
            loop
            playsInline
            aria-hidden="true"
            poster="/images/connection.png"
            className="w-full h-full object-cover object-center opacity-80"
          >
            <source src="/video/bg-hero.mp4" type="video/mp4" />
          </video>
          <div className="absolute inset-0 bg-gradient-to-r from-black/70 via-black/30 to-transparent" />
          <div className="absolute inset-0 bg-gradient-to-b from-black/20 via-transparent to-black/60" />
        </div>
      ) : (
        <div className="absolute inset-0 z-0">
          <div className="absolute inset-0 bg-gradient-to-r from-black via-black/90 to-black/70" />
          <div className="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-black/80" />
        </div>
      )}

      {/* Subtle grid lines */}
      <div className="absolute inset-0 z-[2] overflow-hidden pointer-events-none opacity-20">
        {[...Array(8)].map((_, i) => (
          <div
            key={`h-${i}`}
            className="absolute h-px bg-white/10"
            style={{ top: `${12.5 * (i + 1)}%`, left: 0, right: 0 }}
          />
        ))}
        {[...Array(12)].map((_, i) => (
          <div
            key={`v-${i}`}
            className="absolute w-px bg-white/10"
            style={{ left: `${8.33 * (i + 1)}%`, top: 0, bottom: 0 }}
          />
        ))}
      </div>

      <div
        className={`relative z-10 w-full max-w-[1400px] mx-auto px-6 lg:px-12 ${
          video ? "py-32 lg:py-40" : "pt-36 pb-24 lg:pt-44 lg:pb-32"
        }`}
      >
        <div className={video ? "lg:max-w-[70%]" : "lg:max-w-[78%]"}>
          <div className="mb-8">
            <span className="inline-flex items-center gap-3 text-sm font-mono text-white/60">
              <span className="w-8 h-px bg-white/30" />
              {eyebrow}
            </span>
          </div>

          <h1
            className={`text-left font-display leading-[0.92] tracking-tight text-white ${
              video
                ? "text-[clamp(2rem,6vw,7rem)] mb-12"
                : "text-[clamp(2rem,5vw,5rem)] mb-8"
            }`}
          >
            {title}
          </h1>

          {lede ? (
            <p className="text-lg lg:text-xl text-white/60 leading-relaxed max-w-2xl">{lede}</p>
          ) : null}

          {children}
        </div>
      </div>

      {scenarioBar ? (
        <div className="relative z-10 w-full max-w-[1400px] mx-auto px-6 lg:px-12 pb-10">
          {scenarioBar}
        </div>
      ) : null}

      {stats && stats.length > 0 ? (
        <div className="relative z-10 w-full px-6 lg:px-12 pb-12">
          <div className="max-w-[1400px] mx-auto flex flex-wrap items-start gap-10 lg:gap-20">
            {stats.map((stat) => (
              <div key={stat.label} className="flex flex-col gap-2">
                <span className="text-3xl lg:text-4xl font-display text-white break-all">
                  {stat.value}
                </span>
                <span className="text-xs text-white/50 leading-tight">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </section>
  )
}

/**
 * The bar that says which body of data is on screen.
 *
 * This is the single most important piece of chrome in the application (§19).
 * An analyst who mistakes an attack-lab scenario for a live assessment has
 * been misled by the tool, so the source is stated in words, on every page,
 * above the fold, and the two are never mixed in one view.
 */
export function ScenarioBar({
  source,
  scenarioName,
  scenarioLabel,
  disposition,
  status,
  options,
  generatedAt,
}: {
  source: "DEMO" | "LIVE"
  scenarioName: string
  scenarioLabel: string
  disposition: string
  status: string
  options: SwitcherOption[]
  generatedAt?: string | null
}) {
  const live = source === "LIVE"
  return (
    <div className="flex flex-col gap-4 border border-white/15 bg-black/50 backdrop-blur-sm p-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <span
          className={`inline-flex items-center gap-2 px-3 py-1 text-xs font-mono uppercase tracking-widest ${
            live ? "bg-[#67e8f9]/15 text-[#67e8f9]" : "bg-[#eca8d6]/10 text-[#eca8d6]"
          }`}
        >
          <span
            aria-hidden="true"
            className={`w-2 h-2 rounded-full ${live ? "bg-[#67e8f9] animate-pulse" : "bg-[#eca8d6]"}`}
          />
          {live ? "Live assessment" : "Demo scenario"}
        </span>
        <span className="text-xs font-mono text-white/50">
          {live
            ? "Output of a real assessment published to reports/live."
            : "Real Module 1–4 output over an attack-lab scenario. Not a live deployment."}
        </span>
      </div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <span className="text-xs font-mono text-white/40">
          {scenarioLabel} · {status === "RUN" ? disposition : "NOT_RUN"}
          {generatedAt ? ` · ${generatedAt}` : ""}
        </span>
        <ScenarioSwitcher options={options} value={scenarioName} source={source} />
      </div>
    </div>
  )
}
