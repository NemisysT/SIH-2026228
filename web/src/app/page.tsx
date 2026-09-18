import Link from "next/link";
import { ArrowUpRight, ShieldCheck, GitBranch, FileSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Eyebrow } from "@/components/site/eyebrow";
import { Glow } from "@/components/site/glow";
import { Footer } from "@/components/site/footer";

const DETECTORS = [
  {
    n: "01",
    name: "Near-duplicate flooding",
    id: "near_duplicate",
    detail:
      "Two-stage detection: perceptual-hash Hamming distance for recall, cosine similarity in the classical feature space for precision — rejecting structurally similar but content-distinct pairs.",
    stat: "2-stage",
    statLabel: "recall + precision",
  },
  {
    n: "02",
    name: "Systematic mislabelling",
    id: "systematic_mislabel",
    detail:
      "Per-contributor binomial tests against the cohort baseline surface a consistent, directional label mapping — the signature of a hostile batch, not random noise.",
    stat: "q<0.01",
    statLabel: "multiple-testing corrected",
  },
  {
    n: "03",
    name: "Out-of-distribution insertion",
    id: "ood",
    detail:
      "Mahalanobis distance, k-NN and reconstruction residual, each calibrated to a target false-positive rate against a declared reference distribution.",
    stat: "3 methods",
    statLabel: "family-wise FPR budget",
  },
  {
    n: "04",
    name: "Label consistency",
    id: "label_consistency",
    detail:
      "Neighbourhood-based label agreement, with near-duplicate clusters excluded so one flooded pair can't manufacture consensus.",
    stat: "graph-based",
    statLabel: "neighbourhood agreement",
  },
  {
    n: "05",
    name: "Integrity & exact duplicates",
    id: "integrity",
    detail:
      "Byte-level and pixel-level SHA-256 over every sample, malformed annotation detection, and exact-duplicate grouping — deterministic, not statistical.",
    stat: "SHA-256",
    statLabel: "byte + pixel identity",
  },
];

const PIPELINE = [
  { n: "01", title: "Ingest", detail: "Adapter detects the dataset layout (folder, COCO, YOLO) and loads samples with their contributor attribution." },
  { n: "02", title: "Manifest", detail: "Every file hashed twice — bytes and decoded pixels — into a cryptographic identity the rest of the platform binds to." },
  { n: "03", title: "Features", detail: "A deterministic classical descriptor, chosen for air-gapped operation: no pretrained weights, no download." },
  { n: "04", title: "Detect", detail: "Five detectors run in a fixed order — near-duplicate clusters feed label-consistency, which feeds systematic-mislabel." },
  { n: "05", title: "Aggregate", detail: "Findings roll up per contributor with a worst-case disposition rule: one confident high-severity finding is never averaged away." },
  { n: "06", title: "Report", detail: "Coverage statement, calibration status and limitations ship with every report — a clean result names what it did not test." },
];

export default function Home() {
  return (
    <main className="relative min-h-screen overflow-x-hidden">
      {/* ---------------------------------------------------------------- Hero */}
      <section className="relative min-h-screen flex items-center pt-20">
        <Glow className="top-1/4 -left-40 w-[500px] h-[500px]" />
        <Glow className="bottom-0 right-0 w-[400px] h-[400px]" />
        <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12 w-full py-24">
          <Eyebrow>SIH26228 · Module 1 · Dataset forensics</Eyebrow>
          <h1 className="text-6xl md:text-7xl lg:text-[104px] font-display tracking-tight leading-[0.92] max-w-5xl">
            Trustworthy data,
            <br />
            <span className="text-muted-foreground">before it trains anything.</span>
          </h1>
          <p className="mt-8 text-xl text-muted-foreground leading-relaxed max-w-xl">
            Offline dataset forensics for multi-contributor computer vision
            pipelines. Cryptographic manifests, calibrated detectors, and
            evidence an analyst — or a hostile reviewer — can recompute.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-4">
            <Button
              size="lg"
              className="rounded-full px-8 h-11"
              render={<Link href="/dashboard">Run the demo <ArrowUpRight className="ml-1 size-4" /></Link>}
            />
            <Button
              variant="outline"
              size="lg"
              className="rounded-full px-8 h-11 border-foreground/20 bg-transparent hover:bg-foreground/5"
              render={<Link href="#pipeline">See the pipeline</Link>}
            />
          </div>
          <div className="mt-20 grid grid-cols-2 sm:grid-cols-4 gap-8 max-w-2xl pt-10 border-t border-foreground/10">
            <div>
              <span className="block text-4xl font-display">5</span>
              <span className="block text-sm text-muted-foreground font-mono mt-1">detectors</span>
            </div>
            <div>
              <span className="block text-4xl font-display">15</span>
              <span className="block text-sm text-muted-foreground font-mono mt-1">attack classes tracked</span>
            </div>
            <div>
              <span className="block text-4xl font-display">0</span>
              <span className="block text-sm text-muted-foreground font-mono mt-1">network calls at run time</span>
            </div>
            <div>
              <span className="block text-4xl font-display">1/5</span>
              <span className="block text-sm text-muted-foreground font-mono mt-1">modules shipped</span>
            </div>
          </div>
        </div>
      </section>

      {/* ----------------------------------------------------------- Detectors */}
      <section id="detectors" className="relative py-24 lg:py-32 overflow-hidden">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
          <div className="relative mb-16 lg:mb-24">
            <div className="grid lg:grid-cols-12 gap-8 items-end">
              <div className="lg:col-span-7">
                <Eyebrow>Detectors</Eyebrow>
                <h2 className="text-6xl md:text-7xl lg:text-[96px] font-display tracking-tight leading-[0.9]">
                  Evidence,
                  <br />
                  <span className="text-muted-foreground">not intuition.</span>
                </h2>
              </div>
              <div className="lg:col-span-5 lg:pb-4">
                <p className="text-xl text-muted-foreground leading-relaxed">
                  Every finding carries a machine-checkable observation — hamming
                  distances, neighbour ids, p-values, counts — an analyst can
                  recompute from scratch. A claim with no observation cannot be
                  represented.
                </p>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-4 lg:gap-6">
            {DETECTORS.map((d, i) => (
              <div
                key={d.id}
                className={`relative bg-card border border-foreground/10 p-8 lg:p-10 group transition-colors duration-500 hover:border-foreground/25 ${
                  i === 0 ? "lg:col-span-2 min-h-[360px]" : "min-h-[300px]"
                } flex flex-col justify-between`}
              >
                <div>
                  <span className="font-mono text-sm text-muted-foreground">{d.n}</span>
                  <h3 className="text-2xl lg:text-3xl font-display mt-4 mb-4 group-hover:translate-x-1 transition-transform duration-500">
                    {d.name}
                  </h3>
                  <p className="text-base text-muted-foreground leading-relaxed max-w-lg">
                    {d.detail}
                  </p>
                </div>
                <div className="mt-8">
                  <span className="text-4xl lg:text-5xl font-display">{d.stat}</span>
                  <span className="block text-sm text-muted-foreground font-mono mt-2">
                    {d.statLabel}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------ Pipeline */}
      <section
        id="pipeline"
        className="relative py-24 lg:py-32 bg-[oklch(0.09_0.01_260)] text-foreground overflow-hidden"
      >
        <Glow className="bottom-0 left-0 w-[400px] h-[400px] bg-background/40" />
        <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
          <div className="grid lg:grid-cols-2 gap-12 items-end mb-20">
            <div>
              <Eyebrow>Pipeline</Eyebrow>
              <h2 className="text-6xl md:text-7xl lg:text-[96px] font-display tracking-tight leading-[0.88]">
                <span className="block">Fixed order.</span>
                <span className="block text-foreground/30">One report.</span>
              </h2>
            </div>
            <p className="text-xl text-foreground/60 leading-relaxed lg:pb-4">
              Detectors are not five independent demos. Near-duplicate clusters
              are excluded from label-consistency&apos;s neighbourhoods, and its
              suggestions are what systematic-mislabel tests. That chain is why
              execution order is fixed in code, not configuration.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-px bg-foreground/10 border border-foreground/10">
            {PIPELINE.map((s) => (
              <div key={s.n} className="bg-[oklch(0.09_0.01_260)] p-8 min-h-[220px] flex flex-col justify-between">
                <span className="font-mono text-sm text-foreground/40">{s.n}</span>
                <div>
                  <h3 className="text-2xl font-display mb-2">{s.title}</h3>
                  <p className="text-sm text-foreground/50 leading-relaxed">{s.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- Coverage */}
      <section id="coverage" className="relative py-24 lg:py-32">
        <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
          <div className="grid lg:grid-cols-12 gap-8 items-end mb-16">
            <div className="lg:col-span-7">
              <Eyebrow>Coverage &amp; limitations</Eyebrow>
              <h2 className="text-6xl md:text-7xl lg:text-[96px] font-display tracking-tight leading-[0.9]">
                Declared,
                <br />
                <span className="text-muted-foreground">not implied.</span>
              </h2>
            </div>
            <div className="lg:col-span-5 lg:pb-4">
              <p className="text-xl text-muted-foreground leading-relaxed">
                A clean report from a system that never tested for an attack
                class is not a clean result. Every attack class the platform
                knows about appears in the coverage statement — including the
                ones this build does not assess.
              </p>
            </div>
          </div>

          <div className="grid md:grid-cols-3 gap-4 lg:gap-6">
            <div className="border border-foreground/10 bg-card p-8">
              <ShieldCheck className="size-6 text-highlight mb-6" strokeWidth={1.5} />
              <h3 className="text-xl font-display mb-3">Calibrated, capped confidence</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Uncalibrated detectors are capped and flagged — never reported
                with confidence they haven&apos;t earned.
              </p>
            </div>
            <div className="border border-foreground/10 bg-card p-8">
              <FileSearch className="size-6 text-highlight mb-6" strokeWidth={1.5} />
              <h3 className="text-xl font-display mb-3">Recomputable evidence</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Every finding ships the raw observation behind it — not just a
                score an analyst has to trust.
              </p>
            </div>
            <div className="border border-foreground/10 bg-card p-8">
              <GitBranch className="size-6 text-highlight mb-6" strokeWidth={1.5} />
              <h3 className="text-xl font-display mb-3">Worst-case rollup</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Contributor risk aggregates by rule, not by average — one
                confident finding is never buried in a mean.
              </p>
            </div>
          </div>

          <div className="mt-16 border border-foreground/10 bg-card p-10 lg:p-12 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
            <div>
              <span className="font-mono text-sm text-muted-foreground">Full coverage statement</span>
              <p className="text-2xl font-display mt-2">See every tracked attack class, live from the running pipeline.</p>
            </div>
            <Button
              size="lg"
              className="rounded-full px-8 h-11 shrink-0"
              render={<Link href="/dashboard">Open dashboard <ArrowUpRight className="ml-1 size-4" /></Link>}
            />
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
