"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { ArrowRight, Check, Zap } from "lucide-react";

/**
 * The reference's pricing section, carrying the demo scenario matrix.
 *
 * Preserved exactly: the 7/5 header with the stroked second line, the whale
 * image in the right column, the three overlapping cards with the highlighted
 * middle one scaled and pulled forward, the "Most Popular" ribbon, the
 * numbered plan header, the large display figure, the checked feature list in
 * pink, the full-width CTA with its sliding arrow, and the bottom note row.
 *
 * The cards are attack-lab scenarios and the figure is the disposition the
 * policy engine produced for each. The ribbon marks the scenario a judge
 * should open first. Nothing on these cards is authored: every disposition,
 * rule and count came out of a real Module 1-4 run.
 */

export interface ScenarioCard {
  name: string;
  label: string;
  description: string;
  disposition: string;
  status: string;
  facts: string[];
  href: string;
  highlight: boolean;
}

export function PricingSection({
  scenarios,
  allHref,
  lede,
  eyebrow,
  titleLead,
  titleTrail,
  facts,
}: {
  scenarios: ScenarioCard[];
  allHref: string;
  lede: string;
  /** Source-aware: this section must never label live results as demo ones. */
  eyebrow: string;
  titleLead: string;
  titleTrail: string;
  facts: string[];
}) {
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setIsVisible(true);
      },
      { threshold: 0.1 }
    );

    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section id="scenarios" ref={sectionRef} className="relative py-32 lg:py-40">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header - Dramatic offset */}
        <div className="grid lg:grid-cols-12 gap-8 mb-20">
          <div className="lg:col-span-7">
            <span className="inline-flex items-center gap-3 text-sm font-mono text-muted-foreground mb-8">
              <span className="w-12 h-px bg-foreground/30" />
              {eyebrow}
            </span>
            <h2 className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9] transition-all duration-1000 ${
              isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
            }`}>
              {titleLead}
              <br />
              <span className="text-stroke">{titleTrail}</span>
            </h2>
            <p className={`mt-8 text-xl text-muted-foreground leading-relaxed max-w-xl transition-all duration-1000 delay-100 ${
              isVisible ? "opacity-100" : "opacity-0"
            }`}>
              {lede}
            </p>
          </div>
          
          <div className="lg:col-span-5 relative p-0 h-64 lg:h-auto">
            {/* Whale image */}
            <div className={`absolute inset-0 pointer-events-none transition-all duration-1000 delay-100 ${
              isVisible ? "opacity-100" : "opacity-0"
            }`} aria-hidden="true">
              <img
                src="/images/whale.png"
                alt=""
                aria-hidden="true"
                className="w-full h-full object-contain object-center"
              />
            </div>
          </div>
        </div>

        {/* Scenario cards - Horizontal layout with overlap */}
        <div className="relative">
          <div className="grid lg:grid-cols-3 gap-4 lg:gap-0">
            {scenarios.map((scenario, index) => (
              <div
                key={scenario.name}
                className={`relative bg-background border transition-all duration-700 ${
                  scenario.highlight 
                    ? "border-foreground lg:-mx-2 lg:z-10 lg:scale-105" 
                    : "border-foreground/10 lg:first:-mr-2 lg:last:-ml-2"
                } ${isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-12"}`}
                style={{ transitionDelay: `${index * 100}ms` }}
              >
                {/* Start-here ribbon */}
                {scenario.highlight && (
                  <div className="absolute -top-4 left-8 right-8 flex justify-center">
                    <span className="inline-flex items-center gap-2 px-4 py-2 bg-foreground text-background text-xs font-mono uppercase tracking-widest whitespace-nowrap">
                      <Zap aria-hidden="true" className="w-3 h-3" />
                      Start here
                    </span>
                  </div>
                )}

                <div className="p-8 lg:p-10">
                  {/* Scenario header */}
                  <div className="mb-8 pb-8 border-b border-foreground/10">
                    <span className="font-mono text-xs text-muted-foreground">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <h3 className="text-2xl lg:text-3xl font-display mt-2 break-words">{scenario.label}</h3>
                    <p className="text-sm text-muted-foreground mt-2 line-clamp-3">{scenario.description}</p>
                  </div>

                  {/* Disposition */}
                  <div className="mb-8">
                    <span className="text-5xl lg:text-6xl font-display break-words">
                      {scenario.status === "RUN" ? scenario.disposition : "NOT_RUN"}
                    </span>
                    <p className="text-xs text-muted-foreground mt-2 font-mono">
                      produced by the policy engine
                    </p>
                  </div>

                  {/* Facts */}
                  <ul className="space-y-3 mb-10">
                    {scenario.facts.map((fact) => (
                      <li key={fact} className="flex items-start gap-3">
                        <Check aria-hidden="true" className="w-4 h-4 text-[#eca8d6] mt-0.5 shrink-0" />
                        <span className="text-sm text-muted-foreground break-words">{fact}</span>
                      </li>
                    ))}
                  </ul>

                  {/* CTA */}
                  <Link
                    href={scenario.href}
                    className={`w-full py-4 flex items-center justify-center gap-2 text-sm font-medium transition-all group ${
                      scenario.highlight
                        ? "bg-foreground text-background hover:bg-foreground/90"
                        : "border border-foreground/20 text-foreground hover:border-foreground hover:bg-foreground/5"
                    }`}
                  >
                    Open scenario
                    <ArrowRight aria-hidden="true" className="w-4 h-4 transition-transform group-hover:translate-x-1" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom note */}
        <div className={`mt-20 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-8 pt-12 border-t border-foreground/10 transition-all duration-1000 delay-500 ${
          isVisible ? "opacity-100" : "opacity-0"
        }`}>
          <div className="flex flex-wrap gap-6 text-sm text-muted-foreground">
            {facts.map((fact) => (
              <span key={fact} className="flex items-center gap-2">
                <Check aria-hidden="true" className="w-4 h-4 text-[#eca8d6]" />
                {fact}
              </span>
            ))}
          </div>
          <Link href={allHref} className="text-sm underline underline-offset-4 hover:text-foreground transition-colors">
            See the whole scenario matrix
          </Link>
        </div>
      </div>

      <style jsx>{`
        .text-stroke {
          -webkit-text-stroke: 1.5px currentColor;
          -webkit-text-fill-color: transparent;
        }
      `}</style>
    </section>
  );
}
