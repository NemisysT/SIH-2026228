"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";

/**
 * The reference's developer section, carrying the decision's reasoning.
 *
 * Preserved exactly: the supplied image anchored bottom-right at 55%x85% with
 * its two gradient fades into the background, the oversized two-line display
 * title, and the left-half column of description plus a two-column feature
 * grid with its 50ms stagger.
 *
 * What it holds is the answer to the only question this screen exists for:
 * why did the system produce this disposition? The bullets are the rules that
 * fired, in the engine's own words — not a paraphrase, and not a story
 * assembled by the frontend.
 */

export interface ReasonItem {
  title: string;
  description: string;
}

export function DevelopersSection({
  disposition,
  rationale,
  reasons,
  href,
}: {
  disposition: string;
  rationale: string;
  reasons: ReasonItem[];
  href: string;
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
    <section id="why" ref={sectionRef} className="relative py-24 lg:py-32 overflow-hidden">

      {/* Image — absolute, bottom-right, behind all content */}
      <div
        className={`absolute bottom-0 right-0 w-[55%] h-[85%] pointer-events-none transition-all duration-1000 delay-300 ${
          isVisible ? "opacity-100" : "opacity-0"
        }`}
        aria-hidden="true"
      >
        <img
          src="/images/decision-panel.png"
          alt=""
          aria-hidden="true"
          className="w-full h-full object-cover object-left-top"
        />
        {/* Fade left edge */}
        <div className="absolute inset-0 bg-gradient-to-r from-background via-background/60 to-transparent" />
        {/* Fade top edge */}
        <div className="absolute inset-0 bg-gradient-to-b from-background via-transparent to-transparent" />
      </div>

      {/* All text content sits on top */}
      <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header — Full width */}
        <div
          className={`mb-16 transition-all duration-700 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}
        >
          <span className="inline-flex items-center gap-3 text-sm font-mono text-muted-foreground mb-6">
            <span className="w-8 h-px bg-foreground/30" />
            Assurance decision
          </span>
          <h2 className="text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9]">
            {disposition}.
            <br />
            <span className="text-muted-foreground">Here is why.</span>
          </h2>
        </div>

        {/* Description + reasons — left half only on desktop */}
        <div
          className={`max-w-[50%] transition-all duration-700 delay-100 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}
        >
          <p className="text-xl text-muted-foreground mb-12 leading-relaxed max-w-xl">
            {rationale}
          </p>
          <div className="grid sm:grid-cols-2 gap-6">
            {reasons.map((reason, index) => (
              <div
                key={reason.title}
                className={`transition-all duration-500 ${
                  isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
                }`}
                style={{ transitionDelay: `${index * 50 + 200}ms` }}
              >
                <h3 className="font-medium mb-1 font-mono text-sm">{reason.title}</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{reason.description}</p>
              </div>
            ))}
          </div>

          <Link
            href={href}
            className="group mt-12 inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
          >
            Open the full decision
            <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">&rarr;</span>
          </Link>
        </div>
      </div>
    </section>
  );
}
