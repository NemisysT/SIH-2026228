"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { Fingerprint, Layers, Sliders, Activity, Crosshair, ScanLine } from "lucide-react";

/**
 * The reference's security section, carrying Module 2's assessment levels.
 *
 * Preserved exactly: the oversized two-line display title above a wide lede,
 * the 7/5 split, the large left card with its cross-fading supplied imagery at
 * 85% opacity and the certification chips pinned along its bottom, and the
 * stacked right-hand cards with their bordered icon tile that inverts when
 * active, cycling on a 3-second timer and responding to hover.
 *
 * The chips are coverage levels rather than compliance badges, and the cards
 * are the six levels Module 2 assesses. Their status stays categorical —
 * CONSISTENT, MISMATCH, ANOMALOUS, NO_ANOMALY_DETECTED, NOT_ASSESSED — because
 * a detector that reports a category has not earned a percentage, and printing
 * one would invent precision it never claimed.
 */

const LEVEL_ICONS = [Fingerprint, Layers, Sliders, Activity, ScanLine, Crosshair];

/** Supplied imagery, cycled behind the headline the way the reference does. */
const PLATES = [
  "/images/isolated.jpg",
  "/images/encrypted.jpg",
  "/images/audit.jpg",
  "/images/permissions.jpg",
];

export interface LevelCard {
  title: string;
  status: string;
  detail: string;
  assessed: boolean;
}

export function SecuritySection({
  levels,
  headline,
  headlineLabel,
  accessMode,
  coverageChips,
  href,
  lede,
}: {
  levels: LevelCard[];
  headline: string;
  headlineLabel: string;
  accessMode: string;
  coverageChips: string[];
  href: string;
  lede: string;
}) {
  const [isVisible, setIsVisible] = useState(false);
  const [activeLevel, setActiveLevel] = useState(0);
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

  useEffect(() => {
    if (levels.length === 0) return;
    const interval = setInterval(() => {
      setActiveLevel((prev) => (prev + 1) % levels.length);
    }, 3000);
    return () => clearInterval(interval);
  }, [levels.length]);

  return (
    <section id="model" ref={sectionRef} className="relative py-32 lg:py-40 overflow-hidden">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header */}
        <div className="mb-20">
          <span className={`inline-flex items-center gap-4 text-sm font-mono text-muted-foreground mb-8 transition-all duration-700 ${
            isVisible ? "opacity-100" : "opacity-0"
          }`}>
            <span className="w-12 h-px bg-foreground/20" />
            Model forensics
          </span>
          
          {/* Title — full width */}
          <h2 className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9] mb-12 transition-all duration-1000 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}>
            Six levels,
            <br />
            <span className="text-muted-foreground">each answered separately.</span>
          </h2>
          
          {/* Description — below title */}
          <div className={`transition-all duration-1000 delay-100 ${
            isVisible ? "opacity-100" : "opacity-0"
          }`}>
            <p className="text-xl text-muted-foreground leading-relaxed max-w-3xl">{lede}</p>
          </div>
        </div>

        {/* Main content */}
        <div className="grid lg:grid-cols-12 gap-6">
          {/* Large visual card */}
          <div className={`lg:col-span-7 relative p-8 lg:p-12 border border-foreground/10 min-h-[400px] overflow-hidden transition-all duration-700 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}>
            {/* Cross-fading plate — desktop only */}
            <div className="absolute inset-0 pointer-events-none items-center justify-end hidden lg:flex" aria-hidden="true">
              {PLATES.map((plate, index) => (
                <img
                  key={plate}
                  src={plate}
                  alt=""
                  className="absolute h-3/4 w-3/4 object-contain object-right transition-opacity duration-500"
                  style={{ opacity: activeLevel % PLATES.length === index ? 0.85 : 0 }}
                />
              ))}
            </div>
            
            <div className="relative z-10">
              <span className="font-mono text-sm text-muted-foreground">Access mode: {accessMode}</span>
              <div className="mt-8">
                <span className="text-7xl lg:text-8xl font-display break-words">{headline}</span>
                <span className="block text-muted-foreground mt-2">{headlineLabel}</span>
              </div>
              <Link
                href={href}
                className="mt-8 inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors group"
              >
                Open model forensics
                <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">&rarr;</span>
              </Link>
            </div>
            
            {/* Coverage chips */}
            <div className="absolute bottom-8 left-8 right-8 flex flex-wrap gap-2">
              {coverageChips.map((chip, index) => (
                <span
                  key={chip}
                  className={`px-3 py-1 border border-foreground/10 text-xs font-mono text-muted-foreground transition-all duration-500 ${
                    isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
                  }`}
                  style={{ transitionDelay: `${index * 100 + 300}ms` }}
                >
                  {chip}
                </span>
              ))}
            </div>
          </div>

          {/* Level cards stack */}
          <div className="lg:col-span-5 flex flex-col gap-4">
            {levels.map((level, index) => {
              const Icon = LEVEL_ICONS[index % LEVEL_ICONS.length];
              return (
                <div
                  key={level.title}
                  className={`p-6 border transition-all duration-500 cursor-default ${
                    activeLevel === index 
                      ? "border-foreground/30 bg-foreground/[0.04]" 
                      : "border-foreground/10"
                  } ${isVisible ? "opacity-100 translate-x-0" : "opacity-0 translate-x-8"}`}
                  style={{ transitionDelay: `${index * 80}ms` }}
                  onMouseEnter={() => setActiveLevel(index)}
                >
                  <div className="flex items-start gap-4">
                    <div className={`shrink-0 w-10 h-10 flex items-center justify-center border transition-colors ${
                      activeLevel === index 
                        ? "border-foreground bg-foreground text-background" 
                        : "border-foreground/20"
                    }`}>
                      <Icon aria-hidden="true" className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1 mb-1">
                        <h3 className="font-medium">{level.title}</h3>
                        <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                          {level.status}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground break-words">{level.detail}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
