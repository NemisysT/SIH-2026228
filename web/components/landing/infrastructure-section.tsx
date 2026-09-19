"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";

/**
 * The reference's global-infrastructure section, carrying distribution shift.
 *
 * Preserved exactly: the sphere image in its own left column at full height,
 * the stacked oversized display title, the 2/1 stat grid with the animated
 * pink node lattice and its drawLine keyframes behind the headline figure, the
 * two stacked stat cards, and the four status cards that cycle on a 3-second
 * timer with their pink dot.
 *
 * What it shows is the population comparison: the reference corpus, the
 * current corpus, and the verdict. The section states the verdict the engine
 * produced and stops there — a shift is an observation about a population, and
 * this screen never upgrades one into an accusation. Whether independent
 * evidence exists is the policy engine's finding, and it lives on the decision
 * page.
 */

export interface ShiftStat {
  value: string;
  label: string;
}

export interface ShiftRow {
  name: string;
  status: string;
  detail: string;
}

export function InfrastructureSection({
  verdict,
  statement,
  headlineValue,
  headlineUnit,
  headlineNote,
  stats,
  rows,
  href,
}: {
  verdict: string;
  statement: string;
  headlineValue: string;
  headlineUnit: string;
  headlineNote: string;
  stats: ShiftStat[];
  rows: ShiftRow[];
  href: string;
}) {
  const [isVisible, setIsVisible] = useState(false);
  const [activeRow, setActiveRow] = useState(0);
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
    if (rows.length === 0) return;
    const interval = setInterval(() => {
      setActiveRow((prev) => (prev + 1) % rows.length);
    }, 3000);
    return () => clearInterval(interval);
  }, [rows.length]);

  return (
    <section id="shift" ref={sectionRef} className="relative py-32 lg:py-40 overflow-hidden">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header */}
        <div className="mb-20">
          <span className={`inline-flex items-center gap-4 text-sm font-mono text-muted-foreground mb-8 transition-all duration-700 ${
            isVisible ? "opacity-100" : "opacity-0"
          }`}>
            <span className="w-12 h-px bg-foreground/20" />
            Population-level distribution shift
          </span>
          
          <div className="grid lg:grid-cols-[auto_1fr] gap-8 lg:gap-16 items-stretch">
            {/* Sphere image — left column, full height */}
            <div className={`w-48 lg:w-72 xl:w-80 shrink-0 transition-all duration-1000 ${
              isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
            }`}>
              <img
                src="/images/world.png"
                alt=""
                aria-hidden="true"
                className="w-full h-full object-contain object-center"
              />
            </div>

            {/* Title + description stacked */}
            <div className="flex flex-col justify-center">
              <h2 className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9] transition-all duration-1000 ${
                isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
              }`}>
                The population
                <br />
                <span className="text-muted-foreground">{verdict}</span>
              </h2>

              <p className={`mt-8 text-xl text-muted-foreground leading-relaxed max-w-2xl transition-all duration-1000 delay-100 ${
                isVisible ? "opacity-100" : "opacity-0"
              }`}>
                {statement}
              </p>

              <p className={`mt-6 text-sm text-muted-foreground max-w-2xl transition-all duration-1000 delay-200 ${
                isVisible ? "opacity-100" : "opacity-0"
              }`}>
                This is a statement about the population, not about any one
                image. Per-sample out-of-distribution flags are a separate
                question, answered by Module 1 on the dataset page.
              </p>
            </div>
          </div>
        </div>

        {/* Main content grid */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Large stat card */}
          <div className={`lg:col-span-2 relative p-8 lg:p-12 border border-foreground/10 bg-foreground/[0.02] overflow-hidden transition-all duration-700 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}>
            {/* Animated dots background with connecting lines */}
            <div className="absolute inset-0 opacity-70" aria-hidden="true">
              <svg
                className="absolute inset-0 w-full h-full"
                style={{ pointerEvents: "none" }}
              >
                <defs>
                  <style>{`
                    @keyframes drawLine {
                      0%   { stroke-dashoffset: 1000; opacity: 0; }
                      15%  { opacity: 1; }
                      70%  { opacity: 0.7; }
                      100% { stroke-dashoffset: 0; opacity: 0; }
                    }
                    .connecting-line {
                      stroke: #eca8d6;
                      stroke-width: 1.2;
                      fill: none;
                      stroke-dasharray: 1000;
                      animation: drawLine 3s ease-in-out infinite;
                    }
                  `}</style>
                </defs>
                {[...Array(19)].map((_, i) => {
                  const x1 = 10 + (i % 5) * 20;
                  const y1 = 10 + Math.floor(i / 5) * 25;
                  const x2 = 10 + ((i + 1) % 5) * 20;
                  const y2 = 10 + Math.floor((i + 1) / 5) * 25;
                  return (
                    <line
                      key={`line-${i}`}
                      x1={`${x1}%`}
                      y1={`${y1}%`}
                      x2={`${x2}%`}
                      y2={`${y2}%`}
                      className="connecting-line"
                      style={{ animationDelay: `${i * 0.15}s` }}
                    />
                  );
                })}
              </svg>

              {[...Array(20)].map((_, i) => (
                <div
                  key={i}
                  className="absolute w-1.5 h-1.5 rounded-full bg-[#eca8d6]"
                  style={{
                    left: `${10 + (i % 5) * 20}%`,
                    top: `${10 + Math.floor(i / 5) * 25}%`,
                    animation: `pulse 2s ease-in-out ${i * 0.1}s infinite`,
                  }}
                />
              ))}
            </div>
            
            <div className="relative z-10">
              <div className="flex items-baseline gap-2 mb-4 flex-wrap">
                <span className="text-8xl lg:text-[10rem] font-display leading-none">{headlineValue}</span>
                <span className="text-2xl text-muted-foreground">{headlineUnit}</span>
              </div>
              <p className="text-muted-foreground max-w-md">{headlineNote}</p>
              <Link
                href={href}
                className="mt-8 inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors group"
              >
                Open the shift assessment
                <span aria-hidden="true" className="group-hover:translate-x-1 transition-transform">&rarr;</span>
              </Link>
            </div>
          </div>

          {/* Stacked stat cards */}
          <div className="flex flex-col gap-6">
            {stats.slice(0, 2).map((stat, index) => (
              <div
                key={stat.label}
                className={`p-8 border border-foreground/10 bg-foreground/[0.02] transition-all duration-700 ${
                  isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
                }`}
                style={{ transitionDelay: `${(index + 1) * 100}ms` }}
              >
                <span className="text-5xl lg:text-6xl font-display break-all">{stat.value}</span>
                <span className="block text-sm text-muted-foreground mt-2">{stat.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Metric list */}
        <div className={`mt-12 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 transition-all duration-1000 delay-300 ${
          isVisible ? "opacity-100" : "opacity-0"
        }`}>
          {rows.map((row, index) => (
            <div
              key={row.name}
              className={`p-6 border transition-all duration-300 cursor-default ${
                activeRow === index 
                  ? "border-foreground/30 bg-foreground/[0.04]" 
                  : "border-foreground/10"
              }`}
            >
              <div className="flex items-center gap-2 mb-3">
                <span aria-hidden="true" className={`w-2 h-2 rounded-full transition-colors ${
                  activeRow === index ? "bg-[#eca8d6]" : "bg-foreground/20"
                }`} />
                <span className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                  {row.status}
                </span>
              </div>
              <span className="font-medium block mb-1 break-words">{row.name}</span>
              <span className="text-sm text-muted-foreground break-words">{row.detail}</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
