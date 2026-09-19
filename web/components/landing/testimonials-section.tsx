"use client";

import { useEffect, useState, useRef } from "react";
import { ArrowLeft, ArrowRight } from "lucide-react";

/**
 * The reference's testimonial carousel, carrying the findings that matter.
 *
 * Preserved exactly: the inverted plate (foreground background, background
 * text), the faint ASCII quote field behind it, the 200px display quote mark,
 * the 7/5 split, the large display quote with its fadeSlideIn, the circular
 * avatar with its initial, the metric card, the segmented progress bar with
 * its 8-second animation, the chip list underneath, and the arrow buttons.
 *
 * The quote is a finding's own statement, verbatim. The metric card carries
 * its severity and the basis of its confidence together, because a bare 0.62
 * invites the reader to treat it as a probability of compromise, and it is not
 * one unless the basis says CALIBRATED.
 */

export interface HeadlineFinding {
  findingId: string;
  statement: string;
  title: string;
  detector: string;
  module: string;
  severity: string;
  confidence: string;
  basis: string;
  attackClass: string;
}

export function TestimonialsSection({
  findings,
  emptyStatement,
}: {
  findings: HeadlineFinding[];
  emptyStatement: string;
}) {
  const [activeIndex, setActiveIndex] = useState(0);
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

  useEffect(() => {
    if (findings.length < 2) return;
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % findings.length);
    }, 8000);
    return () => clearInterval(interval);
  }, [findings.length]);

  const goTo = (index: number) => setActiveIndex(index);
  const goPrev = () =>
    setActiveIndex((prev) => (prev - 1 + findings.length) % findings.length);
  const goNext = () => setActiveIndex((prev) => (prev + 1) % findings.length);

  const active = findings[activeIndex];

  return (
    <section id="findings" ref={sectionRef} className="relative py-32 lg:py-40 bg-foreground text-background overflow-hidden">
      {/* ASCII background pattern */}
      <div
        aria-hidden="true"
        className="absolute inset-0 font-mono text-[10px] text-background/[0.02] leading-tight overflow-hidden whitespace-pre select-none"
      >
        {Array.from({ length: 60 }, () =>
          Array.from({ length: 100 }, (_, column) =>
            (column * 7) % 11 === 0 ? '"' : " "
          ).join("")
        ).join("\n")}
      </div>

      <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header */}
        <div className="flex items-center justify-between mb-20 gap-8">
          <div>
            <span className="inline-flex items-center gap-3 text-sm font-mono text-background/40 mb-4">
              <span className="w-12 h-px bg-background/20" />
              Findings
            </span>
            <h2 className={`text-4xl lg:text-5xl font-display transition-all duration-1000 ${
              isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
            }`}>
              What the detectors
              <span className="text-background/40"> actually observed.</span>
            </h2>
          </div>
          
          {/* Navigation arrows */}
          {findings.length > 1 ? (
            <div className="hidden lg:flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={goPrev}
                aria-label="Previous finding"
                className="p-4 border border-background/20 hover:bg-background/10 transition-colors"
              >
                <ArrowLeft aria-hidden="true" className="w-5 h-5" />
              </button>
              <button
                type="button"
                onClick={goNext}
                aria-label="Next finding"
                className="p-4 border border-background/20 hover:bg-background/10 transition-colors"
              >
                <ArrowRight aria-hidden="true" className="w-5 h-5" />
              </button>
            </div>
          ) : null}
        </div>

        {findings.length === 0 || !active ? (
          <div className="border border-background/20 bg-background/5 p-10 lg:p-14">
            <span className="text-7xl lg:text-8xl font-display block mb-6">No findings</span>
            <p className="text-lg text-background/60 max-w-2xl leading-relaxed">{emptyStatement}</p>
          </div>
        ) : (
          /* Main content - Split layout */
          <div className="grid lg:grid-cols-12 gap-12 lg:gap-20">
            {/* Quote side */}
            <div className="lg:col-span-7 relative">
              {/* Large quote mark */}
              <span aria-hidden="true" className="absolute -left-4 -top-8 text-[200px] font-display text-background/5 leading-none select-none">
                &ldquo;
              </span>
              
              <div className="relative">
                <blockquote 
                  key={activeIndex}
                  className="text-3xl lg:text-4xl xl:text-5xl font-display leading-[1.2] tracking-tight animate-fadeSlideIn"
                >
                  {active.statement}
                </blockquote>

                {/* Source */}
                <div className="mt-12 flex items-center gap-6">
                  <div className="w-14 h-14 rounded-full bg-background/10 flex items-center justify-center shrink-0">
                    <span className="font-display text-xl">{active.module}</span>
                  </div>
                  <div className="min-w-0">
                    <p className="text-lg font-medium break-words">{active.title}</p>
                    <p className="text-background/60 font-mono text-sm break-words">
                      {active.detector} · {active.findingId}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Metric cards side */}
            <div className="lg:col-span-5 flex flex-col justify-center gap-6">
              {/* Active finding — severity and basis together */}
              <div 
                key={`metric-${activeIndex}`}
                className="p-10 border border-background/20 bg-background/5 animate-fadeSlideIn"
              >
                <span className="text-7xl lg:text-8xl font-display block mb-4">
                  {active.severity}
                </span>
                <span className="text-lg text-background/60 block">
                  {active.attackClass}
                </span>
                <span className="mt-6 block text-sm font-mono text-background/50">
                  confidence {active.confidence} · {active.basis}
                </span>
              </div>

              {/* Progress indicators */}
              {findings.length > 1 ? (
                <div className="flex gap-2">
                  {findings.map((finding, idx) => (
                    <button
                      key={finding.findingId}
                      type="button"
                      onClick={() => goTo(idx)}
                      aria-label={`Show finding ${idx + 1} of ${findings.length}`}
                      className="flex-1 h-1 bg-background/20 overflow-hidden"
                    >
                      <div 
                        className={`h-full bg-background transition-all duration-300 ${
                          idx === activeIndex ? "w-full" : idx < activeIndex ? "w-full opacity-50" : "w-0"
                        }`}
                        style={idx === activeIndex ? { animation: "progress 8s linear forwards" } : {}}
                      />
                    </button>
                  ))}
                </div>
              ) : null}

              {/* Attack-class chips */}
              <div className="mt-4 pt-6 border-t border-background/10">
                <span className="text-xs font-mono text-background/30 uppercase tracking-widest block mb-4">
                  Finding identifiers
                </span>
                <div className="flex flex-wrap gap-3">
                  {findings.map((finding, idx) => (
                    <button
                      key={finding.findingId}
                      type="button"
                      onClick={() => goTo(idx)}
                      className={`px-4 py-2 text-sm font-mono border transition-all ${
                        idx === activeIndex 
                          ? "border-background/40 text-background" 
                          : "border-background/10 text-background/40 hover:border-background/30"
                      }`}
                    >
                      {finding.findingId}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        @keyframes fadeSlideIn {
          from {
            opacity: 0;
            transform: translateX(20px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
        .animate-fadeSlideIn {
          animation: fadeSlideIn 0.5s ease-out forwards;
        }
        @keyframes progress {
          from { width: 0%; }
          to { width: 100%; }
        }
      `}</style>
    </section>
  );
}
