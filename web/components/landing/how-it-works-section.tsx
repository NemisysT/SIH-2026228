"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

/**
 * The reference's process section, carrying the four-module pipeline.
 *
 * Preserved exactly: the oklch(0.09 0.01 260) plate, the blurred white orb,
 * the three-line display title with its 100/30/10 opacity ladder, the cherry
 * tree bleeding up the right column with its left-edge fade, the numbered step
 * cards with the pink 01/02/03 numeral, the 6-second progress hairline, the
 * bottom accent bar that scales in from the left, and the styled-jsx keyframes
 * that drive it.
 *
 * The steps are now Modules 1 through 4 — the actual order evidence travels
 * through the engine, and the order the demo walks.
 */

export interface PipelineStep {
  number: string;
  title: string;
  subtitle: string;
  description: string;
  status: string;
  href: string;
}

export function HowItWorksSection({ steps }: { steps: PipelineStep[] }) {
  const [activeStep, setActiveStep] = useState(0);
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = useRef<HTMLDivElement>(null);

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
    if (steps.length === 0) return;
    const interval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % steps.length);
    }, 6000);
    return () => clearInterval(interval);
  }, [steps.length]);

  return (
    <section
      id="pipeline"
      ref={sectionRef}
      className="relative py-24 lg:py-32 bg-[oklch(0.09_0.01_260)] text-white overflow-hidden"
    >
      <div className="absolute bottom-0 left-0 w-[400px] h-[400px] rounded-full bg-white/[0.02] blur-[100px] pointer-events-none" />

      <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header — title + tree image */}
        <div className="relative mb-0 lg:mb-0 grid lg:grid-cols-2 gap-4 lg:gap-12 items-end">
          <div className="overflow-hidden pb-0 lg:pb-32">
            <div className={`transition-all duration-1000 ${isVisible ? "translate-x-0 opacity-100" : "-translate-x-12 opacity-0"}`}>
              <span className="inline-flex items-center gap-3 text-sm font-mono text-white/40 mb-8">
                <span className="w-12 h-px bg-white/20" />
                Assurance pipeline
              </span>
            </div>

            <h2 className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.85] transition-all duration-1000 delay-100 ${
              isVisible ? "translate-y-0 opacity-100" : "translate-y-16 opacity-0"
            }`}>
              <span className="block">Observe.</span>
              <span className="block text-white/30">Verify.</span>
              <span className="block text-white/10">Decide.</span>
            </h2>
          </div>

          {/* Tree image — sits on the bottom of the blocks */}
          <div className={`relative h-[320px] lg:h-[640px] overflow-hidden transition-all duration-1000 delay-200 ${
            isVisible ? "opacity-100" : "opacity-0"
          }`}>
            <img
              src="/images/tree.png"
              alt=""
              aria-hidden="true"
              className="absolute bottom-0 left-0 w-full h-full object-contain object-bottom"
            />
            <div className="absolute inset-0 bg-gradient-to-r from-[oklch(0.09_0.01_260)] via-transparent to-transparent pointer-events-none" />
          </div>
        </div>

        {/* Horizontal Steps Layout */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {steps.map((step, index) => (
            <Link
              key={step.number}
              href={step.href}
              onMouseEnter={() => setActiveStep(index)}
              onFocus={() => setActiveStep(index)}
              className={`relative block text-left p-8 lg:p-12 border transition-all duration-500 ${
                activeStep === index 
                  ? "bg-[#000000] border-white/60" 
                  : "bg-[#000000] border-white/25 hover:border-white/50"
              }`}
            >
              {/* Step number with animated line */}
              <div className="flex items-center gap-4 mb-8">
                <span className={`text-4xl font-display transition-colors duration-300 ${
                  activeStep === index ? "text-[#eca8d6]" : "text-white/20"
                }`}>
                  {step.number}
                </span>
                <div className="flex-1 h-px bg-white/10 overflow-hidden">
                  {activeStep === index && (
                    <div className="h-full bg-[#eca8d6]/50 animate-progress" />
                  )}
                </div>
              </div>

              {/* Title */}
              <h3 className="text-3xl lg:text-4xl font-display mb-2">
                {step.title}
              </h3>
              <span className="text-xl text-white/40 font-display block mb-6">
                {step.subtitle}
              </span>

              {/* Description */}
              <p className={`text-sm text-white/60 leading-relaxed transition-opacity duration-300 ${
                activeStep === index ? "opacity-100" : "opacity-60"
              }`}>
                {step.description}
              </p>

              <span className="mt-6 inline-block text-xs font-mono uppercase tracking-wider text-white/40">
                {step.status}
              </span>

              {/* Active indicator */}
              <div className={`absolute bottom-0 left-0 right-0 h-1 bg-[#eca8d6] transition-transform duration-500 origin-left ${
                activeStep === index ? "scale-x-100" : "scale-x-0"
              }`} />
            </Link>
          ))}
        </div>
      </div>

      <style jsx>{`
        @keyframes progress {
          from { width: 0%; }
          to { width: 100%; }
        }
        .animate-progress {
          animation: progress 6s linear forwards;
        }
      `}</style>
    </section>
  );
}
