"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

/**
 * The reference's closing call to action, carrying the report actions.
 *
 * Preserved exactly: the single foreground-bordered box, the cursor-following
 * spotlight, the 72px display headline, the pill buttons, the bridge image
 * bleeding off the right, and the two decorative corner rules.
 *
 * The actions open and download the engine's own report files. §30 is explicit
 * that the frontend must not define a report format of its own, so these links
 * serve the exact bytes Module 1-4 wrote — the analyst can diff what the
 * screen said against what the engine produced.
 */

export interface ReportLink {
  label: string;
  description: string;
  href: string;
  available: boolean;
}

export function CtaSection({
  reports,
  scenarioLabel,
}: {
  reports: ReportLink[];
  scenarioLabel: string;
}) {
  const [isVisible, setIsVisible] = useState(false);
  const sectionRef = useRef<HTMLDivElement>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setIsVisible(true);
      },
      { threshold: 0.2 }
    );

    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    setMousePosition({
      x: ((e.clientX - rect.left) / rect.width) * 100,
      y: ((e.clientY - rect.top) / rect.height) * 100,
    });
  };

  const primary = reports.find((report) => report.available) ?? null;

  return (
    <section id="reports" ref={sectionRef} className="relative py-24 lg:py-32 overflow-hidden">
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        <div
          className={`relative border border-foreground transition-all duration-1000 ${
            isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
          }`}
          onMouseMove={handleMouseMove}
        >
          {/* Spotlight effect */}
          <div 
            aria-hidden="true"
            className="absolute inset-0 opacity-10 pointer-events-none transition-opacity duration-300"
            style={{
              background: `radial-gradient(600px circle at ${mousePosition.x}% ${mousePosition.y}%, rgba(0,0,0,0.15), transparent 40%)`
            }}
          />
          
          <div className="relative z-10 px-8 lg:px-16 py-16 lg:py-24">
            <div className="flex flex-col lg:flex-row items-center justify-between gap-12">
              {/* Left content */}
              <div className="flex-1 min-w-0">
                <h2 className="text-6xl md:text-7xl lg:text-[72px] font-display tracking-tight mb-8 leading-[0.95]">
                  Read the report
                  <br />
                  the engine wrote.
                </h2>

                <p className="text-xl text-muted-foreground mb-12 leading-relaxed max-w-xl">
                  Every number on these screens comes out of the JSON below. The
                  frontend defines no schema of its own — it serves the exact
                  bytes Modules 1 to 4 produced for {scenarioLabel}.
                </p>

                <div className="flex flex-col sm:flex-row items-start gap-4">
                  {primary ? (
                    <Button
                      asChild
                      size="lg"
                      className="bg-foreground hover:bg-foreground/90 text-background px-8 h-14 text-base rounded-full group"
                    >
                      <a href={primary.href} target="_blank" rel="noreferrer">
                        View assurance JSON
                        <ArrowRight aria-hidden="true" className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-1" />
                      </a>
                    </Button>
                  ) : null}
                  <Button
                    asChild
                    size="lg"
                    variant="outline"
                    className="h-14 px-8 text-base rounded-full border-foreground/20 hover:bg-foreground/5"
                  >
                    <Link href="/coverage">Read the limitations</Link>
                  </Button>
                </div>

                <ul className="mt-10 grid sm:grid-cols-2 gap-x-8 gap-y-3">
                  {reports.map((report) => (
                    <li key={report.label} className="text-sm">
                      {report.available ? (
                        <a
                          href={report.href}
                          download
                          className="font-mono text-muted-foreground hover:text-foreground transition-colors underline underline-offset-4"
                        >
                          {report.label}
                        </a>
                      ) : (
                        <span className="font-mono text-muted-foreground/50">
                          {report.label} — not produced for this run
                        </span>
                      )}
                      <span className="block text-muted-foreground text-xs mt-1">
                        {report.description}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Right image */}
              <div className="hidden lg:flex items-end justify-center w-[520px] shrink-0 h-[560px] -mr-16" aria-hidden="true">
                <img
                  src="/images/bridge.png"
                  alt=""
                  aria-hidden="true"
                  className="w-full h-full object-contain object-bottom"
                />
              </div>
            </div>
          </div>

          {/* Decorative corner */}
          <div aria-hidden="true" className="absolute top-0 right-0 w-32 h-32 border-b border-l border-foreground/10" />
          <div aria-hidden="true" className="absolute bottom-0 left-0 w-32 h-32 border-t border-r border-foreground/10" />
        </div>
      </div>
    </section>
  );
}
