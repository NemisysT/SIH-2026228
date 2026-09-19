"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

/**
 * The reference's bento feature section, carrying the four assurance scopes.
 *
 * The large card — black plate, live particle field, the number/title/body/
 * stat stack on the left and the mirrored supplied image bleeding off the
 * right — is the reference's, unchanged. So is the diagonal 12-column header
 * with its oversized display title.
 *
 * What it now holds is the decision: one card for the pipeline disposition,
 * then the four scopes as their own rows. The four are never merged into one
 * status, because `model suspicious + provenance valid` and `model clean +
 * provenance invalid` are opposite situations that call for opposite actions.
 */

export interface ScopeCard {
  scope: string;
  label: string;
  disposition: string;
  assessed: boolean;
  governingRule: string | null;
  statement: string;
  findings: number;
  href: string;
}

// Floating dot particles visualization
function ParticleVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const frameRef = useRef(0);
  const mouseRef = useRef({ x: 0.5, y: 0.5 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);
    };
    resize();
    window.addEventListener("resize", resize);

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = {
        x: (e.clientX - rect.left) / rect.width,
        y: (e.clientY - rect.top) / rect.height,
      };
    };
    canvas.addEventListener("mousemove", handleMouseMove);

    // Generate stable particle positions
    const COUNT = 70;
    const particles = Array.from({ length: COUNT }, (_, i) => {
      const seed = i * 1.618;
      return {
        bx: ((seed * 127.1) % 1),
        by: ((seed * 311.7) % 1),
        phase: seed * Math.PI * 2,
        speed: 0.4 + (seed % 0.4),
        radius: 1.2 + (seed % 2.2),
      };
    });

    let time = 0;
    const render = () => {
      const rect = canvas.getBoundingClientRect();
      const w = rect.width;
      const h = rect.height;

      ctx.clearRect(0, 0, w, h);

      const mx = mouseRef.current.x;
      const my = mouseRef.current.y;

      particles.forEach((p) => {
        const flowX = Math.sin(time * p.speed * 0.4 + p.phase) * 38;
        const flowY = Math.cos(time * p.speed * 0.3 + p.phase * 0.7) * 24;

        const bx = p.bx * w;
        const by = p.by * h;
        const dx = p.bx - mx;
        const dy = p.by - my;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const influence = Math.max(0, 1 - dist * 2.8);

        const x = bx + flowX + influence * Math.cos(time + p.phase) * 36;
        const y = by + flowY + influence * Math.sin(time + p.phase) * 36;

        const pulse = Math.sin(time * p.speed + p.phase) * 0.5 + 0.5;
        const alpha = 0.08 + pulse * 0.18 + influence * 0.3;

        ctx.beginPath();
        ctx.arc(x, y, p.radius + pulse * 0.8, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${alpha})`;
        ctx.fill();
      });

      time += 0.016;
      frameRef.current = requestAnimationFrame(render);
    };
    render();

    return () => {
      window.removeEventListener("resize", resize);
      canvas.removeEventListener("mousemove", handleMouseMove);
      cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 pointer-events-auto"
      style={{ width: "100%", height: "100%" }}
    />
  );
}

export function FeaturesSection({
  disposition,
  summary,
  reportId,
  policyVersion,
  scopes,
  decisionHref,
}: {
  disposition: string;
  summary: string;
  reportId: string;
  policyVersion: string;
  scopes: ScopeCard[];
  decisionHref: string;
}) {
  const [isVisible, setIsVisible] = useState(false);
  const [activeScope, setActiveScope] = useState(0);
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

  return (
    <section
      id="scopes"
      ref={sectionRef}
      className="relative py-24 lg:py-32 overflow-hidden"
    >
      <div className="max-w-[1400px] mx-auto px-6 lg:px-12">
        {/* Header - Full width with diagonal layout */}
        <div className="relative mb-24 lg:mb-32">
          <div className="grid lg:grid-cols-12 gap-8 items-end">
            <div className="lg:col-span-7">
              <span className="inline-flex items-center gap-3 text-sm font-mono text-muted-foreground mb-6">
                <span className="w-12 h-px bg-foreground/30" />
                Assurance scopes
              </span>
              <h2
                className={`text-6xl md:text-7xl lg:text-[128px] font-display tracking-tight leading-[0.9] transition-all duration-1000 ${
                  isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
                }`}
              >
                Four scopes.
                <br />
                <span className="text-muted-foreground">No single score.</span>
              </h2>
            </div>
            <div className="lg:col-span-5 lg:pb-4">
              <p className={`text-xl text-muted-foreground leading-relaxed transition-all duration-1000 delay-200 ${
                isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"
              }`}>
                Dataset, model, provenance and distribution each keep their own
                disposition. The platform never averages them into a trust
                score, because the four failures they describe are not
                interchangeable.
              </p>
            </div>
          </div>
        </div>

        {/* Bento Grid Layout */}
        <div className="grid lg:grid-cols-12 gap-4 lg:gap-6">
          {/* Large feature card */}
          <div 
            className={`lg:col-span-12 relative bg-black border border-foreground/10 min-h-[500px] overflow-hidden group transition-all duration-700 flex ${
              isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-12"
            }`}
          >
            {/* Left: text content */}
            <div className="relative flex-1 p-8 lg:p-12 bg-black">
              <ParticleVisualization />
              <div className="relative z-10">
                <span className="font-mono text-sm text-muted-foreground">Pipeline disposition</span>
                <h3 className="text-3xl lg:text-4xl font-display mt-4 mb-6 group-hover:translate-x-2 transition-transform duration-500">
                  {disposition}
                </h3>
                <p className="text-lg text-muted-foreground leading-relaxed max-w-md mb-8">
                  {summary}
                </p>
                <div className="flex flex-wrap gap-10">
                  <div>
                    <span className="text-5xl lg:text-6xl font-display break-all">{reportId}</span>
                    <span className="block text-sm text-muted-foreground font-mono mt-2">assurance report id</span>
                  </div>
                  <div>
                    <span className="text-5xl lg:text-6xl font-display">{policyVersion}</span>
                    <span className="block text-sm text-muted-foreground font-mono mt-2">policy version</span>
                  </div>
                </div>
                <Link
                  href={decisionHref}
                  className="mt-8 inline-flex items-center gap-2 text-sm font-mono text-muted-foreground hover:text-foreground transition-colors"
                >
                  Why this disposition
                  <span aria-hidden="true" className="transition-transform group-hover:translate-x-1">&rarr;</span>
                </Link>
              </div>
            </div>

            {/* Right: mirrored image, full height */}
            <div className="hidden lg:block relative w-[42%] shrink-0 overflow-hidden">
              <img
                src="/images/dataset-panel.png"
                alt=""
                aria-hidden="true"
                className="absolute inset-0 w-full h-full object-cover object-center"
                style={{ transform: "scaleX(-1)" }}
              />
              {/* Fade left edge into black */}
              <div className="absolute inset-0 bg-gradient-to-r from-black via-transparent to-transparent" />
            </div>
          </div>

          {/* Scope cards — one row each, never merged */}
          {scopes.map((scope, index) => (
            <Link
              key={scope.scope}
              href={scope.href}
              onMouseEnter={() => setActiveScope(index)}
              onFocus={() => setActiveScope(index)}
              className={`lg:col-span-3 relative block p-8 border transition-all duration-500 ${
                activeScope === index
                  ? "border-foreground/30 bg-foreground/[0.04]"
                  : "border-foreground/10 bg-foreground/[0.02] hover:border-foreground/30"
              } ${isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}`}
              style={{ transitionDelay: `${index * 80 + 200}ms` }}
            >
              <div className="flex items-center justify-between gap-3 mb-6">
                <span className="font-mono text-sm text-muted-foreground">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-foreground/10 text-muted-foreground uppercase tracking-wider">
                  {scope.assessed ? "assessed" : "not assessed"}
                </span>
              </div>
              <h3 className="text-2xl lg:text-3xl font-display mb-2">{scope.label}</h3>
              <p className="text-xl font-display text-muted-foreground mb-4">{scope.disposition}</p>
              <p className="text-sm text-muted-foreground leading-relaxed line-clamp-4">
                {scope.statement}
              </p>
              <div className="mt-6 flex items-center justify-between text-xs font-mono text-muted-foreground">
                <span>{scope.governingRule ?? "no rule fired"}</span>
                <span>{scope.findings} finding(s)</span>
              </div>
              <div className="absolute bottom-0 left-0 right-0 h-px bg-foreground/20 overflow-hidden">
                <div className={`h-full bg-foreground transition-all duration-500 ${
                  activeScope === index ? "w-full" : "w-0"
                }`} />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}
