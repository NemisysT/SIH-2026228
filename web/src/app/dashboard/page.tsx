"use client";

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { Eyebrow } from "@/components/site/eyebrow";
import { Glow } from "@/components/site/glow";
import { Footer } from "@/components/site/footer";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Skeleton } from "@/components/ui/skeleton";
import {
  CoverageBadge,
  DispositionBadge,
  OverallBadge,
  SeverityBadge,
} from "@/components/dashboard/badges";
import { api, type AssuranceReport, type DemoResponse } from "@/lib/api";

function StatPanel({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="border border-foreground/10 bg-card p-6">
      <span className="block text-3xl lg:text-4xl font-display">{value}</span>
      <span className="block text-sm text-muted-foreground font-mono mt-2 uppercase tracking-wide">
        {label}
      </span>
      {sub ? <span className="block text-xs text-muted-foreground mt-1">{sub}</span> : null}
    </div>
  );
}

function SeverityBar({ summary }: { summary: AssuranceReport["summary"] }) {
  const total = summary.findings_total || 1;
  const order: Array<[keyof typeof summary.by_severity, string]> = [
    ["CRITICAL", "bg-destructive"],
    ["HIGH", "bg-destructive/60"],
    ["MEDIUM", "bg-highlight"],
    ["LOW", "bg-foreground/40"],
    ["INFO", "bg-foreground/15"],
  ];
  return (
    <div>
      <div className="flex h-2 w-full overflow-hidden bg-foreground/5">
        {order.map(([sev, color]) => {
          const count = summary.by_severity[sev] ?? 0;
          if (!count) return null;
          return (
            <div
              key={sev}
              className={color}
              style={{ width: `${(count / total) * 100}%` }}
              title={`${sev}: ${count}`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-6 gap-y-2 mt-4">
        {order.map(([sev]) => (
          <div key={sev} className="flex items-center gap-2 text-sm">
            <SeverityBadge severity={sev} />
            <span className="text-muted-foreground font-mono">{summary.by_severity[sev] ?? 0}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportView({ report }: { report: AssuranceReport }) {
  const findings = [...report.findings].slice(0, 25);
  return (
    <div className="space-y-8">
      <div className="border border-foreground/10 bg-card p-8">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
          <OverallBadge overall={report.summary.overall} />
          <span className="text-xs text-muted-foreground font-mono">{report.report_id}</span>
        </div>
        <p className="text-muted-foreground leading-relaxed">{report.summary.rationale}</p>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatPanel label="Findings" value={String(report.summary.findings_total)} />
        <StatPanel label="Assets affected" value={String(report.summary.assets_affected)} />
        <StatPanel label="Contributors affected" value={String(report.summary.contributors_affected)} />
        <StatPanel label="Detectors run" value={String(report.detectors.length)} />
      </div>

      <div className="border border-foreground/10 bg-card p-8">
        <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
          Severity distribution
        </span>
        <div className="mt-4">
          <SeverityBar summary={report.summary} />
        </div>
      </div>

      <div className="border border-foreground/10 bg-card overflow-hidden">
        <div className="p-6 pb-0">
          <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
            Findings {report.findings.length > 25 ? `(first 25 of ${report.findings.length})` : ""}
          </span>
        </div>
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-foreground/10 hover:bg-transparent">
                <TableHead>Title</TableHead>
                <TableHead>Attack class</TableHead>
                <TableHead>Contributor</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Disposition</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f) => (
                <TableRow key={f.finding_id} className="border-foreground/10">
                  <TableCell className="max-w-xs truncate font-medium">{f.title}</TableCell>
                  <TableCell className="text-muted-foreground font-mono text-xs">
                    {f.attack_class}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{f.contributor ?? "—"}</TableCell>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {f.confidence.toFixed(2)}
                  </TableCell>
                  <TableCell>
                    <DispositionBadge disposition={f.disposition} />
                  </TableCell>
                </TableRow>
              ))}
              {findings.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-10">
                    No findings — nothing crossed the review threshold.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="border border-foreground/10 bg-card p-6">
          <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
            Detector stats
          </span>
          <ul className="mt-4 space-y-3">
            {report.detectors.map((d) => (
              <li key={d.name} className="flex items-center justify-between text-sm border-b border-foreground/5 pb-2 last:border-0">
                <span className="font-medium">{d.name}</span>
                <span className="font-mono text-muted-foreground">{d.findings} finding(s)</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="border border-foreground/10 bg-card p-6">
          <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
            Contributor risk
          </span>
          <ul className="mt-4 space-y-3">
            {(report.contributor_risk as Array<Record<string, unknown>>).slice(0, 6).map((c, i) => (
              <li key={i} className="flex items-center justify-between text-sm border-b border-foreground/5 pb-2 last:border-0">
                <span className="font-medium">
                  {String(c.contributor)} <span className="text-muted-foreground font-mono text-xs">/ {String(c.attack_class)}</span>
                </span>
                <span className="font-mono text-muted-foreground text-xs">
                  rate ×{typeof c.rate_ratio === "number" ? c.rate_ratio.toFixed(1) : "—"}
                </span>
              </li>
            ))}
            {report.contributor_risk.length === 0 && (
              <li className="text-sm text-muted-foreground">No contributor-level risk aggregated.</li>
            )}
          </ul>
        </div>
      </div>

      <div className="border border-foreground/10 bg-card p-6">
        <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground mb-4 block">
          Coverage statement
        </span>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {report.coverage.entries.map((e) => (
            <div
              key={e.attack_class}
              className="flex items-center justify-between gap-3 border border-foreground/10 px-3 py-2"
            >
              <span className="text-xs truncate">{e.title}</span>
              <CoverageBadge coverage={e.coverage} />
            </div>
          ))}
        </div>
      </div>

      <Accordion className="border border-foreground/10 bg-card px-6">
        <AccordionItem value="limitations" className="border-none">
          <AccordionTrigger className="font-mono text-xs uppercase tracking-wide text-muted-foreground hover:no-underline">
            Declared limitations ({report.limitations.length})
          </AccordionTrigger>
          <AccordionContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {report.limitations.map((l, i) => (
                <li key={i} className="leading-relaxed">
                  • {l}
                </li>
              ))}
            </ul>
          </AccordionContent>
        </AccordionItem>
      </Accordion>
    </div>
  );
}

export default function DashboardPage() {
  const [data, setData] = useState<DemoResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (refresh: boolean, cancelledRef?: { current: boolean }) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.demo(refresh);
      if (!cancelledRef?.current) setData(res);
    } catch (e) {
      if (!cancelledRef?.current) {
        setError(
          e instanceof Error
            ? `${e.message} — is the API running? (./.venv/bin/uvicorn api.server:app --port 8000)`
            : "Unknown error"
        );
      }
    } finally {
      if (!cancelledRef?.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const cancelledRef = { current: false };
    // Initial data fetch on mount; setLoading(true) inside `load` runs before
    // its first await, which this lint rule can't distinguish from a bug.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(false, cancelledRef);
    return () => {
      cancelledRef.current = true;
    };
  }, [load]);

  return (
    <main className="relative min-h-screen overflow-x-hidden pt-32 pb-24">
      <Glow className="top-40 -right-40 w-[500px] h-[500px]" />
      <div className="relative z-10 max-w-[1400px] mx-auto px-6 lg:px-12">
        <div className="flex flex-wrap items-end justify-between gap-6 mb-12">
          <div>
            <Eyebrow>Live pipeline run</Eyebrow>
            <h1 className="text-5xl lg:text-6xl font-display tracking-tight leading-[0.95]">
              Judge-facing demonstration
            </h1>
            <p className="mt-4 text-muted-foreground max-w-xl">
              Generates a reproducible clean corpus, submits a multi-contributor
              attack, detects it, scores against ground truth, then tampers the
              dataset post-baseline and re-verifies. Every number below comes
              from a real run started seconds ago.
            </p>
          </div>
          <Button
            onClick={() => load(true)}
            disabled={loading}
            size="lg"
            className="rounded-full px-6 h-11 shrink-0"
          >
            <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Running…" : "Run again"}
          </Button>
        </div>

        {error && (
          <div className="border border-destructive/40 bg-destructive/10 text-destructive p-6 flex items-start gap-3 mb-10">
            <AlertTriangle className="size-5 shrink-0 mt-0.5" />
            <p className="text-sm leading-relaxed">{error}</p>
          </div>
        )}

        {loading && !data && (
          <div className="space-y-4">
            <Skeleton className="h-32 w-full bg-foreground/5" />
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-24 w-full bg-foreground/5" />
              ))}
            </div>
            <Skeleton className="h-64 w-full bg-foreground/5" />
          </div>
        )}

        {data && (
          <>
            <div className="border border-foreground/10 bg-card p-8 mb-10">
              <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
                <div>
                  <span className="block text-sm text-muted-foreground font-mono uppercase tracking-wide mb-2">
                    Baseline
                  </span>
                  <span className="block text-2xl font-display">{data.baseline.samples} samples</span>
                  <span className="text-xs text-muted-foreground">
                    {Object.keys(data.baseline.contributors).length} contributors · {data.baseline.classes.length} classes
                  </span>
                </div>
                <div>
                  <span className="block text-sm text-muted-foreground font-mono uppercase tracking-wide mb-2">
                    Attack
                  </span>
                  <span className="block text-2xl font-display">{data.attack.affected_count} manipulated</span>
                  <span className="text-xs text-muted-foreground">of {data.attack.total_samples} samples, scenario &quot;{data.attack.scenario}&quot;</span>
                </div>
                <div>
                  <span className="block text-sm text-muted-foreground font-mono uppercase tracking-wide mb-2">
                    Post-baseline verify
                  </span>
                  <span className="flex items-center gap-2 text-2xl font-display">
                    {data.verification.dataset_matches ? (
                      <CheckCircle2 className="size-5 text-highlight" />
                    ) : (
                      <XCircle className="size-5 text-destructive" />
                    )}
                    {data.verification.dataset_matches ? "Clean" : "Tamper caught"}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {data.verification.modified.length} modified, {data.verification.added.length} added
                  </span>
                </div>
                <div>
                  <span className="block text-sm text-muted-foreground font-mono uppercase tracking-wide mb-2">
                    Run time
                  </span>
                  <span className="block text-2xl font-display">{data.duration_s}s</span>
                  <span className="text-xs text-muted-foreground">end-to-end, this machine</span>
                </div>
              </div>
            </div>

            <Tabs defaultValue="attacked">
              <TabsList className="bg-card border border-foreground/10 rounded-full p-1 h-auto mb-8">
                <TabsTrigger value="attacked" className="rounded-full data-[state=active]:bg-foreground data-[state=active]:text-background">
                  Attacked dataset
                </TabsTrigger>
                <TabsTrigger value="clean" className="rounded-full data-[state=active]:bg-foreground data-[state=active]:text-background">
                  Clean baseline
                </TabsTrigger>
              </TabsList>
              <TabsContent value="attacked">
                <ReportView report={data.attacked_report} />
              </TabsContent>
              <TabsContent value="clean">
                <ReportView report={data.clean_report} />
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
      <div className="mt-24">
        <Footer />
      </div>
    </main>
  );
}
