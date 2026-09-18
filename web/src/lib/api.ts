export const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8000";

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Disposition = "ACCEPT" | "REVIEW" | "QUARANTINE";
export type Coverage =
  | "SUPPORTED"
  | "PARTIAL"
  | "NOT_SUPPORTED"
  | "NOT_ASSESSED"
  | "REQUIRES_WHITE_BOX";
export type ConfidenceBasis =
  | "DETERMINISTIC"
  | "STATISTICAL"
  | "CALIBRATED"
  | "HEURISTIC_UNCALIBRATED";

export interface EvidenceItem {
  kind: string;
  statement: string;
  observation: Record<string, unknown>;
  refs: string[];
}

export interface AssetRef {
  type: string;
  id: string;
  locator: string | null;
  digest: string | null;
}

export interface Finding {
  finding_id: string;
  observed_at: string;
  asset: AssetRef;
  contributor: string | null;
  category: string;
  attack_class: string;
  title: string;
  severity: Severity;
  confidence: number;
  confidence_basis: ConfidenceBasis;
  evidence: EvidenceItem[];
  method: string;
  method_version: string;
  assumptions: string[];
  limitations: string[];
  coverage: Coverage;
  disposition: Disposition;
  disposition_rule: string;
}

export interface AssessmentSummary {
  overall: string;
  rationale: string;
  findings_total: number;
  by_severity: Record<Severity, number>;
  by_disposition: Record<Disposition, number>;
  by_attack_class: Record<string, number>;
  assets_affected: number;
  contributors_affected: number;
}

export interface DetectorReport {
  name: string;
  version: string;
  findings: number;
  stats: Record<string, unknown>;
}

export interface CoverageEntry {
  attack_class: string;
  title: string;
  coverage: Coverage;
  owning_module: number;
  detector: string | null;
  detector_version: string | null;
  reason: string | null;
  assumptions: string[];
  limitations: string[];
}

export interface CoverageStatement {
  implemented_modules: number[];
  entries: CoverageEntry[];
}

export interface AssuranceReport {
  schema_version: string;
  report_id: string;
  generated_at: string;
  module: string;
  dataset: Record<string, unknown>;
  summary: AssessmentSummary;
  findings: Finding[];
  contributor_risk: Record<string, unknown>[];
  detectors: DetectorReport[];
  coverage: CoverageStatement;
  limitations: string[];
}

export interface DemoResponse {
  duration_s: number;
  baseline: {
    manifest_id: string;
    digest: string;
    samples: number;
    classes: string[];
    contributors: Record<string, unknown>;
    attribution: string;
  };
  clean_report: AssuranceReport;
  attack: { scenario: string; affected_count: number; total_samples: number };
  attacked_report: AssuranceReport;
  evaluation: Record<string, unknown>;
  verification: {
    manifest_self_consistent: boolean;
    dataset_matches: boolean;
    checked: number;
    modified: Record<string, unknown>[];
    added: string[];
    missing: string[];
  };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; cvtrust_version: string }>("/api/health"),
  coverage: () => request<CoverageStatement>("/api/coverage"),
  demo: (refresh = false) => request<DemoResponse>(`/api/demo${refresh ? "?refresh=true" : ""}`),
  scan: (root: string) =>
    request<AssuranceReport>("/api/dataset/scan", {
      method: "POST",
      body: JSON.stringify({ root }),
    }),
};
