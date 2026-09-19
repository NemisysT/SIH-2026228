/**
 * Synthetic reports for the cases the real feed does not contain.
 *
 * The real attack-lab exports are used wherever they exist — a test against
 * fabricated data proves nothing about the engine. These fixtures exist only
 * for the malformed / hostile inputs §32 asks about, which the engine by
 * construction never produces.
 */

import type { AssuranceReport, DatasetReport, ProvenanceReport } from "../lib/analyst/types.ts"

/** A report with almost nothing in it: every optional field absent. */
export const EMPTY_REPORT: AssuranceReport = {}

/** Fields present but of the wrong type, as a corrupted file would give. */
export const MALFORMED_REPORT = {
  report_id: 42,
  decision: { disposition: ["QUARANTINE"], fired_rules: "not-a-list" },
  evidence: { evidence: null, groups: undefined },
  source_findings: "nope",
  coverage: { entries: [{ attack_class: null, coverage: 7 }] },
  dataset_assurance: { scope: "dataset", disposition: 99, assessed: "yes" },
} as unknown as AssuranceReport

/** A finding type no version of the schema has ever defined. */
export const UNKNOWN_FINDING_REPORT: AssuranceReport = {
  report_id: "AR-unknown",
  decision: { disposition: "REVIEW", decision_id: "D-1", fired_rules: [] },
  source_findings: [
    {
      finding_id: "F-unknown",
      attack_class: "quantum_telepathy",
      category: "from_the_future",
      severity: "APOCALYPTIC",
      confidence: 1.5,
      confidence_basis: "VIBES",
      coverage: "TOTALLY_COVERED",
      title: "A finding from a schema this build does not know",
      evidence: [{ kind: "unknown_kind", statement: "something happened" }],
    },
  ],
  evidence: {
    evidence: [
      {
        evidence_id: "E-unknown",
        finding_id: "F-unknown",
        source_module: 9,
        source_detector: "oracle",
        attack_class: "quantum_telepathy",
        evidence_class: "PRECOGNITION",
        severity: "APOCALYPTIC",
        confidence_basis: "VIBES",
        coverage: "TOTALLY_COVERED",
        title: "A finding from a schema this build does not know",
      },
    ],
    groups: [],
  },
}

/** Two evidence items that point opposite ways on the same asset. */
export const CONFLICTING_REPORT: AssuranceReport = {
  report_id: "AR-conflict",
  decision: {
    disposition: "REVIEW",
    decision_id: "D-conflict",
    fired_rules: [
      {
        rule_id: "RULE-A",
        scope: "model",
        disposition: "QUARANTINE",
        statement: "model is compromised",
        evidence_ids: ["E-1"],
      },
      {
        rule_id: "RULE-B",
        scope: "model",
        disposition: "ACCEPT",
        statement: "model matches the reference",
        evidence_ids: ["E-2"],
      },
    ],
    conflicts: [{ between: ["E-1", "E-2"], detail: "opposite conclusions on one artifact" }],
  },
  evidence: {
    evidence: [
      {
        evidence_id: "E-1",
        finding_id: "F-1",
        severity: "CRITICAL",
        confidence: 0.9,
        confidence_basis: "DETERMINISTIC",
        supports: true,
        title: "digest mismatch",
      },
      {
        evidence_id: "E-2",
        finding_id: "F-2",
        severity: "INFO",
        confidence: 0.2,
        confidence_basis: "HEURISTIC_UNCALIBRATED",
        supports: false,
        title: "behaviour matches",
      },
    ],
    groups: [],
  },
  source_findings: [],
}

/** 5000 evidence items, to check nothing quadratic crept into the joins. */
export function largeEvidenceReport(size = 5000): AssuranceReport {
  return {
    report_id: "AR-large",
    decision: { disposition: "REVIEW", decision_id: "D-large", fired_rules: [] },
    source_findings: Array.from({ length: size }, (_, i) => ({
      finding_id: `F-${i}`,
      title: `finding ${i}`,
      severity: i % 5 === 0 ? "CRITICAL" : "LOW",
      evidence: [{ kind: "k", statement: `observation ${i}` }],
    })),
    evidence: {
      evidence: Array.from({ length: size }, (_, i) => ({
        evidence_id: `E-${i}`,
        finding_id: `F-${i}`,
        severity: i % 5 === 0 ? "CRITICAL" : "LOW",
        confidence: (i % 100) / 100,
        confidence_basis: "STATISTICAL",
      })),
      groups: [],
    },
  }
}

/** A dataset report whose findings list is present but empty. */
export const EMPTY_FINDINGS_DATASET: DatasetReport = {
  report_id: "DR-empty",
  dataset: { root: "/tmp/x", digest: "abc", counts: { samples: 10 } },
  summary: { overall: "NO ACTIONABLE FINDINGS", findings_total: 0, by_severity: {} },
  findings: [],
  contributor_risk: [],
  detectors: [],
}

/** A chain broken at position 3, with four entries after it. */
export const BROKEN_CHAIN: ProvenanceReport = {
  report_id: "PR-break",
  chain: {
    status: "BROKEN",
    log_id: "L-1",
    entry_count: 7,
    first_break_position: 3,
    links: Array.from({ length: 7 }, (_, position) => ({
      position,
      record_id: `R-${position}`,
      entry_digest: `d${position}`,
      sequence_number: position,
      sequence_expected: position,
      sequence_valid: true,
      declared_previous_digest: position === 0 ? null : `d${position - 1}`,
      expected_previous_digest: position === 0 ? null : `d${position - 1}`,
      link_status: position === 3 ? "BROKEN" : "VALID",
      detail: position === 3 ? "declared previous digest does not match" : "links correctly",
    })),
  },
  records: [],
  verifications: [],
}
