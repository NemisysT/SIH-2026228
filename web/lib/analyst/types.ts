/**
 * The shapes the assurance engine writes, as the frontend reads them.
 *
 * These are deliberately permissive. The backend owns the schema (§30: the
 * frontend does not define a report schema), reports evolve, and a Module 5
 * page must render a report it only partly understands rather than crash on
 * it. So every field a page needs is optional here, and the projection
 * functions in this directory decide what an absent field means — usually
 * NOT_ASSESSED, never a fabricated value.
 */

/** The only four top-level answers the policy engine produces. */
export type Disposition = "ACCEPT" | "REVIEW" | "QUARANTINE" | "NOT_ASSESSED"

export const DISPOSITIONS: readonly Disposition[] = [
  "ACCEPT",
  "REVIEW",
  "QUARANTINE",
  "NOT_ASSESSED",
]

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

export const SEVERITY_ORDER: readonly Severity[] = [
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
]

/** Coverage is a statement about what was assessed. It is never a percentage. */
export type Coverage =
  | "SUPPORTED"
  | "PARTIAL"
  | "NOT_SUPPORTED"
  | "NOT_ASSESSED"
  | "REQUIRES_WHITE_BOX"

export const COVERAGE_LEVELS: readonly Coverage[] = [
  "SUPPORTED",
  "PARTIAL",
  "NOT_SUPPORTED",
  "NOT_ASSESSED",
  "REQUIRES_WHITE_BOX",
]

export type ConfidenceBasis =
  | "DETERMINISTIC"
  | "CALIBRATED"
  | "STATISTICAL"
  | "HEURISTIC_UNCALIBRATED"
  | string

export interface AssetRef {
  type?: string
  id?: string
  locator?: string
  digest?: string
}

export interface EvidenceItem {
  kind?: string
  statement?: string
  observation?: Record<string, unknown>
  refs?: string[]
}

export interface Finding {
  finding_id?: string
  schema_version?: string
  observed_at?: string
  asset?: AssetRef
  contributor?: string | null
  category?: string
  attack_class?: string
  title?: string
  severity?: Severity | string
  confidence?: number
  confidence_basis?: ConfidenceBasis
  evidence?: EvidenceItem[]
  method?: string
  method_version?: string
  assumptions?: string[]
  limitations?: string[]
  coverage?: Coverage | string
  disposition?: string
  disposition_rule?: string
}

export interface FusedEvidence {
  evidence_id?: string
  finding_id?: string
  source_module?: number
  source_detector?: string
  source_detector_version?: string
  asset?: AssetRef
  contributor?: string | null
  category?: string
  evidence_class?: string
  attack_class?: string
  title?: string
  severity?: Severity | string
  confidence?: number
  confidence_basis?: ConfidenceBasis
  coverage?: Coverage | string
  source_disposition?: string
  source_disposition_rule?: string
  raw_observation?: Record<string, unknown>
  assumptions?: string[]
  limitations?: string[]
  lineage?: {
    finding_id?: string
    source_module?: number
    source_detector?: string
    source_detector_version?: string
    source_report_id?: string
    source_run_id?: string
    refs?: string[]
  }
  dependency_group?: string
  confounded_by?: string[]
  active_confounders?: string[]
  supports?: boolean
  support_reason?: string
}

export interface EvidenceGroup {
  family?: string
  evidence_class?: string
  evidence_ids?: string[]
  finding_ids?: string[]
  detectors?: string[]
  corroboration?: number
  max_severity?: Severity | string
  max_confidence?: number
  bases?: string[]
  supporting?: number
  context_only?: number
  confounded?: boolean
  active_confounders?: string[]
  assets?: string[]
  contributors?: string[]
}

export interface FiredRule {
  rule_id?: string
  scope?: string
  disposition?: string
  statement?: string
  rationale?: string
  evidence_ids?: string[]
  finding_ids?: string[]
  families?: string[]
  observation?: Record<string, unknown>
}

export interface UnassessedArea {
  area?: string
  kind?: string
  reason?: string
  remedy?: string
}

export interface LineageEntry {
  decision_id?: string
  rule_id?: string
  scope?: string
  disposition?: string
  finding_id?: string
  evidence_id?: string
  source_module?: number
  source_detector?: string
  source_report_id?: string
  detail?: string
}

export interface DecisionScope {
  scope?: string
  disposition?: string
  governing_rule?: string | null
  statement?: string
  assessed?: boolean
  fired_rules?: FiredRule[]
}

export interface AssuranceDecision {
  schema_version?: string
  decision_id?: string
  disposition?: string
  policy_version?: string
  summary?: string
  rationale?: string
  asset_scope?: Record<string, unknown>
  scopes?: DecisionScope[]
  fired_rules?: FiredRule[]
  supporting_evidence?: Record<string, unknown>[]
  contradicting_evidence?: Record<string, unknown>[]
  context_evidence?: Record<string, unknown>[]
  unassessed_areas?: UnassessedArea[]
  coverage_summary?: Record<string, unknown>
  confidence_summary?: Record<string, unknown>
  severity_summary?: Record<string, unknown>
  conflicts?: unknown[]
  lineage?: LineageEntry[]
  limitations?: string[]
  run_context?: Record<string, unknown>
}

export interface ScopeSummary {
  scope?: string
  disposition?: string
  governing_rule?: string | null
  statement?: string
  assessed?: boolean
  source_report_id?: string | null
  findings?: number
  supporting_evidence?: number
}

export interface CoverageEntry {
  attack_class?: string
  title?: string
  coverage?: Coverage | string
  owning_module?: number
  detector?: string | null
  detector_version?: string | null
  reason?: string
  assumptions?: string[]
  limitations?: string[]
}

export interface CoverageStatement {
  implemented_modules?: number[]
  entries?: CoverageEntry[]
}

export interface CapabilityEntry {
  capability?: string
  title?: string
  coverage?: Coverage | string
  owning_module?: number
  detail?: string
  reason?: string
  limitations?: string[]
}

export interface ShiftMetric {
  metric?: string
  version?: string
  status?: string
  statistic?: number | null
  p_value?: number | null
  significant?: boolean
  interpretation?: string
  requirement?: Record<string, unknown>
  observation?: Record<string, unknown>
  reason?: string | null
}

export interface ShiftAssessment {
  assessment_id?: string
  version?: string
  metric_version?: string
  verdict?: string
  statement?: string
  reference?: Record<string, unknown>
  current?: Record<string, unknown>
  metrics?: ShiftMetric[]
  context?: Record<string, unknown>
  declared_context?: Record<string, unknown>
  assumptions?: string[]
  limitations?: string[]
  unassessed?: unknown[]
}

/** Module 4's `PipelineAssuranceReport`. */
export interface AssuranceReport {
  schema_version?: string
  evidence_schema_version?: string
  report_id?: string
  generated_at?: string
  module?: string
  run?: Record<string, unknown>
  inputs?: {
    supplied?: Record<string, boolean>
    missing?: string[]
    note?: string
    [key: string]: unknown
  }
  configuration?: Record<string, unknown>
  policy?: {
    policy_version?: string
    combination?: string
    strictness_order?: string[]
    counting_unit?: string
    no_scoring?: string
    rules?: Record<string, unknown>[]
    [key: string]: unknown
  }
  dataset_assurance?: ScopeSummary | null
  model_assurance?: ScopeSummary | null
  provenance_assurance?: ScopeSummary | null
  distribution_assurance?: ScopeSummary | null
  distribution_shift?: ShiftAssessment | null
  evidence_summary?: Record<string, unknown>
  evidence?: {
    schema_version?: string
    evidence?: FusedEvidence[]
    groups?: EvidenceGroup[]
    active_phenomena?: string[]
    floors?: Record<string, unknown>
  }
  source_findings?: Finding[]
  decision?: AssuranceDecision
  coverage?: CoverageStatement
  capabilities?: { entries?: CapabilityEntry[] }
  limitations?: string[]
}

/** Module 1's dataset report. */
export interface DatasetReport {
  report_id?: string
  module?: string
  run?: Record<string, unknown>
  dataset?: {
    root?: string
    manifest_id?: string
    digest?: string
    adapter?: string
    task?: string
    counts?: Record<string, number>
    classes?: string[]
    contributors?: Record<string, Record<string, unknown>>
    attribution?: Record<string, unknown>
    throughput_samples_per_s?: number
  }
  feature_space?: Record<string, unknown>
  calibration?: Record<string, unknown>
  summary?: {
    overall?: string
    rationale?: string
    findings_total?: number
    by_severity?: Record<string, number>
    by_disposition?: Record<string, number>
    by_attack_class?: Record<string, number>
    assets_affected?: number
    contributors_affected?: number
  }
  findings?: Finding[]
  contributor_risk?: Record<string, unknown>[]
  detectors?: { name?: string; version?: string; findings?: number; stats?: Record<string, unknown> }[]
  coverage?: CoverageStatement
  limitations?: string[]
}

/** Module 2's model report. */
export interface ModelReport {
  report_id?: string
  module?: string
  model?: Record<string, unknown>
  reference?: Record<string, unknown> | null
  access?: {
    access_mode?: string
    capabilities?: string[]
    capabilities_absent?: string[]
    forced_black_box?: boolean
    adapter?: string
    adapter_version?: string
    runtime?: Record<string, unknown>
    consequences?: string[]
  }
  battery?: Record<string, unknown>
  benchmark?: Record<string, unknown>
  assessment?: Record<
    string,
    {
      level?: string
      status?: string
      detail?: string
      reason?: string | null
      detector?: string
      evidence_keys?: string[]
    }
  >
  summary?: Record<string, unknown>
  findings?: Finding[]
  detectors?: Record<string, unknown>[]
  coverage?: CoverageStatement
  limitations?: string[]
}

/** Module 3's provenance report. */
export interface ProvenanceReport {
  report_id?: string
  module?: string
  log?: Record<string, unknown>
  cryptographic?: Record<string, unknown>
  chain?: {
    status?: string
    log_id?: string
    entry_count?: number
    head_entry_digest?: string
    links?: ChainLink[]
    first_break_position?: number | null
    truncation_status?: string
    truncation_detail?: string
    anchor_supplied?: boolean
    mixed_log_ids?: string[]
    detail?: string
    guarantees?: Record<string, string>
  }
  matrix?: Record<string, unknown>
  records?: ProvenanceRecordRow[]
  verifications?: RecordVerification[]
  summary?: Record<string, unknown>
  findings?: Finding[]
  coverage?: CoverageStatement
  limitations?: string[]
}

export interface ChainLink {
  position?: number
  record_id?: string
  entry_digest?: string
  sequence_number?: number
  expected_previous_digest?: string | null
  declared_previous_digest?: string | null
  link_status?: string
  sequence_expected?: number
  sequence_valid?: boolean
  detail?: string
}

export interface ProvenanceRecordRow {
  position?: number
  record_id?: string
  entry_digest?: string
  sequence_number?: number
  timestamp?: string
  signing_key_id?: string
  key_status?: string
  failures?: string[]
  replay_verdict?: string
  input_digest?: string
  model_id?: string
  model_file_sha256?: string
  output_summary?: string
  valid?: boolean
  cryptographically_intact?: boolean
}

export interface VerificationCheck {
  name?: string
  outcome?: string
  detail?: string
  observation?: Record<string, unknown>
}

export interface RecordVerification {
  record_id?: string
  entry_digest?: string
  position?: number
  verified_at?: string
  checks?: VerificationCheck[]
  failures?: string[]
  signing_key_id?: string
  key_status?: string
  key_label?: string
  replay_verdict?: string
  validity_policy?: string
}

/** One row of the exported scenario catalogue (`index.json`). */
export interface ScenarioRow {
  name: string
  status: string
  featured?: boolean
  expected_disposition?: string
  observed_disposition?: string | null
  note?: string
  reason?: string | null
  files?: Record<string, string>
  summary?: {
    report_id?: string
    decision_id?: string
    policy_version?: string
    statement?: string
    scopes?: Record<string, { disposition?: string; assessed?: boolean; governing_rule?: string | null; statement?: string; findings?: number }>
    fired_rules?: string[]
    evidence_total?: number
    source_findings_total?: number
    confounded_evidence?: number
    independent_families?: string[]
    unassessed_areas?: number
    inputs_supplied?: Record<string, boolean>
    shift_verdict?: string | null
    expected_rules?: string[]
    lab_inputs?: Record<string, string | null>
  }
}

export interface ScenarioCatalogue {
  schema_version?: string
  generated_at?: string
  software_version?: string
  config_hash?: string
  source?: string
  kind?: string
  scenarios?: ScenarioRow[]
}

/** Which body of data the analyst is looking at. Never blended. */
export type SourceKind = "DEMO" | "LIVE"
