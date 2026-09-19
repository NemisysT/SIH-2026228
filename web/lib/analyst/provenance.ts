/**
 * Projections over Module 3's provenance report.
 *
 * Two semantics from the module matter enough to be enforced here rather than
 * left to each page:
 *
 * 1. §10 — a failure must show *which* check failed, on which artifact, with
 *    the verifier's own observation. `verificationSteps` keeps every check,
 *    including the ones that passed and the ones that did not apply.
 * 2. §16 — a chain break localises to the successor link. `chainView` marks
 *    exactly one break position and does NOT mark later records invalid,
 *    because the verifier does not establish that.
 */

import { checkState, text, type CheckState } from "./format.ts"
import type {
  ChainLink,
  ProvenanceRecordRow,
  ProvenanceReport,
  RecordVerification,
  VerificationCheck,
} from "./types.ts"

/**
 * The verification stages the brief asks to be shown as a pipeline, mapped to
 * the verifier's own check names. Each stage is PASS only if every check in it
 * passed, FAIL if any failed, and NEUTRAL if none of them ran.
 */
export const VERIFICATION_STAGES: { id: string; label: string; checks: string[] }[] = [
  { id: "input", label: "Input digest", checks: ["input_digest_match", "normalized_input_digest_match"] },
  { id: "preprocessing", label: "Preprocessing digest", checks: ["preprocessing_digest_match", "preprocessing_digest_self_consistent"] },
  { id: "model", label: "Model digest", checks: ["model_digest_match", "model_id_match", "model_graph_digest_match", "model_parameter_digest_match"] },
  { id: "config", label: "Inference configuration", checks: ["inference_config_digest_match", "inference_config_digest_self_consistent"] },
  { id: "output", label: "Output digest", checks: ["output_digest_match", "output_digest_self_consistent"] },
  { id: "signature", label: "Signature", checks: ["signature_valid", "record_id_matches_content"] },
  { id: "key", label: "Trusted key", checks: ["key_known", "key_trusted", "key_purpose_permitted", "key_within_validity_window"] },
  { id: "chain", label: "Chain", checks: ["previous_record_valid", "sequence_valid", "log_id_match"] },
  { id: "replay", label: "Replay check", checks: ["replay_detected", "nonce_present"] },
]

export interface StageView {
  id: string
  label: string
  state: CheckState
  /** Every check that contributed, with the verifier's own detail text. */
  checks: VerificationCheck[]
  /** Checks that were not present in the verification at all. */
  absent: string[]
}

export function stageViews(verification: RecordVerification | null): StageView[] {
  const byName = new Map<string, VerificationCheck>()
  for (const check of verification?.checks ?? []) {
    if (check.name) byName.set(check.name, check)
  }
  return VERIFICATION_STAGES.map((stage) => {
    const checks: VerificationCheck[] = []
    const absent: string[] = []
    for (const name of stage.checks) {
      const check = byName.get(name)
      if (check) checks.push(check)
      else absent.push(name)
    }
    const states = checks.map((check) => checkState(check.outcome))
    const state: CheckState = states.includes("FAIL")
      ? "FAIL"
      : states.includes("PASS")
        ? "PASS"
        : "NEUTRAL"
    return { id: stage.id, label: stage.label, state, checks, absent }
  })
}

export interface ChainEntryView {
  position: number
  recordId: string
  entryDigest: string
  declaredPrevious: string | null
  expectedPrevious: string | null
  sequenceNumber: number | null
  sequenceExpected: number | null
  sequenceValid: boolean
  linkStatus: string
  detail: string
  state: CheckState
  /** True on the one link the verifier localises the break to. */
  isBreak: boolean
  /** True for links after the break: unverified from here, not proven invalid. */
  afterBreak: boolean
  record: ProvenanceRecordRow | null
  verification: RecordVerification | null
}

export interface ChainView {
  status: string
  logId: string
  entryCount: number
  headDigest: string
  firstBreakPosition: number | null
  truncationStatus: string
  truncationDetail: string
  anchorSupplied: boolean
  mixedLogIds: string[]
  detail: string
  guarantees: Record<string, string>
  entries: ChainEntryView[]
}

/**
 * The chain as an ordered list of links, with exactly one break localised.
 *
 * `afterBreak` exists so the UI can grey later links as *unverified beyond this
 * point* rather than paint them red. Module 3 does not conclude that a record
 * after a break is forged, and neither may the screen.
 */
export function chainView(report: ProvenanceReport | null): ChainView {
  const chain = report?.chain ?? {}
  const links: ChainLink[] = chain.links ?? []
  const recordsByPosition = new Map<number, ProvenanceRecordRow>()
  for (const record of report?.records ?? []) {
    if (typeof record.position === "number") recordsByPosition.set(record.position, record)
  }
  const verificationsByPosition = new Map<number, RecordVerification>()
  for (const verification of report?.verifications ?? []) {
    if (typeof verification.position === "number") {
      verificationsByPosition.set(verification.position, verification)
    }
  }
  const breakAt =
    typeof chain.first_break_position === "number" ? chain.first_break_position : null

  return {
    status: text(chain.status, "NOT_ASSESSED"),
    logId: text(chain.log_id),
    entryCount: chain.entry_count ?? links.length,
    headDigest: text(chain.head_entry_digest),
    firstBreakPosition: breakAt,
    truncationStatus: text(chain.truncation_status, "NOT_ASSESSED"),
    truncationDetail: text(chain.truncation_detail, ""),
    anchorSupplied: chain.anchor_supplied === true,
    mixedLogIds: chain.mixed_log_ids ?? [],
    detail: text(chain.detail, ""),
    guarantees: chain.guarantees ?? {},
    entries: links.map((link) => {
      const position = link.position ?? 0
      return {
        position,
        recordId: text(link.record_id),
        entryDigest: text(link.entry_digest),
        declaredPrevious: link.declared_previous_digest ?? null,
        expectedPrevious: link.expected_previous_digest ?? null,
        sequenceNumber: link.sequence_number ?? null,
        sequenceExpected: link.sequence_expected ?? null,
        sequenceValid: link.sequence_valid !== false,
        linkStatus: text(link.link_status, "NOT_ASSESSED"),
        detail: text(link.detail, ""),
        state: checkState(link.link_status),
        isBreak: breakAt !== null && position === breakAt,
        afterBreak: breakAt !== null && position > breakAt,
        record: recordsByPosition.get(position) ?? null,
        verification: verificationsByPosition.get(position) ?? null,
      }
    }),
  }
}

export interface RecordView {
  position: number
  recordId: string
  entryDigest: string
  sequenceNumber: number | null
  timestamp: string
  signingKeyId: string
  keyStatus: string
  failures: string[]
  replayVerdict: string
  inputDigest: string
  modelId: string
  modelSha256: string
  outputSummary: string
  valid: boolean
  cryptographicallyIntact: boolean
  verification: RecordVerification | null
  stages: StageView[]
}

export function recordViews(report: ProvenanceReport | null): RecordView[] {
  const verificationsByPosition = new Map<number, RecordVerification>()
  for (const verification of report?.verifications ?? []) {
    if (typeof verification.position === "number") {
      verificationsByPosition.set(verification.position, verification)
    }
  }
  return (report?.records ?? []).map((record) => {
    const position = record.position ?? 0
    const verification = verificationsByPosition.get(position) ?? null
    return {
      position,
      recordId: text(record.record_id),
      entryDigest: text(record.entry_digest),
      sequenceNumber: record.sequence_number ?? null,
      timestamp: text(record.timestamp),
      signingKeyId: text(record.signing_key_id),
      keyStatus: text(record.key_status, "NOT_ASSESSED"),
      failures: (record.failures ?? []).filter((failure) => failure !== "VALID"),
      replayVerdict: text(record.replay_verdict, "NOT_ASSESSED"),
      inputDigest: text(record.input_digest),
      modelId: text(record.model_id),
      modelSha256: text(record.model_file_sha256),
      outputSummary: text(record.output_summary),
      valid: record.valid === true,
      cryptographicallyIntact: record.cryptographically_intact === true,
      verification,
      stages: stageViews(verification),
    }
  })
}

/** The first record that failed, which is what an analyst opens first. */
export function firstFailure(report: ProvenanceReport | null): RecordView | null {
  return recordViews(report).find((record) => !record.valid) ?? null
}

export interface ProvenanceSummaryView {
  overall: string
  rationale: string
  recordsTotal: number
  recordsValid: number
  recordsIntact: number
  recordsFailed: number
  malformedLines: number
  chainStatus: string
  truncationStatus: string
  replayDetected: number
  byFailureCode: Record<string, number>
  trustStoreSupplied: boolean
  trustedKeyCount: number | null
  revokedKeyCount: number | null
  anchorSupplied: boolean
  replayDatabaseSupplied: boolean
  signatureAlgorithm: string
  hashAlgorithm: string
  validityPolicy: string
}

export function provenanceSummary(report: ProvenanceReport | null): ProvenanceSummaryView {
  const summary = (report?.summary ?? {}) as Record<string, unknown>
  const crypto = (report?.cryptographic ?? {}) as Record<string, unknown>
  const int = (value: unknown, fallback = 0) => (typeof value === "number" ? value : fallback)
  const num = (value: unknown) => (typeof value === "number" ? value : null)
  return {
    overall: text(summary.overall, "NOT ASSESSED"),
    rationale: text(summary.rationale, ""),
    recordsTotal: int(summary.records_total),
    recordsValid: int(summary.records_valid),
    recordsIntact: int(summary.records_cryptographically_intact),
    recordsFailed: int(summary.records_failed),
    malformedLines: int(summary.malformed_lines),
    chainStatus: text(summary.chain_status, "NOT_ASSESSED"),
    truncationStatus: text(summary.truncation_status, "NOT_ASSESSED"),
    replayDetected: int(summary.replay_detected),
    byFailureCode:
      summary.by_failure_code && typeof summary.by_failure_code === "object"
        ? (summary.by_failure_code as Record<string, number>)
        : {},
    trustStoreSupplied: crypto.trust_store_supplied === true,
    trustedKeyCount: num(crypto.trusted_key_count),
    revokedKeyCount: num(crypto.revoked_key_count),
    anchorSupplied: crypto.anchor_supplied === true,
    replayDatabaseSupplied: crypto.replay_database_supplied === true,
    signatureAlgorithm: text(crypto.signature_algorithm),
    hashAlgorithm: text(crypto.hash_algorithm),
    validityPolicy: text(crypto.validity_policy),
  }
}
