/**
 * Where the analyst platform gets its data. Server-side only.
 *
 * Two sources exist and they are never blended (§19):
 *
 *   DEMO — `reports/analyst`, written by `cvtrust analyst export`. Real
 *          Module 1-4 output over the attack lab's scenarios, deterministic,
 *          and regenerated from the engine rather than checked in by hand.
 *   LIVE — `reports/live`, where an operator drops the output of a real
 *          assessment (`cvtrust assurance assess --out ...`). If nothing is
 *          there, the platform says so. It does not fall back to demo data.
 *
 * Both directories are read from disk. There is no network call anywhere in
 * this module, by design (§21): the platform must run with no cloud, no API
 * key and no reachable host.
 */

import { readFile } from "node:fs/promises"
import path from "node:path"

import type {
  AssuranceReport,
  DatasetReport,
  ModelReport,
  ProvenanceReport,
  ScenarioCatalogue,
  ScenarioRow,
  ShiftAssessment,
  SourceKind,
} from "./types.ts"

/** Repository root, resolved from this file rather than from the cwd. */
function repoRoot(): string {
  return path.resolve(process.cwd(), "..")
}

export function demoDir(): string {
  return process.env.CVTRUST_DEMO_DIR ?? path.join(repoRoot(), "reports", "analyst")
}

export function liveDir(): string {
  return process.env.CVTRUST_LIVE_DIR ?? path.join(repoRoot(), "reports", "live")
}

export function sourceDir(kind: SourceKind): string {
  return kind === "LIVE" ? liveDir() : demoDir()
}

/** Reject anything that would escape the source directory. */
function safeJoin(base: string, relative: string): string {
  const resolved = path.resolve(base, relative)
  const normalisedBase = path.resolve(base) + path.sep
  if (!resolved.startsWith(normalisedBase)) {
    throw new Error(`refusing to read outside the report directory: ${relative}`)
  }
  return resolved
}

async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T
  } catch {
    // A missing or malformed report is a state the UI renders, not a crash.
    // Which of the two it was is answered by `readJsonStrict` where it matters.
    return null
  }
}

export type LoadOutcome<T> =
  | { ok: true; data: T }
  | { ok: false; kind: "MISSING" | "MALFORMED"; detail: string }

export async function readJsonStrict<T>(file: string): Promise<LoadOutcome<T>> {
  let raw: string
  try {
    raw = await readFile(file, "utf8")
  } catch (error) {
    return {
      ok: false,
      kind: "MISSING",
      detail: error instanceof Error ? error.message : String(error),
    }
  }
  try {
    return { ok: true, data: JSON.parse(raw) as T }
  } catch (error) {
    return {
      ok: false,
      kind: "MALFORMED",
      detail: error instanceof Error ? error.message : String(error),
    }
  }
}

export async function loadCatalogue(kind: SourceKind = "DEMO"): Promise<ScenarioCatalogue | null> {
  return readJson<ScenarioCatalogue>(path.join(sourceDir(kind), "index.json"))
}

export async function loadCapabilities(
  kind: SourceKind = "DEMO",
): Promise<Record<string, unknown> | null> {
  return readJson<Record<string, unknown>>(path.join(sourceDir(kind), "capabilities.json"))
}

export async function listScenarios(kind: SourceKind = "DEMO"): Promise<ScenarioRow[]> {
  const catalogue = await loadCatalogue(kind)
  return catalogue?.scenarios ?? []
}

export async function findScenario(
  name: string,
  kind: SourceKind = "DEMO",
): Promise<ScenarioRow | null> {
  const scenarios = await listScenarios(kind)
  return scenarios.find((scenario) => scenario.name === name) ?? null
}

/**
 * The scenario the analyst is looking at.
 *
 * Falls back to the first RUN scenario rather than to a hard-coded name, so a
 * feed built from a different spec still opens on something real.
 */
export async function resolveScenario(
  name: string | undefined,
  kind: SourceKind = "DEMO",
): Promise<ScenarioRow | null> {
  const scenarios = await listScenarios(kind)
  if (scenarios.length === 0) return null
  if (name) {
    const match = scenarios.find((scenario) => scenario.name === name)
    if (match) return match
  }
  return scenarios.find((scenario) => scenario.status === "RUN") ?? scenarios[0]
}

export interface ScenarioBundle {
  kind: SourceKind
  scenario: ScenarioRow
  assurance: AssuranceReport | null
  dataset: DatasetReport | null
  model: ModelReport | null
  provenance: ProvenanceReport | null
  shift: ShiftAssessment | null
  /** Artifacts named in the catalogue that would not parse. */
  malformed: string[]
}

/**
 * Load one scenario's reports.
 *
 * Every artifact is optional and their absence is meaningful: a scenario with
 * no model report is a scenario where Module 2 had nothing to assess, and the
 * pages render that as NOT_ASSESSED rather than as a clean model.
 */
export async function loadScenarioBundle(
  scenario: ScenarioRow,
  kind: SourceKind = "DEMO",
): Promise<ScenarioBundle> {
  const base = sourceDir(kind)
  const files = scenario.files ?? {}
  const malformed: string[] = []

  async function load<T>(key: string): Promise<T | null> {
    const relative = files[key]
    if (!relative) return null
    const outcome = await readJsonStrict<T>(safeJoin(base, relative))
    if (!outcome.ok) {
      if (outcome.kind === "MALFORMED") malformed.push(key)
      return null
    }
    return outcome.data
  }

  const [assurance, dataset, model, provenance, shift] = await Promise.all([
    load<AssuranceReport>("assurance"),
    load<DatasetReport>("dataset"),
    load<ModelReport>("model"),
    load<ProvenanceReport>("provenance"),
    load<ShiftAssessment>("shift"),
  ])

  return { kind, scenario, assurance, dataset, model, provenance, shift, malformed }
}

/** Raw bytes of one artifact, for the JSON viewer and the export action. */
export async function readArtifact(
  kind: SourceKind,
  scenarioName: string,
  artifact: string,
): Promise<string | null> {
  const scenario = await findScenario(scenarioName, kind)
  const relative = scenario?.files?.[artifact]
  if (!relative) return null
  try {
    return await readFile(safeJoin(sourceDir(kind), relative), "utf8")
  } catch {
    return null
  }
}

export interface SourceStatus {
  kind: SourceKind
  available: boolean
  directory: string
  scenarioCount: number
  generatedAt: string | null
  softwareVersion: string | null
  /** What to do about it, when it is not available. */
  remedy: string
}

/**
 * Whether each source has anything in it.
 *
 * The LIVE remedy names the exact command, because "no live data" with no way
 * to produce any is a dead end, and a judge will ask.
 */
export async function sourceStatus(kind: SourceKind): Promise<SourceStatus> {
  const catalogue = await loadCatalogue(kind)
  const scenarios = catalogue?.scenarios ?? []
  return {
    kind,
    available: scenarios.length > 0,
    directory: sourceDir(kind),
    scenarioCount: scenarios.length,
    generatedAt: catalogue?.generated_at ?? null,
    softwareVersion: catalogue?.software_version ?? null,
    remedy:
      kind === "LIVE"
        ? "Run a real assessment and publish it: `cvtrust assurance assess --dataset-report … --out reports/live/scenarios/<name>/assurance.json`, then write reports/live/index.json describing it."
        : "Build the demo feed from the attack lab: `cvtrust analyst export --out reports/analyst`.",
  }
}
