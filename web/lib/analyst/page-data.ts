/**
 * What every page needs before it can render anything: which source, which
 * scenario, and the reports behind it. Server-side only.
 */

import { titleise } from "./format.ts"
import {
  listScenarios,
  loadScenarioBundle,
  resolveScenario,
  sourceStatus,
  type ScenarioBundle,
  type SourceStatus,
} from "./source.ts"
import type { ScenarioRow, SourceKind } from "./types.ts"

export interface SwitcherOption {
  name: string
  label: string
  disposition: string
  status: string
}

export interface PageData {
  source: SourceKind
  status: SourceStatus
  /** Null when the chosen source has nothing in it at all. */
  bundle: ScenarioBundle | null
  scenario: ScenarioRow | null
  options: SwitcherOption[]
  /** The other source's status, so the UI can offer the switch honestly. */
  other: SourceStatus
}

export type SearchParams = Record<string, string | string[] | undefined>

function first(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value
}

export function readSource(params: SearchParams): SourceKind {
  return first(params.source)?.toLowerCase() === "live" ? "LIVE" : "DEMO"
}

export function scenarioLabel(name: string): string {
  return titleise(name)
}

/**
 * Resolve the page's data from the query string.
 *
 * If the requested source is empty the page is *not* silently redirected to
 * the other one — it renders the empty state for the source that was asked
 * for. Falling back would mean an analyst who asked for live data could be
 * shown demo data without noticing, which §19 forbids.
 */
export async function loadPageData(params: SearchParams): Promise<PageData> {
  const source = readSource(params)
  const [status, other] = await Promise.all([
    sourceStatus(source),
    sourceStatus(source === "DEMO" ? "LIVE" : "DEMO"),
  ])

  const scenarios = await listScenarios(source)
  const options: SwitcherOption[] = scenarios.map((scenario) => ({
    name: scenario.name,
    label: scenarioLabel(scenario.name),
    disposition: scenario.observed_disposition ?? "NOT_ASSESSED",
    status: scenario.status,
  }))

  const scenario = await resolveScenario(first(params.scenario), source)
  const bundle = scenario ? await loadScenarioBundle(scenario, source) : null

  return { source, status, bundle, scenario, options, other }
}

/** The query suffix that carries the current selection between pages. */
export function linkSuffix(source: SourceKind, scenario: string | undefined): string {
  const query = new URLSearchParams()
  if (scenario) query.set("scenario", scenario)
  if (source === "LIVE") query.set("source", "live")
  const rendered = query.toString()
  return rendered ? `?${rendered}` : ""
}
