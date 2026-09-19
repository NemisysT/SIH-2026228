/** Where the raw report files live, for the JSON viewer and the export action. */
import type { SourceKind } from "./types.ts"

export function artifactHref(
  source: SourceKind,
  scenario: string,
  artifact: string,
  download = false,
): string {
  const base = `/api/analyst/report/${source.toLowerCase()}/${encodeURIComponent(scenario)}/${artifact}`
  return download ? `${base}?download=1` : base
}
