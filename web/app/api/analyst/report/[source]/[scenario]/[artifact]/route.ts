import { NextResponse } from "next/server"

import { readArtifact } from "@/lib/analyst/source"
import type { SourceKind } from "@/lib/analyst/types"

/**
 * Serve one report file, byte for byte.
 *
 * This is the report-export surface (§30). It deliberately streams the file
 * the engine wrote rather than anything the frontend assembled: an analyst who
 * doubts a screen can download the JSON behind it and check. `?download=1`
 * attaches a filename; without it the browser renders the JSON inline.
 */
export async function GET(
  request: Request,
  context: { params: Promise<{ source: string; scenario: string; artifact: string }> },
) {
  const { source, scenario, artifact } = await context.params
  const kind: SourceKind = source.toLowerCase() === "live" ? "LIVE" : "DEMO"

  const body = await readArtifact(kind, scenario, artifact)
  if (body === null) {
    return NextResponse.json(
      {
        error: "NOT_FOUND",
        detail: `No '${artifact}' report exists for scenario '${scenario}' in the ${kind} source. A module that was not supplied to the run produces no report, which is itself the answer.`,
      },
      { status: 404 },
    )
  }

  const download = new URL(request.url).searchParams.get("download") === "1"
  return new NextResponse(body, {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...(download
        ? {
            "content-disposition": `attachment; filename="${kind.toLowerCase()}-${scenario}-${artifact}.json"`,
          }
        : {}),
    },
  })
}
