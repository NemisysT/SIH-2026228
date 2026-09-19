import { NextResponse } from "next/server"

import { sourceStatus } from "@/lib/analyst/source"

/** Which sources have data, for the demo page and for a smoke test. */
export async function GET() {
  const [demo, live] = await Promise.all([sourceStatus("DEMO"), sourceStatus("LIVE")])
  return NextResponse.json({ demo, live }, { headers: { "cache-control": "no-store" } })
}
