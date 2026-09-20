import { NextResponse } from "next/server"

/**
 * Liveness, and nothing more.
 *
 * Deliberately does no disk I/O and reports nothing about the feed: a platform
 * health check answers "is this process able to serve requests", and an absent
 * or empty report directory is a state the UI renders rather than a reason to
 * restart a healthy server. Whether either source has data is
 * `/api/analyst/status`, which is the question an operator asks.
 */
export const dynamic = "force-dynamic"

export async function GET() {
  return NextResponse.json(
    { status: "ok", service: "sih26228-analyst-platform" },
    { headers: { "cache-control": "no-store" } },
  )
}
