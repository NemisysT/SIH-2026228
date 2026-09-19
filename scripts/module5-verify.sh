#!/usr/bin/env bash
# End-to-end verification for Module 5 (brief §33).
#
#   RUN A REAL ASSURANCE SCENARIO
#     -> MODULE 1 -> MODULE 2 -> MODULE 3 -> MODULE 4
#     -> MODULE 5
#     -> ANALYST SEES THE CORRECT RESULT
#
# The last step is the one that matters and the one that is easy to fake: this
# script serves the built application, fetches every page for every scenario,
# and asserts that what the page says matches what the engine's JSON says. A
# frontend-only interpretation that contradicted the backend would fail here.
#
# Everything runs against localhost. No network access is required or made.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-3131}"
PYTHON="${PYTHON:-./.venv/bin/python}"
SKIP_EXPORT="${SKIP_EXPORT:-0}"

echo "==> Module 1-4: exporting the analyst feed from the real pipelines"
if [ "$SKIP_EXPORT" = "1" ]; then
  echo "    (skipped: SKIP_EXPORT=1, reusing reports/analyst)"
else
  "$PYTHON" -m cvtrust analyst export --out reports/analyst
fi

echo "==> Module 5: backend boundary tests"
"$PYTHON" -m pytest tests/integration/test_analyst_export.py -q

echo "==> Module 5: frontend projection tests"
( cd web && npm test --silent )

echo "==> Module 5: type check and production build"
( cd web && npx --no-install tsc --noEmit && NEXT_TELEMETRY_DISABLED=1 npx --no-install next build )

echo "==> Module 5: serving the application on :$PORT"
# A server left behind by an earlier run would serve a stale build and make
# this check pass or fail against code that is no longer on disk.
if lsof -ti tcp:"$PORT" >/dev/null 2>&1; then
  echo "    a process already holds :$PORT — stopping it first"
  lsof -ti tcp:"$PORT" | xargs kill 2>/dev/null || true
  sleep 2
fi
( cd web && NEXT_TELEMETRY_DISABLED=1 npx --no-install next start -p "$PORT" >/tmp/cvtrust-module5.log 2>&1 ) &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 40); do
  if curl -fsS "http://localhost:$PORT/api/analyst/status" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> Analyst view: every page, every scenario, checked against the report"
BASE_URL="http://localhost:$PORT" "$PYTHON" scripts/module5_check.py

echo
echo "MODULE 5 END-TO-END VERIFICATION PASSED"
