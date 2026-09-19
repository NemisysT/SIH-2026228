#!/usr/bin/env bash
#
# The single command that boots the complete SIH26228 demo.
#
#   ./setup.sh     once, on a connected machine  (dependencies)
#   ./run.sh       every time after that         (the demo)
#
# What the demo actually consists of:
#
#   Modules 1-4  the cvtrust engine — a Python library and CLI, not a service.
#                It RUNS ONCE to produce the analyst feed (reports/analyst) and
#                then has nothing left to do. There is no API process, no
#                database and no worker: the engine's output is JSON on disk.
#   Module 5     the analyst platform in web/ — a Next.js server that reads
#                that JSON from the filesystem. It makes no network call of any
#                kind, by design (the system is air-gapped).
#
# So exactly one long-lived process is started here, and it is started last,
# after the data it reads has been verified to exist.
#
# What is deliberately NOT started:
#
#   api/server.py  a FastAPI face on the pipeline from an earlier iteration of
#                  the frontend. Nothing in web/ calls it (the application
#                  makes no network request at all — see
#                  tests/security/test_module5_offline.py), and fastapi and
#                  uvicorn are not in requirements.txt, so ./setup.sh does not
#                  install them. Starting it would add a process the demo does
#                  not use. Run it by hand if you want the HTTP API:
#                  ./.venv/bin/uvicorn api.server:app --port 8000
#   reports/live   the live source is a directory an operator fills with a real
#                  assessment. Empty is a correct, intended state that the
#                  platform renders in words; it is never auto-populated,
#                  because live data must never be demo data.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------- settings --

PORT="${PORT:-3000}"
MODE="start"                 # start | dev
FORCE_FEED=0
FORCE_BUILD=0
PREPARE_ONLY=0
OPEN_BROWSER=0
ALLOW_PARTIAL_FEED="${ALLOW_PARTIAL_FEED:-0}"

PYBIN="$ROOT/.venv/bin/python"
CVTRUST="$ROOT/.venv/bin/cvtrust"
FEED_DIR="$ROOT/reports/analyst"
LIVE_DIR="$ROOT/reports/live"
RUNDIR="$ROOT/.run"
WEB_LOG="$RUNDIR/web.log"
BUILD_LOG="$RUNDIR/build.log"
EXPORT_LOG="$RUNDIR/export.log"
PIDFILE="$RUNDIR/web.pid"
LOCKDIR="$RUNDIR/prepare.lock"

usage() {
    cat <<'USAGE'
Usage: ./run.sh [options]

  --dev              run the frontend in development mode (hot reload) instead
                     of serving the production build
  --rebuild          rebuild the frontend even if a current build exists
  --refresh-feed     re-run the Module 1-4 engine and rewrite reports/analyst
  --prepare-only     build everything the demo needs, then exit without serving
  --open             open the demo in the default browser once it is ready
  --port N           serve on port N (default 3000, or $PORT)
  -h, --help         this message

Environment:
  PORT                 port for the analyst platform            (default 3000)
  CVTRUST_DEMO_DIR     override the demo feed directory   (default reports/analyst)
  CVTRUST_LIVE_DIR     override the live feed directory   (default reports/live)
  ALLOW_PARTIAL_FEED=1 continue even if some scenarios could not be exported

No credentials, API keys or secrets are required. The demo is air-gapped: it
makes no network call at run time.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dev)          MODE="dev" ;;
        --rebuild)      FORCE_BUILD=1 ;;
        --refresh-feed) FORCE_FEED=1 ;;
        --prepare-only) PREPARE_ONLY=1 ;;
        --open)         OPEN_BROWSER=1 ;;
        --port)         shift; PORT="${1:-}" ;;
        --port=*)       PORT="${1#*=}" ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "run.sh: unknown option: $1" >&2; echo >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$PORT" in
    ''|*[!0-9]*) echo "run.sh: --port must be a number, got '$PORT'" >&2; exit 2 ;;
esac

# ------------------------------------------------------------------ output --

if [ -t 1 ]; then
    B=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    RED=$'\033[31m'; BLUE=$'\033[34m'; R=$'\033[0m'
else
    B=""; DIM=""; GREEN=""; YELLOW=""; RED=""; BLUE=""; R=""
fi

step() { printf '\n%s==> %s%s\n' "$B" "$1" "$R"; }
ok()   { printf '%s   ok%s  %s\n' "$GREEN" "$R" "$1"; }
note() { printf '%s      %s%s\n' "$DIM" "$1" "$R"; }
warn() { printf '%s   !!%s  %s\n' "$YELLOW" "$R" "$1" >&2; }
die()  {
    printf '\n%s   xx  %s%s\n' "$RED" "$1" "$R" >&2
    shift
    while [ $# -gt 0 ]; do printf '       %s\n' "$1" >&2; shift; done
    exit 1
}

tail_log() {
    # Last lines of a log, indented, so a failure explains itself in place.
    [ -f "$1" ] || return 0
    printf '%s--- %s (last %s lines) ---%s\n' "$DIM" "$1" "$2" "$R" >&2
    tail -n "$2" "$1" | sed 's/^/       /' >&2
    printf '%s--------------------------------%s\n' "$DIM" "$R" >&2
}

# ------------------------------------------------------- small py utilities --
# The virtualenv's python is a hard prerequisite of the demo anyway, so it is
# used for the probes rather than adding a dependency on curl/lsof/nc.

port_busy() {
    "$PYBIN" - "$1" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
sys.exit(0)
PY
}

http_get() {
    # Prints the body on success (HTTP 200), exits non-zero otherwise.
    "$PYBIN" - "$1" <<'PY'
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
        if response.status != 200:
            sys.exit(1)
        sys.stdout.write(response.read(8192).decode("utf-8", "replace"))
except Exception:
    sys.exit(1)
PY
}

# ------------------------------------------------------------------- lock --
#
# Two launchers bootstrapping at once is not hypothetical: `cvtrust analyst
# export` clears its output directory before rewriting it, so a second export
# running concurrently deletes the first one's work halfway through and leaves
# a feed that is neither complete nor honestly marked NOT_RUN. One preparer at
# a time.

LOCK_HELD=0

acquire_lock() {
    mkdir -p "$RUNDIR"
    if mkdir "$LOCKDIR" 2>/dev/null; then
        echo "$$" > "$LOCKDIR/pid"
        LOCK_HELD=1
        return 0
    fi
    local holder
    holder="$(cat "$LOCKDIR/pid" 2>/dev/null || true)"
    if [ -n "$holder" ] && kill -0 "$holder" 2>/dev/null; then
        die "another ./run.sh (pid $holder) is preparing the demo artifacts" \
            "Wait for it to finish, then run ./run.sh again." \
            "If that process is gone, remove the lock: rm -rf $LOCKDIR"
    fi
    warn "removing a stale preparation lock left by pid ${holder:-unknown}"
    rm -rf "$LOCKDIR"
    mkdir "$LOCKDIR" || die "could not take the preparation lock at $LOCKDIR"
    echo "$$" > "$LOCKDIR/pid"
    LOCK_HELD=1
}

release_lock() {
    [ "$LOCK_HELD" = "1" ] || return 0
    rm -rf "$LOCKDIR"
    LOCK_HELD=0
}

# --------------------------------------------------------------- preflight --

preflight() {
    step "Preflight: checking that ./setup.sh has been run"

    [ -x "$PYBIN" ] || die "the Python environment is missing (.venv)" \
        "Run ./setup.sh first — it creates .venv and installs the engine."
    "$PYBIN" -c 'import cvtrust' >/dev/null 2>&1 || die \
        "the cvtrust engine is not installed in .venv" \
        "Run ./setup.sh first (it does: pip install -r requirements.txt -e .)."
    [ -x "$CVTRUST" ] || die "the cvtrust CLI is missing from .venv/bin" \
        "Run ./setup.sh first."
    ok "engine: $("$CVTRUST" version 2>/dev/null | head -1)"

    command -v node >/dev/null 2>&1 || die "node is not installed" \
        "The analyst platform is a Next.js application and needs Node 20.9+." \
        "Install Node, then run ./setup.sh."
    local major
    major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    if [ "$major" -lt 20 ]; then
        die "node $(node -v) is too old" "Next.js 16 needs Node 20.9 or newer."
    fi
    ok "node: $(node -v)"

    [ -x "$ROOT/web/node_modules/.bin/next" ] || die \
        "the frontend's dependencies are missing (web/node_modules)" \
        "Run ./setup.sh first — it runs 'npm install' in web/." \
        "On an air-gapped machine, carry web/node_modules across with the" \
        "repository; see docs/deployment.md § Module 5."
    ok "frontend dependencies present"

    # There are no secrets to check for. Say so explicitly, because "which
    # credentials do I need?" is the first question a new operator asks.
    ok "no credentials or API keys required (the demo is offline)"
    [ -n "${CVTRUST_DEMO_DIR:-}" ] && note "CVTRUST_DEMO_DIR is set: $CVTRUST_DEMO_DIR"
    [ -n "${CVTRUST_LIVE_DIR:-}" ] && note "CVTRUST_LIVE_DIR is set: $CVTRUST_LIVE_DIR"
    return 0
}

# ------------------------------------------- Modules 1-4: the attack labs ----
#
# These are generated, not committed (.gitignore: they are reproducible from
# published seeds, and model_lab/provenance_lab hold weights and key material).
# A fresh clone therefore has none of them, and the feed cannot be built without
# them — so building them is a genuine first-run requirement, not setup work
# that snuck into the runtime path. It happens once; later runs skip it.

missing_dirs() {
    local base="$1"; shift
    local missing=""
    local name
    for name in "$@"; do
        [ -d "$base/$name" ] || missing="$missing $name"
    done
    printf '%s' "$missing"
}

ensure_labs() {
    step "Modules 1-4: attack laboratories"

    local missing

    # Module 1 — dataset attack lab.
    if [ ! -d "$ROOT/attack_lab/_clean" ]; then
        note "generating the clean baseline corpus (attack_lab/_clean)"
        "$CVTRUST" -q lab generate --out attack_lab/_clean --per-class 14 --coco --yolo \
            || die "could not generate the clean corpus"
    fi
    missing="$(missing_dirs "$ROOT/attack_lab" combined duplicate_flood label_flip ood_insertion)"
    if [ -n "$missing" ]; then
        local scenario
        for scenario in $missing; do
            note "building dataset scenario: $scenario"
            "$CVTRUST" -q lab attack "attack_lab/_clean/dataset" "attack_lab/$scenario" \
                --scenario "$scenario" || die "could not build dataset scenario '$scenario'"
        done
    fi
    ok "Module 1 dataset lab ready (attack_lab)"

    # Module 2 — model attack lab. The slow one: it trains a reference network
    # and fifteen scenarios (~1 min). Needs the onnx/torch extras from
    # requirements.txt.
    missing="$(missing_dirs "$ROOT/model_lab" _reference backdoor_badnets clean_finetuned \
                            clean_unusual_init reserialised substitution_architecture)"
    if [ -n "$missing" ]; then
        note "training the model lab — first run only, about a minute"
        "$CVTRUST" -q lab model-build --out model_lab || die \
            "could not build the model lab" \
            "Module 2 needs the onnx and torch extras: check ./.venv/bin/cvtrust info," \
            "and re-run ./setup.sh if the model runtimes are unavailable."
    fi
    ok "Module 2 model lab ready (model_lab)"

    # Module 3 — provenance attack lab.
    missing="$(missing_dirs "$ROOT/provenance_lab" clean legitimate_reprocess modified_output)"
    if [ -n "$missing" ]; then
        note "building the provenance lab (28 scenarios)"
        "$CVTRUST" -q lab provenance-build --out provenance_lab || die \
            "could not build the provenance lab"
    fi
    ok "Module 3 provenance lab ready (provenance_lab)"

    # Module 4 — the population lab IS committed (the feed is built from it);
    # only rebuild it if it is genuinely absent.
    if [ ! -f "$ROOT/assurance_lab/lab_spec.json" ]; then
        note "building the population lab (1 reference corpus + 10 pairs)"
        "$CVTRUST" -q lab assurance-build --out assurance_lab --per-class 8 || die \
            "could not build the population lab"
    fi
    ok "Module 4 population lab ready (assurance_lab)"
}

# ------------------------------------------ Modules 1-4: the analyst feed ----

feed_summary() {
    "$PYBIN" - "$1" <<'PY'
import json, sys
from pathlib import Path
index = Path(sys.argv[1]) / "index.json"
try:
    catalogue = json.loads(index.read_text())
except FileNotFoundError:
    print("MISSING")
    sys.exit(0)
except Exception as error:                                # malformed
    print("MALFORMED %s" % error)
    sys.exit(0)
rows = catalogue.get("scenarios", [])
run = [row for row in rows if row.get("status") == "RUN"]
not_run = [row.get("name", "?") for row in rows if row.get("status") != "RUN"]
print("OK %d %d %s %s" % (
    len(run), len(rows),
    catalogue.get("generated_at", "?"),
    ",".join(not_run) or "-",
))
PY
}

ensure_feed() {
    step "Modules 1-4: the analyst feed (the data every screen reads)"

    local summary status
    summary="$(feed_summary "$FEED_DIR")"
    status="${summary%% *}"

    if [ "$FORCE_FEED" = "1" ] || [ "$status" != "OK" ]; then
        if [ "$status" = "MALFORMED" ]; then
            warn "the existing feed will not parse — rebuilding it"
        elif [ "$status" = "MISSING" ]; then
            note "no feed yet: running the real Module 1-4 pipelines (~30 s)"
        else
            note "re-running the real Module 1-4 pipelines (--refresh-feed)"
        fi
        # A non-zero exit means one of two very different things, and they
        # need different advice: the engine reported some scenario NOT_RUN
        # (the feed is still written and honest), or it failed outright.
        mkdir -p "$RUNDIR"
        local export_status
        "$CVTRUST" analyst export --out "$FEED_DIR" 2>&1 | tee "$EXPORT_LOG"
        export_status="${PIPESTATUS[0]}"
        summary="$(feed_summary "$FEED_DIR")"
        status="${summary%% *}"
        if [ "$export_status" != "0" ]; then
            if [ "$status" != "OK" ]; then
                tail_log "$EXPORT_LOG" 25
                die "the Module 1-4 engine failed while building the feed" \
                    "Full output: $EXPORT_LOG" \
                    "The labs it reads are rebuildable: rm -rf attack_lab model_lab" \
                    "provenance_lab and run ./run.sh again."
            fi
            if [ "$ALLOW_PARTIAL_FEED" != "1" ]; then
                die "the engine could not export every scenario" \
                    "The scenarios listed as NOT_RUN above name the reason." \
                    "Re-run as: ALLOW_PARTIAL_FEED=1 ./run.sh — the platform renders" \
                    "NOT_RUN honestly rather than hiding it."
            fi
            warn "continuing with a partial feed (ALLOW_PARTIAL_FEED=1)"
        fi
    fi

    [ "$status" = "OK" ] || die "the analyst feed at $FEED_DIR is unusable ($summary)" \
        "Rebuild it with: ./run.sh --refresh-feed"

    local run total generated not_run
    run="$(echo "$summary" | awk '{print $2}')"
    total="$(echo "$summary" | awk '{print $3}')"
    generated="$(echo "$summary" | awk '{print $4}')"
    not_run="$(echo "$summary" | awk '{print $5}')"

    [ "$run" -gt 0 ] || die "the feed contains no runnable scenario" \
        "Rebuild it with: ./run.sh --refresh-feed"

    ok "demo feed: $run/$total scenarios, generated $generated"
    note "$FEED_DIR"
    if [ "$not_run" != "-" ]; then
        warn "not exported: $not_run"
    fi

    # LIVE is an operator-filled directory and is meant to be empty here. The
    # platform renders that state deliberately; it never falls back to demo.
    if [ -f "$LIVE_DIR/index.json" ]; then
        ok "live feed present ($LIVE_DIR)"
    else
        note "no live feed ($LIVE_DIR) — the live source renders its empty state, by design"
    fi
}

# ------------------------------------------------- Module 5: the frontend ----

build_is_stale() {
    # A server serving a build older than the source is the single most
    # misleading failure available here, so check rather than assume.
    [ -f "$ROOT/web/.next/BUILD_ID" ] || return 0
    local newer
    newer="$(find "$ROOT/web/app" "$ROOT/web/lib" "$ROOT/web/components" \
                  "$ROOT/web/hooks" "$ROOT/web/styles" "$ROOT/web/public" \
                  "$ROOT/web/package.json" "$ROOT/web/next.config.mjs" \
                  "$ROOT/web/tsconfig.json" \
                  -newer "$ROOT/web/.next/BUILD_ID" -print 2>/dev/null | head -1)"
    [ -n "$newer" ]
}

ensure_build() {
    step "Module 5: the analyst platform build"

    if [ "$MODE" = "dev" ]; then
        ok "development mode — Next.js compiles on demand, no build needed"
        return 0
    fi

    local reason=""
    if [ "$FORCE_BUILD" = "1" ]; then
        reason="--rebuild requested"
    elif [ ! -f "$ROOT/web/.next/BUILD_ID" ]; then
        reason="no production build yet"
    elif build_is_stale; then
        reason="sources changed since the last build"
    fi

    if [ -z "$reason" ]; then
        ok "current build reused ($(cat "$ROOT/web/.next/BUILD_ID"))"
        return 0
    fi

    note "building: $reason (~1 min, type errors fail the build by design)"
    mkdir -p "$RUNDIR"
    if ! ( cd "$ROOT/web" && NEXT_TELEMETRY_DISABLED=1 npm run build ) >"$BUILD_LOG" 2>&1; then
        tail_log "$BUILD_LOG" 40
        die "the frontend build failed" "Full output: $BUILD_LOG"
    fi
    ok "build complete ($(cat "$ROOT/web/.next/BUILD_ID"))"
}

# ----------------------------------------------------------- the process ----

WEB_PID=""
REUSED=0

cleanup() {
    local code=$?
    trap '' INT TERM EXIT
    if [ -n "$WEB_PID" ] && kill -0 "$WEB_PID" 2>/dev/null; then
        printf '\n%s==> stopping the analyst platform%s\n' "$B" "$R"
        # The server was started in its own process group (set -m), so the
        # whole group goes down with it — Next.js spawns workers, and killing
        # only the parent would leave them holding the port.
        kill -TERM -"$WEB_PID" 2>/dev/null || kill -TERM "$WEB_PID" 2>/dev/null || true
        local i=0
        while [ "$i" -lt 20 ] && kill -0 "$WEB_PID" 2>/dev/null; do
            sleep 0.5
            i=$((i + 1))
        done
        if kill -0 "$WEB_PID" 2>/dev/null; then
            kill -KILL -"$WEB_PID" 2>/dev/null || kill -KILL "$WEB_PID" 2>/dev/null || true
        fi
        ok "stopped"
    fi
    rm -f "$PIDFILE"
    release_lock
    exit $code
}

check_port() {
    step "Port $PORT"

    if ! port_busy "$PORT"; then
        ok "free"
        return 0
    fi

    # Something is there. If it is this same application, reuse it rather than
    # fighting it for the port; if it is anything else, say so and stop.
    local body
    if body="$(http_get "http://127.0.0.1:$PORT/api/analyst/status" 2>/dev/null)" \
       && printf '%s' "$body" | grep -q '"demo"'; then
        REUSED=1
        warn "the analyst platform is already running on :$PORT — reusing it"
        note "it was not started by this script, so Ctrl+C here will not stop it"
        note "to stop it:    kill \$(lsof -ti tcp:$PORT)"
        note "to run a second copy alongside it:   ./run.sh --port $((PORT + 1))"
        return 0
    fi

    die "port $PORT is in use by something else" \
        "Free it, or choose another port:   ./run.sh --port $((PORT + 1))" \
        "What is holding it:   lsof -i tcp:$PORT"
}

start_web() {
    step "Module 5: starting the analyst platform"

    mkdir -p "$RUNDIR"
    : > "$WEB_LOG"

    # cwd MUST be web/: lib/analyst/source.ts resolves the report directories
    # relative to the server's working directory (repoRoot = cwd/..).
    #
    # set -m puts the server in its own process group so the whole tree can be
    # signalled on exit, and so Ctrl+C reaches this script's trap first.
    set -m
    if [ "$MODE" = "dev" ]; then
        ( cd "$ROOT/web" && exec env NEXT_TELEMETRY_DISABLED=1 \
            ./node_modules/.bin/next dev -p "$PORT" ) >>"$WEB_LOG" 2>&1 &
    else
        ( cd "$ROOT/web" && exec env NEXT_TELEMETRY_DISABLED=1 \
            ./node_modules/.bin/next start -p "$PORT" ) >>"$WEB_LOG" 2>&1 &
    fi
    WEB_PID=$!
    set +m
    echo "$WEB_PID" > "$PIDFILE"
    note "pid $WEB_PID, log $WEB_LOG"
}

wait_ready() {
    # "Started" is not "ready": in dev the first request compiles the route,
    # and in production the server binds before it answers.
    local deadline=60
    [ "$MODE" = "dev" ] && deadline=180

    local i=0
    while [ "$i" -lt "$deadline" ]; do
        if [ "$REUSED" = "0" ] && ! kill -0 "$WEB_PID" 2>/dev/null; then
            tail_log "$WEB_LOG" 30
            die "the analyst platform exited during startup" "Full output: $WEB_LOG"
        fi
        if http_get "http://127.0.0.1:$PORT/api/analyst/status" >/dev/null 2>&1; then
            ok "data API answering:  http://localhost:$PORT/api/analyst/status"
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    if [ "$i" -ge "$deadline" ]; then
        tail_log "$WEB_LOG" 30
        die "the analyst platform did not become ready within ${deadline}s" \
            "Full output: $WEB_LOG"
    fi

    # The API answering only proves the server is up. Render the dashboard too:
    # that is the page a judge opens, and it exercises the feed on disk.
    local page_deadline=$((deadline / 2 + 30))
    i=0
    while [ "$i" -lt "$page_deadline" ]; do
        if http_get "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
            ok "dashboard rendering: http://localhost:$PORT/"
            return 0
        fi
        if [ "$REUSED" = "0" ] && ! kill -0 "$WEB_PID" 2>/dev/null; then
            tail_log "$WEB_LOG" 30
            die "the analyst platform exited while rendering the dashboard" \
                "Full output: $WEB_LOG"
        fi
        sleep 1
        i=$((i + 1))
    done
    tail_log "$WEB_LOG" 30
    die "the dashboard did not render within ${page_deadline}s" "Full output: $WEB_LOG"
}

banner() {
    local url="http://localhost:$PORT"
    printf '\n%s==========================================================%s\n' "$BLUE" "$R"
    printf '%s  DEMO READY%s' "$B" "$R"
    [ "$MODE" = "dev" ] && printf '%s  (development mode)%s' "$DIM" "$R"
    printf '\n%s==========================================================%s\n\n' "$BLUE" "$R"
    printf '  Analyst platform   %s%s%s\n' "$B" "$url" "$R"
    printf '  Evidence explorer  %s/evidence\n' "$url"
    printf '  The decision       %s/decision\n' "$url"
    printf '  Scenario matrix    %s/demo\n' "$url"
    printf '  Live source        %s/?source=live\n' "$url"
    printf '  Feed status (API)  %s/api/analyst/status\n' "$url"
    printf '\n'
    printf '  Engine             cvtrust %s (ran already; nothing else to start)\n' \
        "$("$CVTRUST" version 2>/dev/null | awk '{print $2}')"
    printf '  Demo data          %s\n' "$FEED_DIR"
    printf '  Server log         %s\n' "$WEB_LOG"
    printf '\n'
    if [ "$REUSED" = "1" ]; then
        printf '  %sThis server was already running; this script did not start it.%s\n' "$DIM" "$R"
        printf '  %sStop it with:  kill $(lsof -ti tcp:%s)%s\n\n' "$DIM" "$PORT" "$R"
    else
        printf '  %sPress Ctrl+C to stop the demo.%s\n\n' "$DIM" "$R"
    fi
}

open_browser() {
    [ "$OPEN_BROWSER" = "1" ] || return 0
    if command -v open >/dev/null 2>&1; then
        open "http://localhost:$PORT" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "http://localhost:$PORT" >/dev/null 2>&1 || true
    fi
}

# ------------------------------------------------------------------- main ----

printf '%sSIH26228 · cvtrust — trustworthy CV integrity assurance%s\n' "$B" "$R"
printf '%sComplete demo launcher. Everything below runs locally and offline.%s\n' "$DIM" "$R"

preflight
acquire_lock
trap 'release_lock' EXIT
ensure_labs
ensure_feed
ensure_build
release_lock
trap - EXIT

if [ "$PREPARE_ONLY" = "1" ]; then
    step "Prepared"
    ok "labs, analyst feed and frontend build are ready"
    note "start the demo with:  ./run.sh"
    exit 0
fi

check_port
trap cleanup INT TERM EXIT
if [ "$REUSED" = "0" ]; then
    start_web
fi
wait_ready
banner
open_browser

if [ "$REUSED" = "1" ]; then
    trap - INT TERM EXIT
    exit 0
fi

# Stay in the foreground so Ctrl+C lands here and the trap can take the server
# down with it. If the server dies on its own, say so instead of exiting 0.
wait "$WEB_PID" || true

# Reaching here means the server exited by itself: Ctrl+C and SIGTERM are
# handled by the trap, which does not return.
WEB_PID=""
tail_log "$WEB_LOG" 20
printf '\n%s   xx  the analyst platform stopped unexpectedly%s\n' "$RED" "$R" >&2
rm -f "$PIDFILE"
trap - INT TERM EXIT
exit 1
