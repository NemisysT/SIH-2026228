#!/usr/bin/env bash
#
# cvtrust — the one command a new developer runs after cloning (SIH26228).
#
#   ./setup.sh
#
# It brings a fresh clone to a state where the engine, the test suite and the
# analyst platform all work, and it is safe to run again at any time: work that
# is already done is detected and skipped rather than repeated or overwritten.
#
# What it does, in order:
#
#   1. checks the prerequisites (Python 3.11+, and Node 20.9+ for Module 5)
#   2. creates .venv and installs the Python dependencies (the ONLY step that
#      needs a package index — nothing downloads anything at run time)
#   3. creates the working directories and the local config that Git ignores
#   4. installs the Module 5 frontend dependencies (web/node_modules)
#   5. builds the attack labs and exports the analyst feed the frontend reads
#   6. smoke-tests the result
#
# This script orchestrates the project's existing scripts and CLI rather than
# reimplementing them:
#
#   scripts/evaluate.sh             builds attack_lab      (Module 1)
#   scripts/provenance-evaluate.sh  builds provenance_lab  (Module 3)
#   cvtrust lab model-build         builds model_lab       (Module 2)
#   cvtrust lab assurance-build     builds assurance_lab   (Module 4)
#   cvtrust analyst export          builds reports/analyst (Module 5)
#
# There are no secrets, API keys or accounts anywhere in this project. If a
# step ever needs one, it will say so instead of inventing a value.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"

# ---------------------------------------------------------------- options --

DO_WEB=1          # Module 5 frontend (Node)
DO_FEED=1         # attack labs + analyst feed
DO_MODEL_LAB=1    # Module 2 lab: trains 16 small CNNs, ~70 s, needs torch
FORCE=0           # redo work that is already done
WHEELHOUSE=""     # air-gapped install: a directory of pre-downloaded wheels

usage() {
    cat <<'USAGE'
Usage: ./setup.sh [options]

  --skip-web          Python engine only; do not touch Node or web/
  --skip-feed         do not build the attack labs or the analyst feed
  --skip-model-lab    skip the Module 2 model lab (fastest useful setup;
                      17 of the 19 analyst scenarios then export as NOT_RUN,
                      which is the engine reporting missing evidence honestly)
  --wheelhouse DIR    install Python dependencies from DIR with no package
                      index (air-gapped install; see docs/deployment.md)
  --force             recreate .venv, reinstall web dependencies and rebuild
                      the labs and the feed even if they are already present
  -h, --help          this message

Environment:
  PYTHON              Python interpreter to build .venv with (default python3)

First run takes about five minutes, most of it generating the labs. Later runs
skip whatever is already in place and take seconds.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-web)       DO_WEB=0 ;;
        --skip-feed)      DO_FEED=0 ;;
        --skip-model-lab) DO_MODEL_LAB=0 ;;
        --with-model-lab) DO_MODEL_LAB=1 ;;   # the default; accepted for clarity
        --wheelhouse)
            [ $# -ge 2 ] || { echo "setup.sh: --wheelhouse needs a directory" >&2; exit 2; }
            WHEELHOUSE="$2"; shift ;;
        --force)          FORCE=1 ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "setup.sh: unknown option '$1'" >&2; echo >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ------------------------------------------------------------------ output --

if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; BLUE=$'\033[34m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

STEP=0
step()  { STEP=$((STEP + 1)); printf '\n%s==> [%d/6] %s%s\n' "$BOLD$BLUE" "$STEP" "$1" "$RESET"; }
info()  { printf '    %s\n' "$1"; }
skip()  { printf '    %s· %s%s\n' "$DIM" "$1" "$RESET"; }
ok()    { printf '    %s✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn()  { printf '    %s! %s%s\n' "$YELLOW" "$1" "$RESET"; }

# die <what went wrong> [<what to do about it> ...]
die() {
    printf '\n%serror: %s%s\n' "$BOLD$RED" "$1" "$RESET" >&2
    shift
    for line in "$@"; do printf '       %s\n' "$line" >&2; done
    printf '\n       setup.sh is safe to re-run once this is fixed.\n' >&2
    exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------- 1. prerequisites --

step "checking prerequisites"

PY="${PYTHON:-python3}"
have "$PY" || die "no '$PY' on PATH" \
    "cvtrust needs Python 3.11 or newer (see docs/deployment.md)." \
    "Install it, or point setup.sh at one:  PYTHON=/path/to/python3.13 ./setup.sh"

if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    die "$PY is $("$PY" -c 'import platform; print(platform.python_version())'), and cvtrust needs 3.11 or newer" \
        "Install a newer Python and re-run, or point setup.sh at one you have:" \
        "  PYTHON=/path/to/python3.13 ./setup.sh"
fi
ok "$("$PY" -c 'import platform,sys; print("Python " + platform.python_version() + "  (" + sys.executable + ")")')"

"$PY" -c 'import venv' 2>/dev/null || die "$PY cannot create virtual environments ('venv' is missing)" \
    "On Debian/Ubuntu:  sudo apt install python3-venv" \
    "Otherwise install a Python distribution that includes the standard library."

if [ -n "$WHEELHOUSE" ]; then
    [ -d "$WHEELHOUSE" ] || die "wheelhouse directory '$WHEELHOUSE' does not exist" \
        "Build one on a connected machine:  pip download -r requirements.txt -d wheelhouse"
    ok "wheelhouse: $WHEELHOUSE (no package index will be used)"
fi

if [ "$DO_WEB" = 1 ]; then
    if ! have node || ! have npm; then
        die "Node.js and npm are required for Module 5 (the analyst platform)" \
            "Install Node 20.9 or newer from https://nodejs.org, then re-run." \
            "To set up the Python engine alone for now:  ./setup.sh --skip-web"
    fi
    NODE_VERSION="$(node --version | sed 's/^v//')"
    NODE_MAJOR="${NODE_VERSION%%.*}"
    NODE_REST="${NODE_VERSION#*.}"; NODE_MINOR="${NODE_REST%%.*}"
    if [ "$NODE_MAJOR" -lt 20 ] || { [ "$NODE_MAJOR" -eq 20 ] && [ "$NODE_MINOR" -lt 9 ]; }; then
        die "Node $NODE_VERSION is too old for the frontend (Next.js 16 needs 20.9+)" \
            "Upgrade Node, or set up the Python engine alone:  ./setup.sh --skip-web"
    fi
    ok "Node $NODE_VERSION, npm $(npm --version)"
fi

# --------------------------------------------- 2. Python virtual env + deps --

step "installing the Python engine into .venv"

VENV_PY="$ROOT/.venv/bin/python"

if [ "$FORCE" = 1 ] && [ -d .venv ]; then
    info "--force: removing the existing .venv"
    rm -rf .venv
fi

if [ -x "$VENV_PY" ] && "$VENV_PY" -c 'import sys' 2>/dev/null; then
    skip ".venv already exists — reusing it"
elif [ -e .venv ]; then
    die ".venv exists but its interpreter does not work" \
        "Something interrupted an earlier setup, or the clone moved on disk." \
        "Re-create it:  ./setup.sh --force"
else
    info "creating .venv"
    "$PY" -m venv .venv
fi

PIP_ARGS="--quiet --disable-pip-version-check"
if [ -n "$WHEELHOUSE" ]; then
    PIP_ARGS="$PIP_ARGS --no-index --find-links $WHEELHOUSE"
fi

info "installing dependencies (this is the only step that needs a network)"
# shellcheck disable=SC2086
"$VENV_PY" -m pip install $PIP_ARGS --upgrade pip setuptools wheel
# shellcheck disable=SC2086
"$VENV_PY" -m pip install $PIP_ARGS -r requirements.txt || die \
    "installing requirements.txt failed" \
    "The usual cause is no route to the package index." \
    "For an air-gapped machine, vendor the wheels on a connected one:" \
    "  pip download -r requirements.txt -d wheelhouse" \
    "then:  ./setup.sh --wheelhouse wheelhouse"
# shellcheck disable=SC2086
if [ -n "$WHEELHOUSE" ]; then
    "$VENV_PY" -m pip install $PIP_ARGS --no-build-isolation -e .
else
    "$VENV_PY" -m pip install $PIP_ARGS -e .
fi

CVTRUST="$ROOT/.venv/bin/cvtrust"
[ -x "$CVTRUST" ] || die "the cvtrust command was not installed into .venv" \
    "Re-run with a clean environment:  ./setup.sh --force"
ok "$("$CVTRUST" version)"

# ------------------------------- 3. directories and local, Git-ignored files --

step "creating the local working directories and configuration"

# These are all deliberately out of version control: reports/ and the labs are
# generated, and keys/ holds operational key material. The project expects them
# to exist, so a fresh clone has to create them.
for directory in reports reports/live datasets models; do
    if [ -d "$directory" ]; then
        skip "$directory/ exists"
    else
        mkdir -p "$directory"
        ok "created $directory/"
    fi
done

if [ -d keys ]; then
    skip "keys/ exists"
else
    mkdir -p keys && chmod 700 keys
    ok "created keys/ (mode 700 — Module 3 signing keys live here)"
fi

[ -f configs/default.yaml ] || die "configs/default.yaml is missing" \
    "It is version-controlled, so this clone is incomplete. Try:  git checkout configs"
skip "configs/default.yaml present"

if [ "$DO_WEB" = 1 ]; then
    # web/.env is Git-ignored (the Next.js template ignores every .env*), and
    # the checked-in template is the only record of what belongs in it.
    if [ -f web/.env ]; then
        skip "web/.env exists — left untouched"
    else
        cp web/.env.example web/.env
        ok "created web/.env from web/.env.example"
    fi
    if grep -q 'REPLACE_ME' web/.env 2>/dev/null; then
        die "web/.env still contains a REPLACE_ME placeholder" \
            "Open web/.env and fill it in, then re-run ./setup.sh"
    fi
fi

# ------------------------------------------------ 4. Module 5 dependencies --

if [ "$DO_WEB" = 1 ]; then
    step "installing the analyst platform's dependencies (web/node_modules)"
    if [ -d web/node_modules ] && [ "$FORCE" = 0 ]; then
        skip "web/node_modules already present — reusing it (--force reinstalls)"
    else
        if [ -f web/package-lock.json ]; then
            info "npm ci from web/package-lock.json — a few hundred MB on disk"
        else
            info "npm install — about 550 MB, a few minutes on a cold cache"
        fi
        # --legacy-peer-deps: @react-three/fiber 9.5.0 declares a peer range of
        # react "<19.3" and this project is built against react 19.3.0, which
        # npm's strict peer resolution refuses outright. web/.npmrc sets the
        # same flag so a hand-run `npm install` behaves identically; it is
        # repeated here so setup does not depend on that file surviving.
        if [ -f web/package-lock.json ]; then
            ( cd web && npm ci --legacy-peer-deps --no-audit --no-fund ) || die "npm ci failed in web/" \
                "Check the output above. If the lockfile is stale:  cd web && npm install"
        else
            ( cd web && npm install --legacy-peer-deps --no-audit --no-fund ) || die "npm install failed in web/" \
                "The usual cause is no route to the npm registry." \
                "For an air-gapped machine, carry web/node_modules across with the" \
                "repository instead — see docs/deployment.md § Module 5." \
                "To continue without the frontend for now:  ./setup.sh --skip-web"
        fi
        ok "frontend dependencies installed"
    fi
else
    step "analyst platform dependencies (skipped: --skip-web)"
    skip "run ./setup.sh later without --skip-web to set up web/"
fi

# ---------------------------------------- 5. attack labs and analyst feed --

if [ "$DO_FEED" = 1 ]; then
    step "building the attack labs and the analyst feed"

    if [ -d attack_lab/_clean/dataset ] && [ -d attack_lab/ood_insertion ] && [ "$FORCE" = 0 ]; then
        skip "attack_lab/ already built (Module 1)"
    else
        info "Module 1: generating the corpus and all six dataset scenarios (~50 s)"
        ./scripts/evaluate.sh >/dev/null || die "scripts/evaluate.sh failed" \
            "Re-run it on its own to see the output:  ./scripts/evaluate.sh"
        ok "attack_lab/ built, reports/evaluation.json written"
    fi

    if [ -f provenance_lab/lab_manifest.json ] && [ "$FORCE" = 0 ]; then
        skip "provenance_lab/ already built (Module 3)"
    else
        info "Module 3: building the provenance lab, 28 scenarios (~10 s)"
        ./scripts/provenance-evaluate.sh >/dev/null || die "scripts/provenance-evaluate.sh failed" \
            "Re-run it on its own to see the output:  ./scripts/provenance-evaluate.sh"
        ok "provenance_lab/ built"
    fi

    if [ "$DO_MODEL_LAB" = 0 ]; then
        skip "Module 2 model lab skipped (--skip-model-lab)"
    elif [ -f model_lab/_reference/reference.onnx ] && [ -d model_lab/backdoor_badnets ] && [ "$FORCE" = 0 ]; then
        skip "model_lab/ already built (Module 2)"
    else
        info "Module 2: training the reference model and 15 scenarios (~70 s)"
        # torch prints deprecation warnings on stderr during scripting and
        # serialisation. Keep the log, and show it only if the step fails.
        MODEL_LOG="$(mktemp -t cvtrust-model-build)"
        if ! "$CVTRUST" -q lab model-build --out model_lab >"$MODEL_LOG" 2>&1; then
            tail -20 "$MODEL_LOG" >&2
            rm -f "$MODEL_LOG"
            die "cvtrust lab model-build failed" \
                "This step needs the torch runtime. Check what is available:" \
                "  ./.venv/bin/cvtrust info" \
                "Setup can continue without it:  ./setup.sh --skip-model-lab"
        fi
        rm -f "$MODEL_LOG"
        ok "model_lab/ built"
    fi

    # The Module 4 population lab is version-controlled, so a clone normally
    # already has it; rebuild only if it is missing.
    if [ -f assurance_lab/lab_spec.json ] && [ "$FORCE" = 0 ]; then
        skip "assurance_lab/ present (Module 4)"
    else
        info "Module 4: building the population lab (~60 s)"
        "$CVTRUST" -q lab assurance-build --out assurance_lab --per-class 8 >/dev/null || die \
            "cvtrust lab assurance-build failed" \
            "Re-run it on its own to see the output:" \
            "  ./.venv/bin/cvtrust lab assurance-build --out assurance_lab --per-class 8"
        ok "assurance_lab/ built"
    fi

    if [ -f reports/analyst/index.json ] && [ "$FORCE" = 0 ]; then
        skip "reports/analyst/ already exported — the frontend has data"
    else
        info "Module 5: running the real Module 1-4 pipelines and exporting the feed (~40 s)"
        # Exit status 1 means the feed was written but some scenario had no
        # upstream lab to run against. That is the engine reporting missing
        # evidence rather than fabricating it, and it is not a setup failure.
        set +e
        "$CVTRUST" analyst export --out reports/analyst >/tmp/cvtrust-analyst-export.$$.log 2>&1
        EXPORT_STATUS=$?
        set -e
        if [ "$EXPORT_STATUS" -gt 1 ] || [ ! -f reports/analyst/index.json ]; then
            tail -20 "/tmp/cvtrust-analyst-export.$$.log" >&2
            rm -f "/tmp/cvtrust-analyst-export.$$.log"
            die "cvtrust analyst export failed" \
                "Re-run it on its own to see the output:" \
                "  ./.venv/bin/cvtrust analyst export --out reports/analyst"
        fi
        grep -E '[0-9]+/[0-9]+ scenario' "/tmp/cvtrust-analyst-export.$$.log" | sed 's/^/    /' || true
        rm -f "/tmp/cvtrust-analyst-export.$$.log"
        ok "reports/analyst/ exported"
    fi
else
    step "attack labs and analyst feed (skipped: --skip-feed)"
    skip "the frontend will report that it has no data until you run:"
    skip "  ./setup.sh   (or: ./.venv/bin/cvtrust analyst export --out reports/analyst)"
fi

# -------------------------------------------------------- 6. smoke checks --

step "smoke-testing the installation"

"$VENV_PY" - <<'PYCHECK' || die "the installed package is incomplete" \
    "Re-create the environment:  ./setup.sh --force"
import importlib

for module in ("cvtrust", "cvtrust.cli.main", "cvtrust.attack_lab", "cvtrust.assurance"):
    importlib.import_module(module)
PYCHECK
ok "cvtrust imports, including the lab generators"

"$CVTRUST" info >/dev/null || die "'cvtrust info' failed" "Run it directly to see why:  ./.venv/bin/cvtrust info"
ok "cvtrust info reports its coverage statement"

if [ -f reports/analyst/index.json ]; then
    FEED_SUMMARY="$("$VENV_PY" - <<'PYCHECK'
import json, pathlib
catalogue = json.loads(pathlib.Path("reports/analyst/index.json").read_text())
rows = catalogue["scenarios"]
run = [row for row in rows if row["status"] == "RUN"]
print(f"analyst feed: {len(run)}/{len(rows)} scenarios exported")
PYCHECK
)" || die "reports/analyst/index.json is not readable" \
        "Rebuild the feed:  ./setup.sh --force"
    ok "$FEED_SUMMARY"
    case "$FEED_SUMMARY" in
        *"19/19"*) : ;;
        *) warn "scenarios without their upstream lab export as NOT_RUN with the reason;"
           warn "build the missing lab and re-run ./setup.sh --force to fill them in" ;;
    esac
fi

if [ "$DO_WEB" = 1 ] && [ -d web/node_modules ]; then
    ( cd web && npm test --silent >/dev/null 2>&1 ) || die "the frontend's projection tests failed" \
        "Run them directly to see why:  cd web && npm test"
    ok "frontend projection tests pass"
fi

# -------------------------------------------------------------- what next --

printf '\n%sSetup complete.%s The machine can now be disconnected: nothing below\n' "$BOLD$GREEN" "$RESET"
printf 'reaches the network at run time.\n\n'
printf '%sRun the engine%s\n' "$BOLD" "$RESET"
printf '  ./scripts/demo.sh                     the whole story, end to end, ~15 s\n'
printf '  ./.venv/bin/cvtrust info              what this build does and does not cover\n'
printf '  ./.venv/bin/pytest                    the full test suite, ~5 min\n\n'
if [ "$DO_WEB" = 1 ]; then
    printf '%sRun the analyst platform (Module 5)%s\n' "$BOLD" "$RESET"
    if [ -x ./run.sh ]; then
        printf '  ./run.sh                              serve the platform, http://localhost:3000\n'
    fi
    printf '  cd web && npm run dev                 development server, http://localhost:3000\n'
    printf '  ./scripts/module5-verify.sh           engine -> feed -> UI, end to end\n\n'
fi
printf '%sRefresh the analyst feed after changing the engine%s\n' "$BOLD" "$RESET"
printf '  ./.venv/bin/cvtrust analyst export --out reports/analyst\n\n'
printf 'See README.md for the full command list and docs/deployment.md for\n'
printf 'air-gapped installation.\n'
