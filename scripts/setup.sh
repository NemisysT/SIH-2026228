#!/usr/bin/env bash
# MOVED. The canonical setup entry point is ./setup.sh in the repository root,
# which does everything this script used to do (create .venv, install the
# dependencies) and everything else a fresh clone needs: the Git-ignored
# working directories, web/.env, the frontend's dependencies, the attack labs
# and the analyst feed.
#
# This shim stays so that older instructions keep working. It forwards every
# argument; run `./setup.sh --help` for the options.
set -euo pipefail
printf 'note: scripts/setup.sh now forwards to ./setup.sh, the canonical entry point.\n\n' >&2
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/setup.sh" "$@"
