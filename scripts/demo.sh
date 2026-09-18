#!/usr/bin/env bash
# One-command end-to-end demonstration.
#
#   clean corpus -> integrity baseline -> false-alarm check -> multi-contributor
#   attack -> detection with evidence -> measurement against ground truth ->
#   post-baseline tampering -> re-verification -> declared limitations
set -euo pipefail
cd "$(dirname "$0")/.."
exec ./.venv/bin/cvtrust -q demo \
    --workdir attack_lab \
    --reports-dir reports \
    "$@"
