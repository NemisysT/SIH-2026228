#!/usr/bin/env bash
# One-command setup. This is the only step that needs a package index;
# runtime is air-gapped.
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
echo "==> creating virtual environment (.venv)"
"$PY" -m venv .venv

echo "==> installing dependencies"
./.venv/bin/python -m pip install --quiet --upgrade pip setuptools wheel
./.venv/bin/python -m pip install --quiet -r requirements.txt
./.venv/bin/python -m pip install --quiet -e .

echo
./.venv/bin/cvtrust version
echo
echo "Setup complete. The machine can now be disconnected."
echo
echo "  ./scripts/demo.sh        end-to-end demonstration"
echo "  ./scripts/evaluate.sh    generate the attack lab and measure the detectors"
echo "  ./.venv/bin/pytest       full test suite"
echo "  ./.venv/bin/cvtrust info coverage statement for this build"
