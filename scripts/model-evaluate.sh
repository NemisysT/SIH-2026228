#!/usr/bin/env bash
# One-command Module 2 evaluation: train the reference model, build every model
# attack scenario, measure every model detector against ground truth, and write
# a calibration table.
#
# Reproducible: the reference model and every scenario are pure functions of
# their seeds. Re-running produces byte-identical artifacts.
#
# Requires the 'onnx' and 'torch' extras. Without them, `cvtrust info` reports
# no model formats available and this script has nothing to run.
set -euo pipefail
cd "$(dirname "$0")/.."

CVTRUST=./.venv/bin/cvtrust
LAB="${MODEL_LAB:-model_lab}"
PER_CLASS="${PER_CLASS:-60}"
EPOCHS="${EPOCHS:-30}"

echo "==> building the model attack lab (reference + 15 scenarios)"
$CVTRUST -q lab model-build --out "$LAB" --per-class "$PER_CLASS" --epochs "$EPOCHS"

echo
echo "==> WHITE-BOX evaluation over the ONNX artifacts"
$CVTRUST -q lab model-evaluate "$LAB" \
    --artifact model.onnx \
    --out reports/model_evaluation.json \
    --calibration-out reports/model_calibration.json

echo
echo "==> BLACK-BOX evaluation: graph, parameter, activation and gradient"
echo "    access are genuinely removed, not simulated"
$CVTRUST -q lab model-evaluate "$LAB" \
    --artifact model.onnx --black-box \
    --out reports/model_evaluation_blackbox.json \
    --calibration-out /dev/null

echo
echo "==> GRADIENT pathway: TorchScript artifacts, where Neural Cleanse can run"
$CVTRUST -q lab model-evaluate "$LAB" \
    --artifact model.pt \
    --out reports/model_evaluation_torchscript.json \
    --calibration-out /dev/null

echo
echo "==> a single assessment, rendered for an analyst"
$CVTRUST -q model assess "$LAB/backdoor_badnets/model.onnx" \
    --reference "$LAB/_reference/reference.onnx" \
    --calibration reports/model_calibration.json \
    --markdown-out reports/model_assurance_backdoor.md || true

echo
echo "reports/ now contains the evaluation, the calibration table and a"
echo "rendered model assurance report. See docs/model-security.md for what the"
echo "numbers mean and for the two methods that did NOT work."
