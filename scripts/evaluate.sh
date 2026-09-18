#!/usr/bin/env bash
# One-command full evaluation: generate the corpus, build every attack scenario,
# measure every detector against ground truth, and write a calibration table.
#
# Reproducible: the corpus and every attack are pure functions of their seeds.
set -euo pipefail
cd "$(dirname "$0")/.."

CVTRUST=./.venv/bin/cvtrust
PER_CLASS="${PER_CLASS:-14}"
LAB="${LAB:-attack_lab}"

echo "==> generating the clean baseline corpus (${PER_CLASS} per class per contributor)"
$CVTRUST -q lab generate --out "$LAB/_clean" --per-class "$PER_CLASS" --coco --yolo

for scenario in duplicate_flood near_duplicate_flood label_flip \
                systematic_mislabel ood_insertion combined; do
    echo "==> building scenario: $scenario"
    $CVTRUST -q lab attack "$LAB/_clean/dataset" "$LAB/$scenario" --scenario "$scenario"
done

echo "==> measuring detectors against ground truth"
$CVTRUST -q lab evaluate "$LAB" \
    --out reports/evaluation.json \
    --calibration-out reports/calibration.json

echo
echo "==> clean-corpus false-alarm baseline"
$CVTRUST -q dataset scan "$LAB/_clean/dataset" --out reports/clean_scan.json || true

echo
echo "reports/evaluation.json   per-scenario metrics with evaluation populations"
echo "reports/calibration.json  measured precision per score bin"
echo "reports/clean_scan.json   behaviour on data with nothing wrong with it"
