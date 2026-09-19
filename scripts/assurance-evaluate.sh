#!/usr/bin/env bash
# One-command Module 4 evaluation: build the population lab, measure the
# distribution-shift characteriser against ten population pairs, fuse the real
# Module 1/2/3 labs through nineteen end-to-end scenarios, and render the two
# reports that make the design argument.
#
# NINE OF THE TEN POPULATION PAIRS CONTAIN NO ATTACK. That is the point. The
# failure this module can most easily commit is calling a legitimate seasonal,
# terrain, sensor or illumination change an attack, so most of what is measured
# here is a FALSE-POSITIVE rate, not a detection rate.
#
# The pipeline scenarios need the other three labs. Without them the shift
# pairs still run and every pipeline scenario is reported NOT_RUN with the
# reason — never faked, never silently dropped.
set -euo pipefail
cd "$(dirname "$0")/.."

CVTRUST=./.venv/bin/cvtrust
LAB="${ASSURANCE_LAB:-assurance_lab}"
DATASET_LAB="${DATASET_LAB:-attack_lab}"
MODEL_LAB="${MODEL_LAB:-model_lab}"
PROVENANCE_LAB="${PROVENANCE_LAB:-provenance_lab}"
PER_CLASS="${PER_CLASS:-8}"

mkdir -p reports

echo "==> building the population lab (1 reference corpus + 10 pairs)"
$CVTRUST -q lab assurance-build --out "$LAB" --per-class "$PER_CLASS"

UPSTREAM=()
for pair in "--dataset-lab:$DATASET_LAB" "--model-lab:$MODEL_LAB" \
            "--provenance-lab:$PROVENANCE_LAB"; do
    flag="${pair%%:*}"; dir="${pair#*:}"
    if [ -d "$dir" ]; then
        UPSTREAM+=("$flag" "$dir")
    else
        echo "    note: $dir not present — the scenarios needing it will be"
        echo "          reported NOT_RUN with the reason, rather than skipped"
    fi
done

echo
echo "==> checking every pair and every scenario against its expectation"
echo "    ground truth lives OUTSIDE the evidence being evaluated: no rule can"
echo "    read which condition the lab applied"
$CVTRUST -q lab assurance-evaluate "$LAB" "${UPSTREAM[@]}" \
    --out reports/assurance-evaluation.json

echo
echo "==> a legitimate, DECLARED night collection against the reference"
echo "    a real shift that must NOT be reported as an attack"
$CVTRUST -q assurance shift "$LAB/operational_illumination/dataset" \
    --reference "$LAB/_reference/dataset" \
    --reference-declare "illumination=daylight,season=summer,terrain=mixed" \
    --declare "illumination=low,acquisition_mode=night" \
    --reference-provenance "baseline collection, declared by the operator" \
    --out reports/assurance_shift_declared.json

echo
echo "==> the SAME imagery with the declaration saying nothing changed"
echo "    identical pixels, identical statistics, different verdict — because"
echo "    the difference is in what was claimed, not in what was measured"
$CVTRUST -q assurance shift "$LAB/undeclared_illumination/dataset" \
    --reference "$LAB/_reference/dataset" \
    --reference-declare "illumination=daylight,season=summer,terrain=mixed" \
    --declare "illumination=daylight,season=summer,terrain=mixed" \
    --out reports/assurance_shift_undeclared.json

echo
echo "==> scanning the shifted corpus with Module 1, then fusing"
$CVTRUST -q dataset scan "$LAB/operational_illumination/dataset" \
    --out reports/assurance_dataset.json || true

echo
echo "==> the fusion, with the shift context supplied"
$CVTRUST -q assurance assess \
    --dataset-report reports/assurance_dataset.json \
    --shift reports/assurance_shift_declared.json \
    --out reports/assurance_with_context.json \
    --markdown-out reports/assurance_with_context.md || true

echo
echo "==> the SAME dataset findings with NO shift analysis supplied"
echo "    the distribution scope becomes NOT_ASSESSED and the dataset findings"
echo "    lose their confounding mark — same evidence, different explanation"
$CVTRUST -q assurance assess \
    --dataset-report reports/assurance_dataset.json \
    --out reports/assurance_without_context.json \
    --markdown-out reports/assurance_without_context.md || true

echo
echo "==> supplying nothing at all"
echo "    NOT_ASSESSED, never ACCEPT. Withholding a report is the cheapest"
echo "    attack available in a multi-contributor pipeline."
$CVTRUST -q assurance assess --out reports/assurance_no_inputs.json || true

echo
echo "reports/ now contains the evaluation, two shift assessments over the same"
echo "physical change, and three assurance decisions. Read"
echo "assurance_with_context.md and assurance_without_context.md side by side:"
echo "identical findings, different governing rule, different confounding, and"
echo "the same conservative disposition — which is itself a documented limit."
echo "See docs/module-4-plan.md and docs/attack-matrix.md for the measurements."
