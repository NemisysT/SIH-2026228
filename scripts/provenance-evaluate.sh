#!/usr/bin/env bash
# One-command Module 3 evaluation: build every provenance attack scenario, check
# each one's verification outcome against its ground truth, measure the
# performance of the machinery, and render two analyst-facing reports — one
# clean, one compromised.
#
# Reproducible: every scenario is a pure function of its seed, and Ed25519
# signatures are deterministic, so re-running produces byte-identical logs.
#
# Needs no model runtime. Module 3 binds Module 2's digests rather than
# recomputing them, so this script runs in a Module-1-only environment.
set -euo pipefail
cd "$(dirname "$0")/.."

CVTRUST="${CVTRUST:-./.venv/bin/cvtrust}"
LAB="${PROVENANCE_LAB:-provenance_lab}"
RECORDS="${RECORDS:-6}"

mkdir -p reports

echo "==> building the provenance attack lab (28 scenarios)"
$CVTRUST -q lab provenance-build --out "$LAB" --records "$RECORDS"

echo
echo "==> checking every scenario against its ground truth"
echo "    scoring is EXACT SET EQUALITY, not precision/recall: an extra failure"
echo "    fails a scenario as hard as a missed one"
$CVTRUST -q lab provenance-evaluate "$LAB" \
    --out reports/provenance_evaluation.json

# Start from a fresh replay database. This matters, and it is not tidiness: a
# replay database REMEMBERS, so verifying the same log twice against the same
# database correctly reports every record as a replay the second time. Leaving
# a stale database in place would make this script non-idempotent and, worse,
# would make a clean log look compromised on a re-run. The two verifications
# below demonstrate exactly that, deliberately.
rm -f reports/provenance_replay.json

echo
echo "==> a clean log, verified with everything supplied, against a FRESH"
echo "    replay database"
$CVTRUST -q provenance verify-log "$LAB/clean/log.jsonl" \
    --store "$LAB/clean/trust_store.json" \
    --anchor "$LAB/clean/anchor.json" \
    --replay-db reports/provenance_replay.json \
    --out reports/provenance_clean.json \
    --markdown-out reports/provenance_clean.md || true

echo
echo "==> the SAME log, re-presented to the now-populated database. Every"
echo "    signature still verifies and every binding still holds; it is a"
echo "    replay because it has been seen before. A valid signature does not"
echo "    establish that an inference happened once."
$CVTRUST -q provenance verify-log "$LAB/clean/log.jsonl" \
    --store "$LAB/clean/trust_store.json" \
    --anchor "$LAB/clean/anchor.json" \
    --replay-db reports/provenance_replay.json \
    --out reports/provenance_replayed.json \
    --markdown-out reports/provenance_replayed.md || true

echo
echo "==> the same log after an adversary holding their OWN signing key"
echo "    rewrote a bound model digest and re-signed. The signature verifies."
$CVTRUST -q provenance verify-log "$LAB/modified_model_digest/log.jsonl" \
    --store "$LAB/modified_model_digest/trust_store.json" \
    --anchor "$LAB/modified_model_digest/anchor.json" \
    --out reports/provenance_compromised.json \
    --markdown-out reports/provenance_compromised.md || true

echo
echo "==> the honest negative result: a truncated log, verified WITHOUT an"
echo "    anchor. Internally perfect; the report says NOT_DETECTABLE, not clean."
$CVTRUST -q provenance verify-log "$LAB/truncated_log/log.jsonl" \
    --store "$LAB/truncated_log/trust_store.json" \
    --out reports/provenance_truncated_no_anchor.json || true

echo
echo "==> measuring the machinery"
$CVTRUST -q provenance benchmark --records 200 \
    --out reports/provenance_benchmark.json

echo
echo "reports/ now contains the scenario evaluation, four verification reports"
echo "and the benchmark. Read provenance_clean.md and provenance_replayed.md"
echo "side by side: identical bytes, identical signatures, opposite verdicts."
echo "See docs/provenance.md for the record schema, the failure taxonomy, and"
echo "what this module does NOT establish."
