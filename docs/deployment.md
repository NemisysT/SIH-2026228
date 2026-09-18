# Deployment

## Requirements

- Python **3.11+** (developed and tested on 3.13)
- ~250 MB disk for the virtual environment
- No GPU. No network at runtime. No database. No services.

Runs on an ordinary laptop; the reference figures in `docs/attack-matrix.md`
were measured on a single laptop CPU core.

## Install

Installation is the only step that needs a package index.

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -e .
```

Or:

```bash
./scripts/setup.sh
```

Verify, then disconnect the machine:

```bash
./.venv/bin/cvtrust version
./.venv/bin/cvtrust info      # prints the coverage statement
```

## Air-gapped installation

Build a wheelhouse on a connected machine with the *same* platform and Python
minor version, transfer it, and install with the index disabled:

```bash
# connected machine
pip download -r requirements.txt -d wheelhouse

# air-gapped machine
python3 -m venv .venv
./.venv/bin/pip install --no-index --find-links=wheelhouse -r requirements.txt
./.venv/bin/pip install --no-index --no-build-isolation -e .
```

Nothing further is fetched, at install time or after.

## Confirming the air gap

```bash
# No HTTP client reaches a runtime path:
grep -rE "requests|urllib3|httpx|aiohttp|urlopen|socket\.|boto3" src/cvtrust/ ; echo "exit=$?"

# The default feature space declares that it needs no weights:
./.venv/bin/python -c "
from cvtrust.features import ClassicalFeatureExtractor
print(ClassicalFeatureExtractor().describe())"
```

The strongest confirmation is to run the whole demonstration with networking
disabled — it completes unchanged.

## Everyday use

```bash
# 1. Establish an integrity baseline. Store the manifest SEPARATELY from
#    the dataset (see docs/security.md).
cvtrust dataset manifest /data/mission-corpus --out /secure/baseline.json

# 2. Assess a dataset.
cvtrust dataset scan /data/mission-corpus \
    --reference /secure/trusted_sample_ids.json \
    --calibration /secure/calibration.json \
    --out reports/scan.json

# 3. Re-verify later: detects modified, missing and added files.
cvtrust dataset verify /secure/baseline.json /data/mission-corpus
```

`dataset scan` exit codes compose into a pipeline:

| Code | Meaning |
|---|---|
| 0 | no actionable findings, within declared coverage |
| 1 | review recommended or required |
| 2 | an explained error (bad path, bad config, unknown detector) |
| 3 | quarantine recommended, or verification failed |

## Declaring a reference distribution

The OOD detector is materially stronger with a declared reference. Without one
it scores against the dataset's own bulk and **says so** in the report — a
contributor supplying a large share shifts that reference towards itself.

```json
{ "samples": ["vehicle/alpha_000.jpg", "vehicle/alpha_001.jpg", "..."] }
```

```bash
cvtrust dataset scan /data/corpus --reference /secure/reference.json
```

## Calibration

With no calibration table, threshold-based detectors report
`HEURISTIC_UNCALIBRATED` confidence, capped at 0.60, and **cannot recommend
quarantine** (policy rule `D-110`). To obtain measured confidence:

```bash
./scripts/evaluate.sh                 # generates the lab and measures
cvtrust dataset scan /data/corpus --calibration reports/calibration.json
```

For a real deployment, regenerate the calibration against imagery
representative of your operating distribution. A table measured on the
synthetic corpus is a defensible lower bound on evidence quality, not an
operational guarantee — the report prints this alongside the table's provenance.

## Configuration

```bash
cp configs/default.yaml configs/site.yaml
cvtrust dataset scan /data/corpus --config configs/site.yaml
```

Every tunable that affects a finding is in the config, is hashed into
`config_hash`, and is serialised into the report. Unknown keys are **rejected**,
not ignored — a silently-ignored threshold is one the analyst believes is
active. There are no thresholds hard-coded in detectors.

## Optional CNN feature backend

Only for deployments that can vendor weights locally. Weights are never
downloaded; the extractor raises `DetectorUnavailable` with a precise message if
the file is absent, and records the file's SHA-256 in the report so the feature
space is itself an assured artifact.

```bash
./.venv/bin/pip install --no-index --find-links=wheelhouse 'cvtrust[torch]'
# then set features.extractor: torch_cnn and features.weights_path in your config
```

## Docker (optional, not required)

Docker is deliberately **not** mandatory: a container adds an image-distribution
problem to an air-gapped deployment. A native path is always available. If you
do containerise, run with `--network none` and mount datasets read-only.

## Repository layout on disk

```
cv-trust/
├── src/cvtrust/      the platform
├── tests/            unit · integration · adversarial · regression
├── docs/             architecture, threat model, research, coverage, ...
├── configs/          default.yaml
├── scripts/          setup.sh · demo.sh · evaluate.sh
├── attack_lab/       generated corpora and scenarios (not in version control)
└── reports/          generated reports (not in version control)
```
