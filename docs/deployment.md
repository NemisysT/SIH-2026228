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


---

## Module 2 — model runtimes in an air-gapped deployment

`onnx`, `onnxruntime` and `torch` are **optional extras**. Without them the
corresponding model formats are unavailable, and the pipeline reports
`NOT_ASSESSED` with a reason naming the missing package — never a crash, never a
silent pass.

Build a wheelhouse on a connected machine:

```bash
pip download -d wheelhouse -r requirements.txt
```

Transfer `wheelhouse/` and install offline:

```bash
python3 -m venv .venv
./.venv/bin/pip install --no-index --find-links wheelhouse -r requirements.txt
./.venv/bin/pip install --no-index --find-links wheelhouse -e .
```

Confirm what the deployment can actually assess:

```bash
./.venv/bin/cvtrust info
```

The tail of that output lists the model formats available in this environment.
If it says `none`, model assessment will report `NOT_ASSESSED` for every level
that needs a runtime, which is correct behaviour and not a failure.

### Which format to ask a supplier for

| Format | Gradients | Activations | Deserialisation risk |
|---|---|---|---|
| **ONNX** | ✗ | ✓ | Low — protobuf, no code execution |
| **TorchScript** | ✓ | ✗ | Low — no arbitrary Python globals |
| `torch.save` module pickle | ✓ | ✓ | **High — executes code on load; refused by default** |
| `torch.save` state dict | — | — | Low, but carries no graph: only parameter analysis is possible |

**Ask for ONNX *and* TorchScript.** Between them they cover every method: ONNX
gives activation access, TorchScript gives gradients. That is exactly what the
model attack lab exports for each scenario.

Never accept a module pickle from an untrusted supplier. If you must load one,
`--allow-unsafe-deserialisation` exists, it records the fact in the manifest,
and it should be used only inside a sandbox with no network.

### Benchmark artifacts

NIST TrojAI and BackdoorBench are never downloaded. Vendor them into a local
directory and point `model.benchmark_dir` at it — layout, licensing notes and
the `index.json` schema are in `docs/model-security.md` §8.

### Everyday model use

```bash
# Establish a baseline when you first accept a model.
cvtrust model manifest detector_v17.onnx --out baselines/detector_v17.json

# Re-verify before each deployment: catches post-assurance modification.
cvtrust model verify baselines/detector_v17.json /srv/models/detector_v17.onnx

# Full assessment of a newly supplied artifact against the trusted one.
cvtrust model assess /incoming/detector_v18.onnx \
    --reference /srv/models/detector_v17.onnx \
    --out reports/detector_v18.json --markdown-out reports/detector_v18.md
```

**Store baseline manifests on separate media from the artifacts they describe.**
Manifest self-tampering is detected, but an adversary with write access to both
could replace a manifest with a self-consistent forgery. Ed25519 signatures
arrive in Module 3; until then, separation is the control.
