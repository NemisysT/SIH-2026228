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
could replace a manifest with a self-consistent forgery. Module 3 makes signing
a manifest possible — its digest binds into a signed provenance record — but
`model manifest` and `dataset manifest` still write plain JSON, so **separation
remains the control**.

---

## Module 3 — inference provenance in an air-gapped deployment

Module 3 adds **no new dependencies and no new runtimes**. `cryptography` is
already a core requirement, and provenance verification binds Module 2's digests
rather than recomputing them, so it runs in a Module-1-only environment with no
ONNX or PyTorch installed.

It also adds no new network surface, which is where signing systems usually
acquire one. There is no certificate authority, no OCSP responder, no CRL fetch,
no key server and no RFC 3161 timestamp authority — and
`tests/security/test_offline.py` asserts that statically, by scanning the
provenance modules for those APIs, as well as dynamically.

### Provisioning a signing key

```bash
# On the SIGNING host (the one running inference).
cvtrust provenance keygen --out /secure/keys/signer.pem --label "edge-node-3"     --passphrase "$SIGNING_PASSPHRASE"
```

This writes a passphrase-encrypted PKCS#8 private key at mode `0600`, and a
`signer.pub.json` beside it. Without `--passphrase` the command **refuses**
unless `--allow-unencrypted` is passed: an unencrypted operational key should be
a decision someone made, not a default they inherited.

**State the assumption you are accepting.** This software cannot protect a
private key from a compromised host — it is a process reading a file, and an
adversary with code execution as the signing user can read the key or simply ask
this software to sign. A hardware token is the correct answer and is not
integrated. See `docs/cryptographic-model.md` §5.

### Provisioning trust — the step that matters most

```bash
# On the VERIFYING host. Carry signer.pub.json over by an INDEPENDENT channel.
cvtrust provenance trust add /media/courier/signer.pub.json     --store /secure/trust_store.json     --label "edge-node-3"     --purpose inference_provenance     --valid-from 2026-03-01T00:00:00Z     --provenance "hand-carried on write-once media; fingerprint read back by phone"
```

`--provenance` is free text and it is the most important field in the record.
**A trust store populated through the same channel that supplies the records
establishes nothing** — every signature would verify against keys the adversary
chose. The CLI warns when it is left empty, and the value is printed in every
finding's assumptions so a reviewer can judge the claim.

### Recording and verifying

```bash
# On the signing host, per inference.
cvtrust provenance record /data/frame_00417.png /tmp/output.json     --key /secure/keys/signer.pem --passphrase "$SIGNING_PASSPHRASE"     --log /var/log/cvtrust/provenance.jsonl     --model-manifest /secure/baselines/detector_v17.json

# Periodically, on the verifying host: take an anchor and store it where the
# signing host CANNOT write. This is the only thing that makes tail truncation
# detectable.
cvtrust provenance anchor /var/log/cvtrust/provenance.jsonl     --out /media/write-once/anchor-2026-03-01.json

# Verify.
cvtrust provenance verify-log /var/log/cvtrust/provenance.jsonl     --store /secure/trust_store.json     --anchor /media/write-once/anchor-2026-03-01.json     --replay-db /secure/replay.json     --model-manifest /secure/baselines/detector_v17.json     --out reports/provenance.json --markdown-out reports/provenance.md
```

Exit codes follow the same convention: `0` verified · `1` review · `2` explained
error · `3` compromised.

### What to protect, and why

| Artifact | Why it matters | If an adversary controls it |
|---|---|---|
| `signer.pem` | The signing key | They can emit records that verify against your trust store |
| `trust_store.json` | Which keys you authorise | They can authorise their own key; every forgery then verifies |
| `anchor-*.json` | The head digest | Tail truncation becomes undetectable again. **An anchor stored beside the log it anchors protects against nothing** |
| `replay.json` | What has already been seen | They can roll it back and every replay becomes first-seen |

The provenance log itself is the *least* sensitive of the five: it is what the
other four exist to verify, and tampering with it is what the module detects.

### Key rotation and revocation

```bash
# Rotate: add the successor, leave the predecessor trusted for the period it
# signed. Both verify; rotation is an ordinary state, not an outage.
cvtrust provenance trust add /media/courier/signer-2027.pub.json     --store /secure/trust_store.json --valid-from 2027-01-01T00:00:00Z     --provenance "hand-carried, annual rotation"

# Revoke: absolute, and effective only for verifications reading THIS store.
# There is no revocation service.
cvtrust provenance trust revoke <key_id> --store /secure/trust_store.json     --reason "signing host suspected compromised 2027-04-02"

cvtrust provenance trust list --store /secure/trust_store.json
```

One deployment decision to make deliberately: `provenance.validity_policy`.
`at_record_timestamp` (the default) honours rotation, and its weakness is exact —
a holder of a retired key also controls the timestamp, so an expired key can be
revived by backdating. `at_verification_time` is immune to that and invalidates
the entire history of every key that has ever expired. Whichever you choose is
recorded in every verification report.

### Storage planning

About **2.8 KB per record** (dominated by the inline canonical output, which is
what lets a record be verified against itself) and **~443 bytes per replay
observation**. A pipeline at one inference per second produces roughly 240 MB of
log and 38 MB of replay database per day.

Chain verification is O(n) and re-hashes every entry — 200 entries in ~11 ms —
so a log that grows without bound verifies proportionally more slowly. Anchor
and rotate logs rather than verifying less.
