# Architecture

## 1. What the system is

A unified **evidence pipeline** for assuring computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted. One
ingestion path, one evidence schema, one report, one coverage statement.

Modules 1 (datasets) and 2 (models) are implemented. Modules 3–5 attach to the
same schema and the same manifest identity; they are declared `NOT_ASSESSED`
in every report until they exist.

```
DATASET (untrusted)
   │
   ▼  DatasetAdapter          coco | yolo | folder — registry-based (ADR-001)
RawDataset + IngestIssue[]
   │
   ▼  ContributorResolver     sidecar > adapter-native > path-pattern > unknown
   │
   ▼  FeatureStore            one decode per image →
   │                          facts + pHash/dHash/aHash + 614-d embedding
   ▼  ManifestBuilder
DatasetManifest ──────────────► digest = DATASET IDENTITY  (Modules 2–5 bind here)
   │
   ▼  Detector[]  (fixed order — this is a dependency chain, not a preference)
   │     integrity          → metadata_inconsistency        DETERMINISTIC
   │     exact_duplicate    → duplicate_flood               DETERMINISTIC
   │     near_duplicate     → near_duplicate_flood          CALIBRATED
   │     ood                → ood_insertion                 CALIBRATED
   │     label_consistency  → label_flip                    CALIBRATED
   │     systematic_mislabel→ systematic_mislabel           STATISTICAL
   │
   ▼  Finding[]  (sample-level, each with recomputable observations)
   │
   ▼  ContributorAggregator  rate vs leave-one-out cohort, binomial + BH
   │
   ▼  DispositionPolicy      explicit rule table → ACCEPT | REVIEW | QUARANTINE
   │
   ▼  CoverageStatement      every known attack class, including Modules 2–5
   │
   ▼  AssuranceReport        JSON (machine) + console/Markdown (analyst)
                             + RunContext (reproducibility)
```

### Why the detector order is fixed in code, not configuration

```
exact_duplicate ─┐
near_duplicate  ─┴─► duplicate groups ──► label_consistency  (excluded from
                                          neighbourhoods, so flooding cannot
                                          manufacture agreement for a flip)

ood ───────────────► out-of-distribution set ──► label_consistency  (findings
                                          on those samples are qualified and
                                          severity-capped, with the reason
                                          recorded as evidence)

label_consistency ─► label suggestions ──► systematic_mislabel  (tested for
                                          directional structure)
```

These are real data dependencies. Making the order configurable would let an
operator silently disable the adversarial hardening.

## 1a. The model pipeline (Module 2)

A second entry point over the *same* evidence schema, calibration set,
disposition policy and coverage statement. It has its own context object because
a model assessment has no dataset, features or contributor attributions — but it
has no second `Finding` type, no second confidence system and no second
disposition policy, because those are properties of the system rather than of
its dataset half.

```
MODEL ARTIFACT (untrusted)
   │
   ▼  ModelAdapter            onnx | torchscript | torch — registry-based (ADR-001)
ModelHandle + Capability set  inference · graph · parameters · activations · gradients
   │
   ▼  ModelManifest
   │      file_sha256      ── identity of the ARTIFACT
   │      graph_digest     ── identity of the ARCHITECTURE (weight-blind)
   │      parameter_digest ── identity of the WEIGHTS       (container-blind)
   │
   ▼  ReferenceBattery       versioned + digested probes: clean · borderline ·
   │                         perturbation · OOD · declared trigger family
   │
   ▼  ModelDetector[]  (fixed order — a dependency chain, not a preference)
   │     model_identity    → model_substitution   DETERMINISTIC
   │     model_structure   → model_tampering      DETERMINISTIC
   │     model_parameters  → model_tampering      DETERMINISTIC / CALIBRATED
   │     model_behaviour   → model_tampering      CALIBRATED      ← publishes fingerprints
   │     model_activation  → model_backdoor       context only (measured, ADR-013)
   │     model_trigger     → model_backdoor       CALIBRATED
   │
   ▼  Finding[]  (the SAME schema Module 1 emits)
   │
   ▼  ModelAssessmentMatrix   six levels, never combined into one score (ADR-012)
   │
   ▼  DispositionPolicy       the same explicit rule table
   ▼  CoverageStatement       the same registry, now including Module 2 classes
   ▼  ModelAssuranceReport    JSON + console/Markdown + RunContext
```

### Why the model detector order is fixed in code

```
model_behaviour ─► behavioural fingerprints ──► model_activation  (class-conditional
                                                analysis needs the model's own
                                                predictions)
                └► targeted-transition metric ─► model_activation  (decides whether
                                                there is a signal worth localising)

model_identity ──► identity comparison ────────► model_structure   (qualifies severity)
```

The battery is forwarded once and the fingerprints are shared, so three
detectors cost one pass rather than three.

## 2. Package layout

| Package | Responsibility |
|---|---|
| `core/` | Evidence schema, canonical serialisation, hashing, config, run context, logging, registry. The schema here is frozen across all five modules. |
| `datasets/` | Adapters, contributor attribution, manifest construction and verification. Adapters report facts; they never decide what is suspicious. |
| `features/` | Perceptual hashes, the classical embedding, the optional CNN backend, and the single-pass feature store. |
| `detectors/` | Six detectors plus the framework that enforces the confidence and coverage contracts. |
| `risk/` | Statistics, calibration tables, contributor aggregation, disposition policy, coverage statement. |
| `reporting/` | The report model and its renderings. Human views are generated *from* the report object so the two cannot drift. |
| `models/` | **Module 2.** Model adapters (ONNX, TorchScript, torch), the three-digest manifest, the reference battery, behavioural fingerprinting, parameter statistics, activation analysis, trigger search, and optional local benchmark ingestion. |
| `attack_lab/` | Corpus generation, five reproducible dataset attacks, a fifteen-scenario model attack lab with its own CNN trainer, and both evaluation harnesses. |
| `cli/` | `typer` application. |

## 3. Design decisions that shape everything else

### ADR-001 — Adapter registry over hard-coded formats
The problem statement requires format-agnosticism. Adapters, feature extractors
and detectors are all looked up by name from a tiny explicit registry — no entry
points, no import scanning — so in an air-gapped deployment the set of loaded
components is exactly what the code imports and is auditable by reading one file.

### ADR-002 — One frozen `Finding` schema for all five modules
Enforced structurally: `Finding` requires at least one `EvidenceItem`, and
`EvidenceItem.observation` is a required non-empty mapping. **A score with no
recomputable observation cannot be represented in this system.** Tested.

### ADR-003 — Content-addressed finding IDs
`F-<12 hex>` derived from `(method, method_version, attack_class, asset,
discriminator)`. A positional counter shifts whenever an unrelated finding
appears, breaking cross-run diffing and analyst-held references. Scores,
severity and timestamps are deliberately *excluded* from the ID, so
recalibrating a detector updates a finding rather than creating a new one.

### ADR-004 — Float-free digest surface
`canonical_json` rejects `float` by default. RFC 8785 number canonicalisation is
implementable but subtle, and Module 3 will sign these structures — every
subtlety would become a signature-verification bug. Configuration, which
legitimately contains thresholds, is hashed through `digest_safe()`, which
rewrites floats as fixed-unit integers.

### ADR-005 — Classical deterministic embedding as the default feature space
Five independent views of each image — 16×16 structure, HSV histogram, gridded
gradient orientation, DCT low band, acquisition statistics — each L2-normalised
independently so every view contributes equally regardless of its
dimensionality. 614 dimensions, no weights, no network, bit-reproducible. The
acquisition block is what lets the OOD detector respond to a genuine sensor or
illumination change rather than only to content change.

### ADR-006 — Confidence must declare one of four bases
`DETERMINISTIC` (1.0, a verified fact) · `STATISTICAL` (`1 − q`, capped at 0.99)
· `CALIBRATED` (Wilson 95% lower bound of measured precision) ·
`HEURISTIC_UNCALIBRATED` (documented prior, capped at 0.60, and the finding is
*required* to carry the `uncalibrated` limitation). Enforced in the model's
validators, not by review.

### ADR-007 — Leave-one-out cohort baselines
A contributor is compared against the flag rate of **every other** contributor.
Including itself would let a contributor supplying most of the data raise the
baseline it is measured against — the more data an adversary submits, the harder
it would become to detect.

### ADR-008 — Data-side trigger detection deferred to Module 2
`trigger_injection` is listed in the coverage registry from day one as
`NOT_ASSESSED — owned by Module 2`. Detecting patch artifacts in training images
without the model-side counterpart (trigger reconstruction, activation
statistics) would be a partial capability presented as a complete one.

### ADR-009 — No blockchain
The problem statement's theme includes blockchain, and the honest architectural
answer is that a distributed ledger solves a problem this deployment does not
have.

A ledger buys **Byzantine agreement among mutually distrusting writers**. The
target deployment is a single air-gapped analyst authority: there is one writer
of assurance records, no need for distributed consensus, no network over which
to gossip blocks, and no second party whose disagreement about ordering must be
resolved. Adding consensus would add nodes, key distribution, fork resolution
and a synchronisation requirement that directly contradicts the air-gap.

What is actually required is **tamper-evidence** and **non-repudiation**, and
those are obtained without a ledger:

| Requirement | Mechanism (Module 1 → Module 3) |
|---|---|
| Artifact identity | SHA-256 over bytes, and separately over decoded content |
| Dataset identity | Manifest digest over canonical, float-free serialisation |
| Detect post-hoc modification | Re-derive and compare digests (`dataset verify`) |
| Non-repudiation of a record | Ed25519 detached signature over the digest (M3) |
| Detect record removal or reordering | Hash chain with sequence numbers (M3) |
| Efficient inclusion proof over many records | Merkle tree over the chain (M3, if justified by volume) |
| Detect replay | Nonce + monotonic sequence + signed timestamp (M3) |

This is the TUF/in-toto model: signed metadata *about* artifacts, with identity
separated from location. It gives the same detection properties the problem
statement asks for, offline, with no consensus layer. The manifest format is
already signature-ready — Module 3 attaches a signature over `digest` without a
schema change.

### ADR-010 — Three digests for a model, not one
`file_sha256` (artifact bytes), `graph_digest` (topology, shapes, dtypes — no
weight values) and `parameter_digest` (weight values, quantised so the digest is
independent of storage dtype). One digest cannot distinguish a re-serialisation
from a substitution, and an analyst who cannot make that distinction cannot act
on the report. This is the model analogue of Module 1's `file_sha256` /
`pixel_sha256` split, and the four-way interpretation table it supports is in
`docs/model-security.md` §3. Identity is never derived from a filename, path,
display name or declared version string — the lab's substitution scenario keeps
the reference's architecture name in its metadata specifically to keep that
honest.

### ADR-011 — Capabilities, not a white-box/black-box binary
`AccessMode` is reported, but the manifest also carries a fine-grained
capability set, because a binary would be a lie about the formats we support:
ONNX exposes weights and activations but **no input gradients**, so Neural
Cleanse cannot run on it; TorchScript exposes gradients but refuses forward
hooks, so activation capture cannot run on it. A detector declares the
capability it needs; an unmet capability yields `REQUIRES_WHITE_BOX` (the remedy
is more access) or `NOT_ASSESSED` (the remedy is a different export), and those
are kept distinct because conflating them sends the analyst after the wrong
thing.

Also recorded here: data-side `trigger_injection`, which ADR-008 deferred to
Module 2, **remains unimplemented**. Module 2 delivered the model side in full;
adding a dataset-image detector under a model-forensics brief would be scope
drift. It stays in the coverage registry as `NOT_ASSESSED` with a reason that
says exactly this, rather than the default "no detector reported on this class",
so the gap keeps its history.

### ADR-012 — An assessment matrix, never a trust score
Module 2 reports six levels — identity, structure, parameters, behaviour,
activation, trigger — as separate fields with a closed status vocabulary, and
the report schema has no `overall_score` field. A single "model trust = 72%"
is strictly less informative than

```
Identity: MISMATCH · Structure: CONSISTENT · Behaviour: 0.3% disagreement
Parameter: UNAVAILABLE · Backdoor: NOT_ASSESSED
```

because the second tells an analyst what to do next. The roll-up that does exist
is a worst-case precedence rule with a named rationale, not an average: one
confident HIGH-severity indicator among five quiet levels is exactly the case
that matters, and any mean would bury it. The vocabulary excludes `SAFE`
permanently, and a test asserts that no assertive field in any report says a
model is safe.

### ADR-013 — A method that does not work is demoted, not shipped
Two published methods were implemented faithfully and then **measured not to
discriminate** in this setting:

- spectral signatures and activation clustering, applied to a probe battery
  rather than the training set they were published for, produced a backdoored
  lift range lying *inside* the clean range — an earlier revision thresholded it
  and fired on a clean model while missing a backdoored one;
- Neural Cleanse's anomaly index, at six classes, gave a clean model a mask as
  small as a backdoored model's.

Neither was quietly deleted and neither was left firing. Each was demoted with
its measurement published: the activation level reports context at INFO severity
and never raises an independent finding, and the anomaly index is declared
uninterpretable below eight classes while its per-class ranking — which *is*
informative — is still reported as evidence. The numbers are in
`docs/model-security.md` §6, and the corresponding coverage entries carry them
as their stated reason.

This is the architectural commitment behind the whole project: a measurement
that contradicts a design is more valuable than the design, and hiding it would
make every other number in the system unbelievable.

## 4. Extension points

Adding a dataset format, feature space or detector requires no change to the
pipeline:

```python
# a new dataset format
class MyAdapter:
    name, version = "myformat", "1.0"
    @staticmethod
    def detect(root: Path) -> bool: ...
    def load(self, root: Path) -> RawDataset: ...
ADAPTERS.add("myformat", MyAdapter())

# a new dataset detector
class MyDetector:
    name, version = "mydetector", "1.0"
    attack_classes = ("my_attack_class",)
    def run(self, ctx: AnalysisContext) -> DetectorOutput: ...
DETECTORS.add("mydetector", MyDetector())

# a new MODEL format
class MyModelAdapter:
    name, version, model_format = "myformat", "1.0", "myformat"
    @staticmethod
    def detect(path: Path) -> bool: ...
    def load(self, path: Path, config=None) -> ModelHandle: ...
    def parameters(self, handle) -> tuple[ParameterTensor, ...]: ...
    def layers(self, handle) -> tuple[LayerInfo, ...]: ...
    def activation_layers(self, handle) -> tuple[str, ...]: ...
    def infer(self, handle, batch, *, capture=()) -> ModelOutput: ...
MODEL_ADAPTERS.add("myformat", MyModelAdapter())

# a new MODEL detector
class MyModelDetector:
    name, version = "mymodeldetector", "1.0"
    attack_classes = ("model_backdoor",)
    required_capabilities = (Capability.INFERENCE,)
    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput: ...
MODEL_DETECTORS.add("mymodeldetector", MyModelDetector())
```

A model adapter must declare an honest **capability set**: claiming a capability
it cannot deliver is the one failure the framework cannot catch for you, and it
would let a detector report a weaker method under a stronger name.

A new detector must: emit findings only via `FindingFactory.emit`, report a
`CoverageEntry` for each of its attack classes (including `NOT_ASSESSED` with a
reason when it cannot run), and register its attack classes in
`ATTACK_CLASS_REGISTRY` so the coverage statement stays complete.
