# Architecture

## 1. What the system is

A unified **evidence pipeline** for assuring computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted. One
ingestion path, one evidence schema, one report, one coverage statement.

Module 1 (this build) implements the dataset half. Modules 2–5 attach to the
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

## 2. Package layout

| Package | Responsibility |
|---|---|
| `core/` | Evidence schema, canonical serialisation, hashing, config, run context, logging, registry. The schema here is frozen across all five modules. |
| `datasets/` | Adapters, contributor attribution, manifest construction and verification. Adapters report facts; they never decide what is suspicious. |
| `features/` | Perceptual hashes, the classical embedding, the optional CNN backend, and the single-pass feature store. |
| `detectors/` | Six detectors plus the framework that enforces the confidence and coverage contracts. |
| `risk/` | Statistics, calibration tables, contributor aggregation, disposition policy, coverage statement. |
| `reporting/` | The report model and its renderings. Human views are generated *from* the report object so the two cannot drift. |
| `attack_lab/` | Corpus generation, five reproducible attacks, and the evaluation harness. |
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

## 4. Extension points

Adding a dataset format, feature space or detector requires no change to the
pipeline:

```python
# a new format
class MyAdapter:
    name, version = "myformat", "1.0"
    @staticmethod
    def detect(root: Path) -> bool: ...
    def load(self, root: Path) -> RawDataset: ...
ADAPTERS.add("myformat", MyAdapter())

# a new detector
class MyDetector:
    name, version = "mydetector", "1.0"
    attack_classes = ("my_attack_class",)
    def run(self, ctx: AnalysisContext) -> DetectorOutput: ...
DETECTORS.add("mydetector", MyDetector())
```

A new detector must: emit findings only via `FindingFactory.emit`, report a
`CoverageEntry` for each of its attack classes (including `NOT_ASSESSED` with a
reason when it cannot run), and register its attack classes in
`ATTACK_CLASS_REGISTRY` so the coverage statement stays complete.
