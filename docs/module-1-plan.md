# Module 1 Plan — Foundation + Dataset Forensics

**Project:** `cvtrust` — Trustworthy Computer Vision Integrity Assurance (SIH26228)
**Module:** 1 of 5 — Foundation + Training-Data Integrity
**Status:** design frozen for implementation
**Audience:** engineering + evaluating judges

---

## 1. Scope boundary (what Module 1 is and is not)

### In scope
Everything needed to ingest an untrusted computer-vision dataset, establish its cryptographic
identity, analyse it for the training-data integrity threats listed in the problem statement
(§2.1), aggregate sample-level evidence to contributor/batch/source level, and emit findings in
the common evidence schema that every later module will reuse.

### Explicitly out of scope for Module 1
| Capability | Deferred to |
|---|---|
| Model ingestion, model identity, behavioural fingerprinting, backdoor/trigger assessment | Module 2 |
| Data-side **trigger injection** detection | Module 2 (see ADR-008) |
| Inference manifests, signatures, hash-chained audit log | Module 3 |
| Reference-distribution *shift* characterisation, drift-vs-manipulation reasoning, cross-module evidence fusion | Module 4 |
| Web UI, assurance report viewer, demo orchestration | Module 5 |

Module 1 ships a **per-sample OOD detector** (required by §2.1 "out-of-distribution insertion").
It does **not** ship distribution-*shift* characterisation (§2.4) — that is a population-level
question and belongs to Module 4. The coverage matrix states this explicitly rather than
implying broader capability.

---

## 2. Threat model for Module 1

**Trust boundary:** the dataset root, its annotation files, and all contributor-supplied metadata
are **untrusted input**. The analyst's machine, the `cvtrust` code, and the reference/baseline
declaration are trusted.

**Adversary:** one or more contributors to a multi-contributor CV pipeline. They can add, modify,
duplicate, relabel, or re-source samples in their own submission. They know the dataset schema.
They may or may not know which detectors run.

**Adversary cannot** (Module 1 assumption): modify the analyst's config, the reference manifest,
or previously committed manifests without detection — manifest tampering is itself detected by
`cvtrust dataset verify`.

| # | Threat (PS §2.1) | Attack class id | Module 1 posture |
|---|---|---|---|
| T1 | Exact duplicate flooding | `duplicate_flood` | SUPPORTED — deterministic |
| T2 | Near-duplicate flooding | `near_duplicate_flood` | SUPPORTED — calibrated |
| T3 | Label flipping (random) | `label_flip` | PARTIAL — calibrated, feature-space dependent |
| T4 | Systematic mislabelling | `systematic_mislabel` | SUPPORTED — statistical test |
| T5 | Out-of-distribution insertion | `ood_insertion` | PARTIAL — calibrated, reference dependent |
| T6 | Trigger injection (data side) | `trigger_injection` | NOT_ASSESSED — Module 2 |
| T7 | Malformed / inconsistent annotation & metadata | `metadata_inconsistency` | SUPPORTED — deterministic |
| T8 | Dataset mutated after baseline | `dataset_tamper` | SUPPORTED — manifest re-verification |

---

## 3. Architecture

### 3.1 Data flow

```
dataset root (UNTRUSTED)
      │
      ▼
 DatasetAdapter        coco | yolo | folder            ← pluggable, registry-based
      │  Sample[]  (relpath, label(s), raw metadata)
      ▼
 ContributorResolver   sidecar > adapter-native > path-pattern > "unknown"
      │
      ▼
 ManifestBuilder       sha256(file) + sha256(pixels) + dims + label digest
      │  DatasetManifest  ──► manifest.digest = DATASET IDENTITY (used by Modules 2-5)
      ▼
 FeatureStore          perceptual hashes (aHash/dHash/pHash) + classical embedding
      │                deterministic, offline, no pretrained weights required
      ▼
 Detector[]            integrity | exact_dup | near_dup | label_consistency
      │                | systematic_mislabel | ood
      │  Finding[]  (sample-level, each carrying EvidenceItem[] with raw observations)
      ▼
 ContributorAggregator rate vs cohort baseline, one-sided binomial test, BH correction
      │  Finding[]  (contributor/batch-level, evidence refs → sample-level findings)
      ▼
 DispositionPolicy     explicit (severity × confidence × coverage) → ACCEPT/REVIEW/QUARANTINE
      ▼
 AssuranceReport       machine-readable JSON + human-readable Markdown/console
                       + CoverageStatement + RunContext (reproducibility)
```

### 3.2 Package layout

```
src/cvtrust/
├── core/        evidence schema, canonical JSON, hashing, config, run context, logging, registry
├── datasets/    DatasetAdapter protocol + coco / yolo / folder adapters, manifest builder
├── features/    FeatureExtractor protocol, perceptual hashes, classical embedding
├── detectors/   Detector protocol + six detectors
├── risk/        calibration tables, contributor aggregation, disposition policy, coverage
├── reporting/   JSON report, Markdown report, console renderer
├── attack_lab/  synthetic clean-dataset generator + 5 reproducible attacks + evaluation harness
└── cli/         typer application
```

### 3.3 Key interfaces

```python
class DatasetAdapter(Protocol):
    name: str; version: str
    def detect(root: Path) -> bool
    def load(root: Path, cfg) -> RawDataset          # Sample[] + class list + issues[]

class FeatureExtractor(Protocol):
    name: str; version: str; dim: int
    def extract(img: np.ndarray) -> np.ndarray       # deterministic

class Detector(Protocol):
    name: str; version: str
    attack_classes: tuple[str, ...]
    requirements: DetectorRequirements                # what it needs to run at all
    def run(ctx: AnalysisContext) -> DetectorOutput   # Finding[] + coverage + timings
```

A detector that cannot meet its requirements must return
`Coverage.NOT_ASSESSED` with a machine-readable `reason`, **never** silently return zero findings.
(This is the same graceful-degradation contract Module 2 uses for
`NOT AVAILABLE — WHITE-BOX ACCESS REQUIRED`.)

---

## 4. Evidence schema (frozen — all five modules use this)

```
Finding
├── finding_id          "F-<12 hex>"  deterministic content hash (see ADR-003)
├── schema_version      "1.0"
├── observed_at         UTC ISO-8601 (excluded from finding_id)
├── asset               AssetRef{type,id,locator,digest}
├── contributor         str | null
├── category            DATA | MODEL | INFERENCE | DISTRIBUTION | PIPELINE
├── attack_class        stable id, e.g. "near_duplicate_flood"
├── title               short human-readable statement
├── severity            INFO | LOW | MEDIUM | HIGH | CRITICAL
├── confidence          float in [0,1] — see §5, never a magic number
├── confidence_basis    DETERMINISTIC | CALIBRATED | STATISTICAL | HEURISTIC_UNCALIBRATED
├── evidence[]          EvidenceItem{kind, statement, observation{...}, refs[]}
├── method              detector name
├── method_version      detector version
├── assumptions[]       stated, machine-readable
├── limitations[]       stated, machine-readable
├── coverage            SUPPORTED | PARTIAL | NOT_SUPPORTED | NOT_ASSESSED | REQUIRES_WHITE_BOX
├── disposition         ACCEPT | REVIEW | QUARANTINE
└── disposition_rule    id of the policy rule that produced the disposition
```

`EvidenceItem.observation` holds the **raw measured values** (hamming distance, neighbour ids,
p-value, counts). An analyst can always recompute the claim from the observation. A finding with
a score but no reproducible observation is a bug, enforced by a schema test.

---

## 5. How confidence is produced (no magic scores)

Four, and only four, permitted bases:

| Basis | Meaning | Value |
|---|---|---|
| `DETERMINISTIC` | The claim is a verified fact, not an inference (SHA-256 equality, malformed JSON, out-of-bounds bbox). | 1.0 |
| `STATISTICAL` | Claim rests on a hypothesis test. | `1 − q` (BH-adjusted p), capped at 0.99 |
| `CALIBRATED` | Claim rests on a threshold whose empirical precision was **measured** on attack-lab scenarios. | Wilson 95% lower bound of precision in the score bin |
| `HEURISTIC_UNCALIBRATED` | No calibration table available for this detector version. | documented prior, capped at 0.60, and `limitations` gains `"uncalibrated"` |

Calibration tables are produced by `cvtrust evaluate`, stored as JSON with their own provenance
(scenario, N, seed, detector version, date) and loaded at scan time. **Stated limitation:**
calibration is measured on *synthetic* attack-lab data and is a lower bound on evidence quality,
not an operational guarantee. This is printed in every report.

Severity is orthogonal to confidence and comes from a documented, config-visible rule
(scale of the finding × consequence class), never from the same number as confidence.

---

## 6. Detector designs

| Detector | Signal | Established basis | Coverage |
|---|---|---|---|
| `integrity` | unreadable/truncated files, declared-vs-actual dims, dangling annotations, out-of-bounds bbox, unknown category, duplicate ids | schema validation | SUPPORTED |
| `exact_duplicate` | SHA-256 over file bytes **and** over decoded normalised pixels (catches re-encode) | cryptographic equality | SUPPORTED |
| `near_duplicate` | pHash (32×32 DCT, 64-bit) Hamming clustering via union-find, **second-stage** confirmation by classical-embedding cosine to suppress pHash false positives | Zauner 2010; standard two-stage retrieval | SUPPORTED |
| `label_consistency` | k-NN label disagreement in feature space (model-free Edited-Nearest-Neighbour family) + class-centroid Mahalanobis giving a *suggested* alternative label | Wilson 1972 ENN; Frénay & Verleysen 2014 | PARTIAL |
| `systematic_mislabel` | contributor × (declared label → suggested label) contingency table; one-sided binomial test of pair concentration vs cohort rate; Benjamini–Hochberg across all tested pairs | Benjamini–Hochberg 1995 | SUPPORTED |
| `ood` | Mahalanobis distance (Ledoit–Wolf shrunk covariance) + k-NN distance to declared reference set; threshold = cross-fitted quantile of reference scores → nominal FPR | Lee et al. 2018; Sun et al. 2022; Ledoit–Wolf 2004 | PARTIAL |

**Feature space (ADR-005):** the default embedding is a deterministic *classical* descriptor
(multi-scale grayscale thumbnail, HSV histograms, gradient-orientation histogram, DCT low-band,
Laplacian focus and noise statistics), L2-normalised per block. Reason: a pretrained CNN backbone
would require downloading weights, which violates the air-gapped requirement. A
`TorchvisionFeatureExtractor` is defined behind the same interface for deployments that vendor
weights locally; when weights are absent it reports `NOT_ASSESSED`, it never silently downloads.

---

## 7. Contributor / batch aggregation (PS §2.1 "do not merely flag individual samples")

For each (contributor, attack_class):

1. `k` = flagged samples, `n` = contributor's total samples.
2. Cohort baseline rate `p0` = flagged rate over **all other** contributors (leave-one-out, so a
   dominant malicious contributor cannot inflate its own baseline).
3. One-sided binomial test `H0: rate ≤ p0`; BH correction across all (contributor, class) tests.
4. Effect size = rate ratio `(k/n) / p0`.
5. Severity from effect size × absolute volume; confidence = `min(mean evidence confidence, 1 − q)`.
6. Contributor finding carries `refs` to every sample-level finding that fed it — full lineage.

---

## 8. Reproducibility

Every run records a `RunContext`: `run_id = sha256(canonical(config) ‖ dataset_digest ‖ seed)[:16]`,
seed, config hash, dataset manifest digest, software version, per-detector versions, platform,
UTC timestamp, wall-clock timings. Timestamps and timings are excluded from all digests, so two
runs over the same inputs produce a byte-identical report modulo an explicitly named volatile set
— asserted by a determinism test.

All randomness flows from a single seeded `numpy.random.Generator` obtained from the run context;
no module may call global RNG state.

---

## 9. Canonical serialisation (security-relevant — ADR-004)

`canonical_json()` produces UTF-8, key-sorted, whitespace-free JSON and **rejects floats by
default**. Structures that are hashed as identity (manifests, sample records, finding ids) are
float-free by construction: scores are carried as integers in fixed units where they must be
hashed. Rationale: RFC 8785 number canonicalisation is subtle and Module 3 will sign these
structures — a float-free digest surface removes the whole class of cross-platform
serialisation ambiguity. Reports (not signed in Module 1) may carry floats via `float_mode="repr"`.

---

## 10. Attack lab

`attack_lab/` scenarios are generated, never hand-authored:

- `synth` — procedural, seeded, offline clean dataset (6 classes, per-contributor acquisition
  style: exposure, noise, JPEG quality) exported simultaneously as folder / COCO / YOLO so every
  adapter is exercised by the same ground truth.
- Attacks: `duplicate_flood`, `near_duplicate_flood`, `label_flip`, `systematic_mislabel`,
  `ood_insertion`. Each writes `dataset/` (the only thing the detector sees) and a **sibling**
  `ground_truth.json` outside the ingestion root, plus `attack_config.json` with the exact seed
  and parameters.
- `evaluate` matches findings to ground truth per attack class and reports precision, recall, F1,
  FPR, detection latency and throughput, always annotated with the evaluation population.

---

## 11. Test strategy

| Layer | Examples |
|---|---|
| unit | canonical JSON rejects floats/NaN; pHash invariant to JPEG-90 re-encode and ±10% brightness, sensitive to object substitution; union-find correctness; Wilson bound; binomial aggregation math; adapter parsing incl. malformed input |
| integration | clean dataset → zero HIGH/CRITICAL findings; each attacked dataset → expected attack_class present with sample-level evidence traceable to the injected samples |
| adversarial | evade near-dup with strong augmentation → assert recall degrades **and** report still states PARTIAL coverage rather than claiming detection; low-rate label flip → assert measured recall matches documented number |
| negative | clean-dataset false-positive rate below documented bound |
| regression | golden report digest with volatile fields stripped |
| tamper | mutate a file after manifest creation → `dataset verify` fails with the exact sample and both digests |

---

## 12. Dependencies (runtime = offline)

Core: `numpy`, `scipy`, `scikit-learn`, `pillow`, `pydantic>=2`, `typer`, `rich`, `cryptography`,
`pyyaml`. Dev: `pytest`, `pytest-cov`.
No network access at runtime. No pretrained weights required. `cryptography` is pulled in now
because Module 3 needs Ed25519 and the manifest format must be signature-ready from the start.

---

## 13. Architecture decision records

- **ADR-001** Adapter registry over hard-coded formats — PS requires format-agnosticism.
- **ADR-002** Single frozen `Finding` schema across all five modules; enforced by a schema test.
- **ADR-003** Deterministic content-derived `finding_id` rather than a positional counter, so
  identical inputs yield identical ids across runs and machines.
- **ADR-004** Float-free digest surface; canonical JSON rejects floats by default.
- **ADR-005** Classical deterministic embedding as the default feature space; CNN backbone
  optional and never auto-downloaded.
- **ADR-006** Confidence must declare one of four bases; uncalibrated confidence is capped at 0.60.
- **ADR-007** Leave-one-out cohort baseline in contributor aggregation.
- **ADR-008** Data-side trigger detection deferred to Module 2 so that it is developed together
  with model-side backdoor assessment rather than as a partial capability.
- **ADR-009** No blockchain. Justification recorded in `docs/architecture.md`: a single-authority
  air-gapped analyst deployment has no Byzantine multi-writer consensus problem; hash-chained
  append-only logs plus Ed25519 signatures give tamper-evidence with far lower complexity.

---

## 14. Risks

| Risk | Mitigation |
|---|---|
| Classical embedding too weak to separate classes → label-flip recall poor | measure it; report the measured number; state the limitation; expose the optional CNN backend |
| Synthetic-data calibration mistaken for operational calibration | every report prints the calibration provenance and the limitation |
| O(n²) near-duplicate comparison at scale | packed-uint64 popcount in blocks + optional LSH banding prefilter; throughput benchmarked and reported |
| Over-claiming detection of poisoning | coverage matrix is a first-class artefact; NOT_ASSESSED is a valid, visible outcome |
