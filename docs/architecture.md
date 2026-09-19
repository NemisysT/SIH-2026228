# Architecture

## 1. What the system is

A unified **evidence pipeline** for assuring computer-vision pipelines whose
contributors, datasets, models and inference records are all untrusted. One
ingestion path, one evidence schema, one report, one coverage statement.

Modules 1 (datasets), 2 (models) and 3 (inference provenance) are implemented.
Modules 4–5 attach to the same schema and the same manifest identity; they are
declared `NOT_ASSESSED` in every report until they exist.

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

## 1b. The provenance pipeline (Module 3)

A third entry point over the same evidence schema, disposition policy and
coverage statement — and the first one that *consumes* the other two rather than
running beside them. It computes no dataset or model forensics of its own: it
binds Module 1's sample digests and Module 2's three model digests, so a
mismatch it reports and a mismatch `cvtrust model verify` reports are statements
about the same values.

```
PROVENANCE LOG (untrusted)          TRUST STORE        ANCHOR       REPLAY DB
   │  JSONL, one signed record       (analyst's)      (out of band)  (local)
   │  per line; unparseable lines         │                │             │
   │  are findings, not aborts            │                │             │
   ▼                                      │                │             │
verify_chain  ── FIRST, because a record's position is a property of the
   │             whole sequence, not of the record                       │
   │   linkage over entry_digest (payload + SIGNATURE, ADR-015)          │
   │   contiguous sequence numbers from genesis                          │
   │   truncation ── front: detected · tail: ONLY against an anchor ─────┤
   ▼                                      │                │             │
verify_record  per entry, with the chain result in hand    │             │
   │                                      │                │             │
   │   ┌─ the record alone ──────── schema · record id · self-consistency
   │   ├─ signature + trust store ── Ed25519 · key known · key trusted · │
   │   │                             window · purpose ─────┘             │
   │   ├─ the expectation ───────── input · model · config · output      │
   │   │      (from M1 sample digests and M2 manifests) ─────────────────┤
   │   └─ replay database ───────── exact · nonce · sequence · SUBJECT ──┘
   │      EVERY check runs. Nothing short-circuits.
   ▼
FailureCode[]  integrity | trust | context — three groups, three remedies
   │
   ▼  Finding[]  (the SAME schema, always DETERMINISTIC at 1.0 — ADR-014)
   │
   ▼  VerificationMatrix   per-check tallies; names the run's blind spots
   ▼  DispositionPolicy    the same explicit rule table
   ▼  CoverageStatement    the same registry, now including Module 3 classes
   ▼  ProvenanceReport     JSON + console/Markdown + RunContext
                           NO aggregate score, and there will not be one
```

### Why chain verification runs before record verification

A record's `previous_record_valid` and `sequence_valid` checks are answers about
its *position*, and a position is a property of the sequence. Verifying records
first and then the chain would leave every position check reporting
`NOT_CHECKED` in a log verification — the report saying it did not look at the
thing it was asked to look at.

The replay database is threaded through the record loop rather than consulted
once, because a log containing the same record twice must have the second one
flagged, and that is only visible if the first has already been recorded.

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

## 1c. The assurance engine (Module 4)

The fourth entry point, and the only one that produces no forensics of its own.
It characterises **population-level distribution shift**, then fuses the
findings the other three modules already emitted into one explicit, versioned
disposition — and the thing it most carefully does not do is add them up.

```
REFERENCE POPULATION              CURRENT POPULATION
  declared corpus, or a             the operating batch
  declared subset of the            under assessment
  current dataset (weaker,
  and recorded as weaker)
        │  build_features                  │  build_features
        ▼                                  ▼
  PopulationView ────────┬─────────── PopulationView
                         │
                         ▼  ShiftCharacterizer
        ┌────────────────────────────────────────────┐
        │ energy distance + permutation null  OMNIBUS│  ← the only test that
        │ mean displacement, per feature block       │    decides "shift"
        │ covariance, cross-fitted PCA + permutation │  supporting detail,
        │ marginal PSI + permutation + BH correction │  never decisive on
        │ class mix, Jensen-Shannon + permutation    │  its own
        └────────────────────────────────────────────┘
                         │  every metric: ASSESSED | INSUFFICIENT_SAMPLE
                         │                | NOT_ASSESSED
                         ▼  declared context vs observed block shares
                  ShiftAssessment   ── one of seven verdicts, never a score,
                         │             and never the word "attack"
   M1 report ─┐          │
   M2 report ─┼──────────┤  Finding[]  carried VERBATIM; Module 4 rewrites
   M3 report ─┘          │             nothing and re-verifies nothing
                         ▼  normalise      ← family, class, floors, lineage
                  NormalizedEvidence[]
                         ▼  build_graph    ← dependency groups, confounding
                   EvidenceGraph           ← a family contributes AT MOST ONE
                         │                   unit of independent support
                         ▼  AssurancePolicyEngine   23 explicit versioned rules
                  ScopeDecision × 4        ← dataset · model · provenance ·
                         │                   distribution, kept separate
                         ▼  strictest across scopes
                                QUARANTINE > REVIEW > NOT_ASSESSED > ACCEPT
                  AssuranceDecision        ← supporting · contradicting ·
                         │                   unassessed · lineage · rationale
                         ▼
           PipelineAssuranceReport  JSON + console/Markdown
                   NO aggregate score, and there will not be one
```

### Why shift is characterised before fusion

A population shift is an **active phenomenon**: it determines which other
evidence is confounded. A statistical label anomaly measured during a seasonal
change is not independent evidence of mislabelling, because the neighbourhood
structure the detector relies on has moved. The graph therefore cannot be built
until the shift verdict is known. Building it first and patching it afterwards
would make the confounding marks depend on the order the patches arrived in.

The converse matters just as much and is why `build_graph` takes
`extra_active_phenomena`: a shift the declared context *explains* raises only an
`INFO` finding, so it never clears the corroboration floor and would not mark
its own family as present — yet it still makes label neighbourhoods
unrepresentative. It is declared active explicitly so that an explained shift
keeps confounding without ever being able to corroborate.

### Why the disposition is the strictest scope, not the first match

Modules 1–3 use a first-match rule chain: the rules are ordered by severity and
the first one that fires wins. Module 4 cannot do that, because its four scopes
are four independent facts about four different artifacts. A first-match chain
would let whichever scope happened to be evaluated first speak for the others.

So every rule that fires, fires; each scope takes the strictest disposition
among its own fired rules; and the overall disposition is the strictest across
scopes, **with the scope named**. `NOT_ASSESSED` sits between `ACCEPT` and
`REVIEW` in that order, which has one deliberate consequence: an overall
`ACCEPT` requires every scope to have been assessed. Three clean scopes and one
missing report is `NOT_ASSESSED`, never `ACCEPT`.

### Why there is no weighting

There is no `dataset_weight`, no `model_weight`, no calibrated posterior over
"is this pipeline compromised". Such a model would need a joint prior over
attack classes, detector error rates measured on operational data, and an
independence structure — and this system has none of the three. What it has
instead is a rule table an analyst can read, argue with, and version. See
ADR-016.

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
| `provenance/` | **Module 3.** The canonical record schema, output and configuration binding, Ed25519 key lifecycle, the offline trust store, signing, record verification, the replay database, the hash-chained log and its anchor, and the performance benchmark. |
| `shift/` | **Module 4.** Population-level distribution-shift metrics with their permutation nulls, reference-population identity and contamination caveats, the declared-context explanation table, the characteriser and its finding factory. |
| `assurance/` | **Module 4.** Evidence families and the confounding table, evidence normalisation and the dependency-aware evidence graph, the 23-rule policy engine, the assurance decision, and the fusion orchestrator. |
| `attack_lab/` | Corpus generation, five reproducible dataset attacks, a fifteen-scenario model attack lab with its own CNN trainer, a twenty-eight-scenario provenance attack lab, a ten-pair population lab with fifteen end-to-end assurance scenarios, and all four evaluation harnesses. |
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

### ADR-014 — Cryptographic invalidity and ML suspicion never become one number

Module 3's findings are `DETERMINISTIC` at confidence 1.0, always. Modules 1, 2
and 4 produce `STATISTICAL`, `CALIBRATED` and `HEURISTIC_UNCALIBRATED`
confidences. **These are different kinds of evidence and the system never
combines them.**

The reason is that all four of these states are real and an analyst has to be
able to tell them apart:

```
model looks clean     + provenance valid     → the ordinary case
model looks clean     + provenance INVALID   → someone rewrote the account of it
model looks suspicious + provenance valid    → a genuine record of a bad model
model looks suspicious + provenance INVALID  → nothing here can be relied on
```

Any function that mapped these onto one scale would map rows 2 and 3 onto the
same value, and they call for opposite actions: row 2 is an integrity incident
with a clean artifact, row 3 is an artifact problem with a trustworthy audit
trail. So Module 3 carries its own attack classes, its own report schema with no
aggregate field of any kind, and a `DETERMINISTIC` basis enforced by the
`Finding` validator and asserted by a test. Its report object has no
`integrity_score`, no `trust_percentage`, and will not acquire one.

The corollary, which Module 3 also enforces: a check that *could not run* is
never a pass. An absent trust store, replay database, anchor or expectation
degrades that attack class to `NOT_ASSESSED`, and any finding depending on it is
dispositioned `REVIEW` by rule `D-000-not-assessed` — never quarantining a
pipeline over an input the operator simply did not supply, and never reporting
it clean either. The report's verification matrix lists every check that
produced neither a pass nor a fail on any record, so the run's blind spots are
printed rather than inferred.

### ADR-015 — The chained digest covers the signature, not only the payload

`entry_digest` is SHA-256 over `{"record": …, "signature": …}` together. The
obvious alternative — chaining the payload alone — has a specific hole: an
adversary who swaps a signature on an already-linked record leaves every
back-pointer matching, so the chain reports itself **intact** while carrying an
entry whose authenticity has changed. That entry's own signature check would
still fail, but a chain that reports itself intact over a tampered entry is
worse than no chain, because it is the field an operator reads first.

The cost is that the chain cannot be built before signing, which is no cost at
all: a producer signs and then appends, which is the order it would use anyway.
The `missing_signature` lab scenario exists to keep this decision honest — it
strips a signature mid-log and asserts the chain breaks.

### ADR-016 — Rule-based evidence fusion, never a universal trust score

Module 4's job is to combine evidence from four sources. The tempting shape is a
number: weight each module, sum, threshold. **That number does not exist and
this system does not produce one.**

Producing it honestly would require three things the project does not have:

1. a **prior** over how often each attack class occurs in a multi-contributor
   pipeline — unmeasurable without operational incident data;
2. **error rates** for each detector on operational data — the reason
   `HEURISTIC_UNCALIBRATED` exists as a basis at all (ADR-013);
3. an **independence structure** — and the detectors here are demonstrably
   dependent (ADR-017).

Absent all three, any weighting is a set of numbers chosen to make the demo look
right, presented with a precision it does not have. Worse, it is *unarguable*:
an analyst who disagrees with `trust = 0.62` has nothing to disagree with.

So fusion is a table of 23 rules, each with an id, a scope, its conditions, its
required evidence, its exclusions, its disposition and its rationale, all
printed in every report. An analyst who disagrees with a disposition can name
the rule. A reviewer can diff the table between versions. The policy version is
bound into the decision, the run context and the report digest, so two runs that
reached `ACCEPT` under different rule tables are not mistaken for the same
result.

The cost is real and is accepted: the rule table is coarser than a calibrated
model would be, and it cannot express "three weak signals together". That is
deliberate — see ADR-017 for why "together" is the hard part.

### ADR-017 — Dependency-aware evidence aggregation

Corroboration is the one aggregation the engine does perform, and the naive form
of it is wrong. Five near-duplicate detectors that all fire on the same cluster
are five reports of **one** phenomenon, not five independent observations. A
rule that required "two or more detectors" would be satisfied by a single noisy
family.

Every attack class is therefore mapped to an **evidence family** (`FAMILY_OF`),
and a family contributes **at most one unit of independent support** regardless
of how many findings or detectors it contains. `independent_family_count` is a
count of distinct phenomena, and the report says in as many words that it is not
a score and is never combined with severity or confidence.

A second table, `CONFOUNDED_BY`, records the one confounding relationship the
project can actually justify: `DATASET_LABELLING` is confounded by
`DISTRIBUTION_SHIFT`, because the leave-one-out neighbourhood statistic that
detects label anomalies assumes a stable feature distribution. Every other entry
is empty, on purpose — a confounding table populated by intuition would silence
real findings.

The limitation is stated in every report: **independence is decided by a curated
table, not measured.** Two detectors correlated in a way the table does not
record would still be counted as two phenomena. Publishing the table is what
makes that assumption challengeable rather than hidden.

### ADR-018 — Distribution shift is never evidence of manipulation

The single most damaging rule this system could contain is `shift detected →
attack`. Terrain, season, sensor, illumination and collection-protocol changes
are the *normal condition* of a surveillance or reconnaissance pipeline, and
they produce the same feature-space signature as a deliberate insertion.

No rule in the policy escalates on shift alone. The strongest statement the
distribution scope can make is `REVIEW`, and that is reserved for a shift the
declared operational context does not account for — which is an *open question*,
phrased as one. Any `QUARANTINE` in a run that also observed a shift came from
another scope's own evidence, and the report names that scope.

The symmetric error is also avoided. Consistency between an observed shift and a
declared change is **not confirmation** of that change: a manipulation
engineered to move the same feature views would be reported identically. The
declaration is a claim by the supplying side and is marked
`declaration_validated: false` in every explanation.

Two measurements forced the current design and are recorded here because they
are the reason the thresholds are what they are:

- An in-sample PCA basis made **every** current population look contracted
  (log-determinant ratio −2.35 on two independent clean draws). Cross-fitting
  the basis — fit on half the reference, compare the held-out half — moved it to
  +0.56, and the fixed threshold was then replaced by a permutation null.
- The conventional PSI band of 0.25 fired on a clean pair at 0.37. Measured on a
  clean reference split in half, max-PSI across 23 quantities had mean 0.49 and
  p95 0.65. The band is retained as a **label only**, documented as unvalidated
  folklore, and the decision is made by a permutation null with a
  Benjamini–Hochberg correction.

### ADR-019 — Coverage-aware disposition: NOT_ASSESSED outranks ACCEPT

A scope with no input is `NOT_ASSESSED`, never `ACCEPT`, and `NOT_ASSESSED` sits
above `ACCEPT` in the strictness order. The consequence is deliberate: **an
overall `ACCEPT` requires all four scopes to have been assessed.**

This is the cheapest attack available in a multi-contributor pipeline — withhold
the report rather than forge one — and the disposition vocabulary is the defence.
Three green scopes must not average away the fourth's absence.

The gap is reported at two granularities: the scope, with a remedy naming the
command that would close it, and each individual attack class left open. A
pipeline with major unassessed attack classes is not equivalent to a
comprehensively assessed clean one, and the report does not present it as
equivalent.

`NOT_ASSESSED` sits *below* `REVIEW` and `QUARANTINE` for the same reason: a
missing model report must not soften a broken hash chain into "incomplete".

### ADR-020 — Cryptographic evidence stays deterministic inside fusion

ADR-014 keeps Module 3's `DETERMINISTIC` findings out of any arithmetic. Module
4 adds two properties that the corroboration machinery made necessary.

**Deterministic evidence is exempt from the confidence floor.** The floor exists
to stop weak statistical evidence driving a disposition. A failed signature
check has no "confidence" to be weak — it is a fact — so applying the floor to it
would turn the operator's noise-suppression knob into a switch for turning off
the cryptography. Raising `corroboration_min_confidence` to 0.99 and
`corroboration_min_severity` to `CRITICAL` leaves a broken chain quarantined,
and a test asserts exactly that.

**A cryptographic failure is never transformed into a probability.** Nothing in
Module 4 maps a `DETERMINISTIC` finding onto a statistical scale, and the
`Finding` schema refuses a `DETERMINISTIC` finding at any confidence other than
1.0 — so a report edited to read "signature check, 0.4 confidence" is rejected at
load time rather than fused.

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
