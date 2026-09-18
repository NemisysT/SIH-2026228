# Threat model

## 1. System and trust boundary

```
┌─────────────────────────── UNTRUSTED ────────────────────────────┐
│  dataset root: image files                                       │
│  annotation documents (COCO JSON, YOLO txt, directory names)     │
│  contributor sidecar and all contributor-supplied metadata        │
│  declared image dimensions, categories, identifiers, timestamps  │
└──────────────────────────────────────────────────────────────────┘
                                │  read-only
                                ▼
┌──────────────────────────── TRUSTED ─────────────────────────────┐
│  the analyst workstation and its filesystem                      │
│  the cvtrust code and its configuration                          │
│  the analyst's declared reference distribution                   │
│  previously established manifests held by the analyst            │
└──────────────────────────────────────────────────────────────────┘
```

The system reads the untrusted side and **never writes to it**. Nothing in the
dataset can alter the tool's configuration, thresholds or policy.

## 2. Adversary model

**Who.** One or more contributors to a multi-contributor CV pipeline, plus an
adversary with write access to the dataset after an integrity baseline has been
established.

**Capabilities.**
- Add, remove, modify, duplicate, relabel or re-source any sample in their own
  submission.
- Author the annotation records describing their submission.
- Author their own contributor/batch/source metadata (so attribution is a claim,
  not a fact — see §4).
- Full knowledge of this system: the detectors, the thresholds, the default
  configuration, and this document.
- Re-encode, strip metadata, and apply photometric and mild geometric edits.

**Explicitly assumed unable to.**
- Modify the analyst's configuration, policy or code.
- Modify or replace a manifest the analyst holds, without that being detected.
- Break SHA-256 collision resistance.
- Collude with the analyst.

**Goals.** Skew class balance; install a mislabelling bias; degrade the training
distribution; insert data from a different source; or alter the dataset after
sign-off without detection.

## 3. Threats, coverage and residual risk

| # | Threat | Attack class | Coverage | Mechanism | Residual risk |
|---|---|---|---|---|---|
| T1 | Exact duplicate flooding | `duplicate_flood` | SUPPORTED | SHA-256 over file bytes **and** over decoded pixels | None for exact matches. Any pixel change defeats it by design — T2 covers that. |
| T2 | Near-duplicate flooding | `near_duplicate_flood` | SUPPORTED | pHash Hamming clustering, confirmed in feature space, union-find | No invariance to rotation, reflection or heavy crop. **Tested and documented.** Low-entropy imagery raises false-positive pressure; stage 2 mitigates, does not eliminate. |
| T3 | Random label flipping | `label_flip` | PARTIAL | k-NN label disagreement + class-centroid margin | Feature-space dependent. Boundary samples produce the same evidence as flips. Recall falls as the flip rate rises, because flipped samples begin to form a consistent neighbourhood of their own. |
| T4 | Systematic mislabelling | `systematic_mislabel` | SUPPORTED | Directional concentration, binomial test, BH correction, leave-one-out baseline | A mapping applied uniformly by *every* contributor has no cohort baseline to stand out against. Significance is not intent. |
| T5 | Out-of-distribution insertion | `ood_insertion` | PARTIAL | Mahalanobis + k-NN + PCA residual against a declared reference; quantile thresholds | An adversary who matches the reference's low-level statistics is not detected. Requires a trustworthy declared reference; without one the detector self-references and **says so**. |
| T6 | Trigger injection (data side) | `trigger_injection` | NOT_ASSESSED | — | **Not assessed in this build.** Module 2 scope (ADR-008). |
| T7 | Malformed / contradictory metadata | `metadata_inconsistency` | SUPPORTED | Schema validation, declared-vs-actual dimensions, bbox bounds, category and identifier checks | Detects contradictions *within* the dataset. A consistent lie — annotations that are internally coherent but describe the wrong reality — is structurally valid and invisible here. |
| T8 | Post-baseline modification | `dataset_tamper` | SUPPORTED | `dataset verify`: re-hash against a held manifest; detects modified, missing and added files, and manifest self-tampering | Requires the analyst to hold a manifest from before the tampering. Until Module 3 signs it, a manifest stored alongside the dataset could be replaced wholesale — store it separately. |

## 4. Attribution is a claim, not a fact

Contributor metadata originates on the untrusted side, so an adversary could
attempt to launder its submissions into another contributor's risk profile.
Three mitigations:

1. **Precedence is explicit and recorded.** Every manifest record carries
   `attribution_source`: `sidecar` > `adapter_native` > `path_pattern` > `none`.
   An analyst can see that "contributor bravo" was inferred from a directory
   name rather than asserted.
2. **A filename is never an identity.** Path-pattern attribution is opt-in and
   off by default; an unattributed dataset resolves to `unknown` rather than
   guessing from paths. Tested.
3. **Sample-level evidence survives attribution failure.** Contributor
   aggregation can be diluted by spreading an attack across every contributor —
   by construction, there is then no cohort to stand out against. The report
   therefore carries **both** levels, and the sample-level findings remain.
   Tested (`test_spreading_an_attack_over_many_contributors_still_yields_findings`).

Module 3 makes the sidecar signable, at which point `sidecar_signed` becomes the
only strong attribution source. The mechanism now exists — a manifest digest can
be bound into a signed provenance record — but wiring contributor sidecars
through it is dataset-pipeline work that Module 3 did not undertake, so the
attribution posture above is unchanged in this build.

## 5. Attacks on the detectors themselves

| Evasion | Status |
|---|---|
| Re-encode to a different container to defeat byte hashing | **Detected** — content digest is independent of the container. Tested. |
| Strip metadata and re-encode at high quality | **Detected.** Tested. |
| Photometric perturbation (exposure, contrast, noise, variable JPEG quality) | **Detected**, ≥8/10 variants. Tested. |
| Flood near-copies of a flipped label to manufacture neighbourhood agreement | **Defeated** by excluding a query's perceptual duplicates from its neighbourhood. Tested. |
| Spread a campaign across all contributors to dilute aggregation | Contributor signal is lost by construction; **sample-level findings survive**. Tested. |
| Rotate or reflect near-duplicates | **Not detected.** Documented in the detector's `limitations` and asserted by a test, so the claim and the code cannot drift apart. |
| Mislabel an entire class uniformly | **Not detected.** Internally consistent. Documented and asserted by a test. |
| Submit a dataset too large for exact pairwise comparison | **Refused, not approximated.** Coverage becomes `NOT_ASSESSED` with a reason; the detector does not silently subsample. Tested. |
| Match the reference distribution's low-level statistics | **Not detected.** Stated residual risk for T5. |

## 6. Non-goals for this build

- Detecting backdoored models or reconstructing triggers (Module 2).
- Verifying inference records, replay or reordering (Module 3).
- Population-level distribution-shift characterisation, or distinguishing
  operational drift from deliberate manipulation (Module 4). Module 1 scores
  individual samples against a reference and **never asserts malice**.
- Authentication, authorisation, multi-tenancy, or protecting the analyst
  workstation itself.


---

## Module 2 — the model trust boundary

**Trust boundary.** The model artifact, every field of its embedded metadata,
its filename, its declared version string and its declared architecture name are
**untrusted input**. The analyst's machine, the `cvtrust` code, the
configuration, and the *reference model designation* are trusted.

**Adversary.** A party who can place a model artifact where the pipeline will
load it: a compromised model registry, a malicious supplier, an insider with
write access to the deployment, or a poisoned training pipeline upstream.

### Assumed adversary capabilities

| # | Capability | Posture |
|---|---|---|
| M1 | Replace the artifact wholesale | **SUPPORTED** — content identity |
| M2 | Re-serialise the same model so bytes differ but behaviour does not | **SUPPORTED** — distinguished from M1 by the three-digest design, severity-capped |
| M3 | Modify the graph after assurance | **SUPPORTED** with a reference |
| M4 | Modify a subset of weights after assurance | **SUPPORTED** with a reference, localised to named tensors |
| M5 | Retrain to produce different behaviour | **SUPPORTED** with a reference (behavioural divergence) |
| M6 | Install a patch backdoor by data poisoning | **SUPPORTED** for the declared family: measured P=1.00, R=1.00, FPR=0.00 |
| M7 | Use a low-opacity blended trigger | **PARTIAL** — outside the full-opacity family |
| M8 | Embed malicious code in a pickled artifact | **MITIGATED** — `weights_only=True` by default; a module pickle is refused |
| M9 | Lie in the artifact's declared metadata | **MITIGATED** — metadata plays no part in any identity decision, and the lab tests exactly this |

### Capabilities NOT defended against — stated up front

| # | Capability | Why |
|---|---|---|
| M10 | Sample-specific / input-aware triggers | The reconstruction searches for one **universal** mask; by construction it cannot find a per-input one. |
| M11 | Semantic backdoors (a real-world object as the trigger) | Not a perturbation, so neither the family probe nor the mask optimisation applies. |
| M12 | Triggers large by design | The `‖m‖₁` penalty that makes Neural Cleanse work is what makes it blind to these. |
| M13 | **Adaptive** backdoors optimised against these detectors | Regularising the reconstructed mask norm toward the clean population, or suppressing the spectral signature during training, are both documented in the literature and both succeed. |
| M14 | A compromised **reference** model | Every reference-dependent claim assumes the reference came through an independent channel. Unverified until Module 3 signs manifests. |
| M15 | Exploits in the deserialisation stack | ONNX protobuf, TorchScript and torch pickle are all parsed by third-party code, unsandboxed. Run assessments in a container or VM with no network. |

### Attacks on the model detectors themselves

- **Hiding behind a legitimate retrain.** A retrained clean model and a
  backdoored one both show identity MISMATCH, parameter ANOMALOUS and behaviour
  ANOMALOUS. Only the trigger level separates them — which is why the matrix
  reports six levels rather than one score, and why the trigger level's measured
  false-positive rate (0/9) is the number that matters.
- **Exploiting the probe family.** The declared trigger family is published, so
  an adversary can choose a trigger outside it. That is a real limitation, is
  stated in every trigger finding, and is the reason coverage for
  `model_backdoor` is `PARTIAL` rather than `SUPPORTED`.
- **Exploiting the low-class-count blind spot.** On a model with few classes,
  Neural Cleanse's index is uninterpretable, so an adversary attacking such a
  model faces only the family probe. Measured and documented, not hidden.
- **Poisoning the reference.** An adversary who controls the reference controls
  every comparison. Store reference artifacts and their manifests separately
  from the artifacts under assessment.

---

## Module 3 — the inference provenance trust boundary

**Trust boundary.**

```
┌─────────────────────────── UNTRUSTED ────────────────────────────┐
│  provenance records and the log file they live in                │
│  every field of every record, including timestamps and nonces    │
│  the producer label, the host label, all execution metadata      │
│  the declared model name and version inside a record             │
│  the public key carried in a signature envelope                  │
│  the input and model artifacts the records refer to              │
└──────────────────────────────────────────────────────────────────┘
                                │  read-only
                                ▼
┌──────────────────────────── TRUSTED ─────────────────────────────┐
│  the verifying host, its filesystem and its clock                │
│  the cvtrust code and its configuration                          │
│  the trust store, and the channel each key in it came through    │
│  the replay database                                             │
│  any log anchor the analyst holds                                │
│  expectations the analyst derived independently (M1/M2 manifests)│
└──────────────────────────────────────────────────────────────────┘
```

Note what sits on the untrusted side: **the public key in the envelope**. It is
read, it is used to check the signature, and it establishes nothing until the
trust store says so.

**Adversary.** Anyone who can write to a provenance log or the artifacts it
refers to: a compromised inference host, an insider with filesystem access, a
party in the transport path between the producer and the analyst, or a supplier
handing over a log after the fact. Two variants are modelled throughout, and the
distinction runs through every scenario in the lab:

- the **unprivileged** adversary can edit the log but holds no signing key;
- the **privileged** adversary holds a signing key — their own, a stolen one, or
  a revoked one — and can emit records that verify.

### Assumed adversary capabilities

| # | Capability | Posture |
|---|---|---|
| P1 | Edit any field of any record without a key | **SUPPORTED** — the signature covers the canonical bytes. `modified_input_digest`, `modified_timestamp`, `modified_nonce` |
| P2 | Swap the bound input digest and re-sign with their own key | **SUPPORTED** — `UNKNOWN_KEY`, plus `INPUT_MISMATCH` against the artifact the analyst holds |
| P3 | Swap the bound model digest and re-sign | **SUPPORTED** — same two mechanisms. `modified_model_digest` |
| P4 | Replace the model artifact on disk, leaving the log genuine | **SUPPORTED** — the expectation re-derived from disk contradicts every record. `modified_model_artifact` |
| P5 | Rewrite preprocessing or inference configuration | **SUPPORTED** — the configuration is canonicalised and bound, and the inline copy makes the record self-verifying |
| P6 | Rewrite the output | **SUPPORTED** — three independent checks fire |
| P7 | Delete, insert, reorder or duplicate records | **SUPPORTED** — hash-chain linkage plus contiguous sequence numbers |
| P8 | Strip or swap a signature on a chained record | **SUPPORTED** — `entry_digest` covers the envelope, not only the payload |
| P9 | Re-present a genuine signed record | **PARTIAL** — detected by the local replay database, bounded by its retention |
| P10 | Sign with a key the operator never authorised | **SUPPORTED** given a trust store; `NOT_ASSESSED` without one |
| P11 | Sign with a revoked key | **SUPPORTED** — and whether the record *claims* to predate the revocation is reported separately, as a claim |
| P12 | Backdate a record to fall inside a retired key's window | **PARTIAL** — see P17 |
| P13 | Declare a schema version the verifier does not implement | **SUPPORTED** — refused rather than guessed |
| P14 | Corrupt a log line to suppress verification of the rest | **SUPPORTED** — the loader keeps going and reports the line as a finding |
| P15 | Name a trusted `key_id` while carrying another key | **SUPPORTED** — `MALFORMED_SIGNATURE`, and the trust lookup is *not* performed on the declared id |
| P16 | Remove entries from the **front** of a log | **SUPPORTED** — genesis must carry a null back-pointer and sequence 0 |

### Capabilities NOT defended against — stated up front

| # | Capability | Why |
|---|---|---|
| P17 | **Tail truncation without an anchor** | A chain truncated at the end is internally perfect. No self-contained structure detects its own absence. With an anchor: **SUPPORTED**. Without: reported `NOT_DETECTABLE`, never clean |
| P18 | **Signing a record for an inference that never ran** | The record would be entirely valid. Binding proves the record *describes* these artifacts, not that a forward pass happened. Detecting this needs trusted execution, which this build does not implement |
| P19 | **Backdating under the `at_record_timestamp` policy** | The window is evaluated against the record's own clock, which a key holder also controls. `at_verification_time` is immune and invalidates every expired key's history instead; the policy is configurable and recorded in every verification |
| P20 | **A compromised signing host** | It can sign anything, correctly. File permissions and passphrases do not change this. An HSM is the right answer and is not integrated |
| P21 | **A trust store populated through the same channel as the records** | Every signature would verify against keys the adversary chose. This is *the* assumption the module rests on, and it is printed in every finding's assumptions |
| P22 | **A rolled-back or deleted replay database** | Every record becomes first-seen again. The database must be protected at least as well as the log it guards |
| P23 | **Seeing the replayed copy before the original** | A local database records the first presentation as original. Presentation order is not locally establishable |
| P24 | **Two verifiers with separate replay databases** | Each will accept a replay the other would catch. There is no shared state — a shared ledger is what ADR-009 declined |
| P25 | **Collision in SHA-256 or forgery against Ed25519** | Assumed hard. If either falls, every claim in this module falls with it |

### Attacks on the verifier itself

- **Denial of verification by one malformed byte.** A loader that aborted on a
  bad line would let an adversary hide every finding in the rest of a log with a
  single edit. The loader keeps going, counts the line, and reports it.
- **Borrowing a trusted key's status.** A forged envelope naming a trusted
  `key_id` while carrying another key would, under a naive implementation,
  resolve the declared id and report `key_trusted: PASS` for a record that key
  did not sign. The trust lookup is skipped entirely when the id does not
  fingerprint the carried key. `key_id_forgery` in the lab.
- **Making verification stop early.** No check short-circuits. A report showing
  one failure would otherwise not distinguish "the rest was clean" from "the
  rest was never examined".
- **Exploiting a missing input to look clean.** An absent trust store, replay
  database, anchor or expectation degrades the corresponding coverage to
  `NOT_ASSESSED` and downgrades any finding that depended on it to `REVIEW` via
  rule `D-000-not-assessed` — never to a pass, and never to a quarantine over an
  input the operator simply did not supply.
- **Quantisation-grid collision.** Two outputs closer than 10⁻⁶ share a digest.
  Measured, tested and documented; a deployment needing finer resolution raises
  `output_quantization_places`, which changes the record visibly.

### The one that is not a threat

**The same input legitimately processed twice.** Every real pipeline does this.
It produces one subject key and two records with distinct nonces, sequences and
signatures, and it is reported as `DUPLICATE_SUBJECT` at observation level —
never as replay. A detector that called this an attack would be switched off
within a day, and `legitimate_reprocess` in the lab asserts it produces zero
findings.

### Non-goals for this build

- Trusted execution, remote attestation, or any proof that a forward pass
  occurred (P18).
- Hardware-backed key storage (P20).
- Distributed consensus, shared ledgers or cross-verifier state (P24, ADR-009).
- Population-level distribution-shift analysis (Module 4).
- Any combination of a cryptographic verdict with an ML assessment (ADR-014).
