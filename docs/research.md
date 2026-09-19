# Research notes

Every non-trivial detector in this system is an adaptation of established work,
not an invention. This file records, per method: what it originally did, what it
assumes, what it needs, its access requirement, its strengths and weaknesses,
and the implementation decision we took. Methods we *considered and rejected*
are recorded too — a rejected method with a stated reason is more useful to a
reviewer than a silent omission.

Research was performed during development. **Runtime is air-gapped**: nothing in
this list requires a network call, a hosted service, or downloaded weights.

---

## Standards and frameworks consulted

| Source | What we took from it |
|---|---|
| **NIST AI RMF 1.0** (Jan 2023) — `Map`, `Measure`, `Manage`, `Govern` | The insistence that a risk claim is only meaningful alongside its measurement context. Drove the requirement that every metric carries its evaluation population, and that coverage/limitations are first-class report artifacts rather than prose. |
| **IARPA/NIST TrojAI** | Its framing of backdoor detection as an evaluated task with declared model-access assumptions. Drove the `Coverage` enum including `REQUIRES_WHITE_BOX`, present in the schema from Module 1 although Module 2 owns the methods. |
| **BackdoorBench** (Wu et al., NeurIPS 2022 Datasets & Benchmarks) | The discipline of pairing every attack with a reproducible configuration and a matched evaluation. Drove the `attack_lab/` structure: `dataset/` + `ground_truth.json` + `attack_config.json`. |
| **TUF — The Update Framework** | Signed metadata *about* artifacts, distinct from the artifacts themselves; separation of artifact identity from artifact location. Drove the manifest design and ADR-004 (float-free digest surface), and the rule that a path is never an identity. |
| **in-toto** / **SLSA** | Attestation of each step in a supply chain. The manifest is the Module 1 attestation; Module 3 signs it and chains inference records to it. |
| **RFC 8785 — JSON Canonicalization Scheme** | Canonical serialisation. We adopt the key-ordering, whitespace and UTF-8 rules and deliberately **diverge** on numbers: floats are rejected on the digest path rather than formatted per ECMAScript `Number::toString`. Rationale in ADR-004. |
| **MITRE ATLAS** | Adversary-technique vocabulary for the threat model's attack classes. |

---

## Method cards — implemented

### 1. Perceptual hashing (pHash / dHash / aHash)

- **Origin**: Zauner, C. (2010), *Implementation and Benchmarking of Perceptual
  Image Hash Functions*. DCT-based image hashing for content identification.
- **Original purpose**: near-duplicate image retrieval and copy detection.
- **Assumptions**: images are compared at the same orientation and framing;
  content, not geometry, is the thing being matched.
- **Inputs required**: decoded pixels only.
- **Access**: black-box; no model involved.
- **Strengths**: cheap, exact (no training), robust to re-encoding, exposure
  change and mild rescaling. The DCT low band is the most robust of the three.
- **Weaknesses**: no invariance to rotation, reflection, heavy crop or
  geometric warping. Low-entropy images (uniform sky, sea, sand) produce
  colliding hashes and therefore false positives.
- **Implementation decision**: implemented from first principles
  (`features/perceptual.py`) rather than via `imagehash`, so that the transform
  is pinned (LANCZOS resampling, fixed DCT size, DC coefficient excluded) and
  the hash is bit-reproducible across machines. The DC coefficient is dropped
  because it encodes only mean brightness — keeping it would make the hash
  sensitive to exactly the edit we want to be blind to. Weakness on
  low-entropy content is mitigated by a **second confirmation stage** in the
  feature space (below), and the rotation limitation is asserted as a test
  (`tests/adversarial/test_evasion.py::test_rotation_defeats_near_duplicate_detection_as_documented`)
  so the code and the documented claim cannot drift apart.

### 2. Two-stage near-duplicate confirmation

- **Origin**: standard practice in large-scale image retrieval — a cheap
  high-recall candidate generator followed by an independent verification step.
- **Original purpose**: precision recovery in retrieval pipelines.
- **Assumptions**: the two stages fail independently.
- **Access**: black-box.
- **Strengths**: turns pHash's high-recall/low-precision behaviour into
  something reportable. Both stages appear in the evidence, so an analyst sees
  two independent measurements, not one score.
- **Weaknesses**: independence is an assumption, not a proof; both stages share
  the same decoded pixels.
- **Implementation decision**: stage 1 is exact all-pairs pHash Hamming (not
  LSH — see §"Rejected"), stage 2 is cosine similarity in the classical feature
  space, which examines colour, gradient and acquisition statistics that pHash
  discards. Clusters are connected components over confirmed pairs (union-find),
  because a chain of small perturbations is exactly what a flooding adversary
  produces and pairwise reporting would understate the injected group size.
  Measured stage-2 rejection rate is reported in the detector's stats.

### 3. Neighbourhood label agreement (Edited Nearest Neighbour family)

- **Origin**: Wilson, D. L. (1972), *Asymptotic Properties of Nearest Neighbor
  Rules Using Edited Data*, IEEE Trans. SMC. Surveyed for label noise in
  Frénay, B. & Verleysen, M. (2014), *Classification in the Presence of Label
  Noise: A Survey*, IEEE TNNLS.
- **Original purpose**: removing mislabelled or borderline training instances to
  improve a k-NN classifier.
- **Assumptions**: samples of the same class are nearer each other than samples
  of different classes, in the chosen feature space.
- **Inputs required**: features and labels. **No model.**
- **Access**: black-box; needs no model at all.
- **Strengths**: model-free, explainable (the analyst can be shown the
  disagreeing neighbours), and produces a *suggested* alternative label that is
  actionable.
- **Weaknesses**: entirely dependent on the feature space; fires on genuinely
  ambiguous boundary samples; cannot detect a uniformly mislabelled class,
  because such a class is internally consistent.
- **Implementation decision**: chosen over **Confident Learning** (below)
  specifically because it needs no model. Module 1 assures datasets; a model is
  an untrusted artifact that Module 2 assesses, so using one here would make
  dataset assurance depend on an unassured artifact. Distance weighting
  (`1/(d+ε)`) is used so a close disagreeing neighbour outweighs a distant one,
  which matters at class boundaries where unweighted voting is near a coin flip.
  Corroborated by an independent class-centroid margin. **Adversarial
  hardening:** a query's perceptual near-duplicates are removed from its
  neighbourhood, because otherwise an adversary flips one label, floods
  near-copies carrying the same wrong label, and the neighbourhood agrees with
  itself. That specific attack is tested.

### 4. Confident Learning — *considered, deferred*

- **Origin**: Northcutt, C., Jiang, L. & Chuang, I. (2021), *Confident
  Learning: Estimating Uncertainty in Dataset Labels*, JAIR 70.
- **Original purpose**: find label errors using a model's out-of-sample
  predicted probabilities and a class-conditional noise model.
- **Assumptions**: access to well-calibrated cross-validated predicted
  probabilities from a model trained on the dataset.
- **Access**: needs a trained model.
- **Strengths**: substantially stronger precision/recall than neighbourhood
  methods; principled class-conditional noise estimation.
- **Weaknesses**: requires training a model on data we are being asked to
  distrust; the model's own integrity is unassessed at Module 1.
- **Implementation decision**: **not implemented in Module 1.** Recorded here
  because it is the obvious next step once Module 2 can vouch for a model's
  integrity: a cross-validated model trained on the *assured* subset would let
  the label detector move from PARTIAL to a stronger claim. Noted in
  `docs/limitations.md` as the known path to better label-flip recall.

### 5. Directional label concentration + Benjamini–Hochberg

- **Origin**: Benjamini, Y. & Hochberg, Y. (1995), *Controlling the False
  Discovery Rate: A Practical and Powerful Approach to Multiple Testing*,
  JRSS-B. Binomial testing is textbook.
- **Original purpose**: FDR control across large families of hypothesis tests.
- **Assumptions**: under the null, contributors are exchangeable and mislabel
  any given ordered class pair at comparable rates.
- **Inputs required**: label suggestions plus contributor attribution.
- **Access**: black-box.
- **Strengths**: separates *systematic* mislabelling from *random* flipping,
  which no per-sample check can do — every individual label in a systematic
  mapping is plausible. Fully explainable: `k`, `n`, `p0`, rate ratio, `p`, `q`
  all appear in the evidence, so the arithmetic is checkable.
- **Weaknesses**: inherits the label detector's feature-space dependence; a
  mapping applied uniformly by *every* contributor has no cohort baseline to
  stand out against; statistical significance is not intent.
- **Implementation decision**: one-sided binomial test per
  (contributor, declared→suggested) pair against a **leave-one-out** cohort
  baseline (ADR-007) — a dominant malicious contributor must not be allowed to
  inflate the baseline it is measured against. BH correction across all tests in
  the run, because a dataset with many contributors and classes runs hundreds of
  tests and multiplicity alone would manufacture findings. A null rate of zero
  is floored, because "infinitely significant" is not an honest output.

### 6. Mahalanobis distance for OOD

- **Origin**: Lee, K., Lee, K., Lee, H. & Shin, J. (2018), *A Simple Unified
  Framework for Detecting Out-of-Distribution Samples and Adversarial Attacks*,
  NeurIPS.
- **Original purpose**: OOD detection using class-conditional Gaussians fitted
  to a deep network's features.
- **Assumptions**: the reference distribution is approximately Gaussian in the
  chosen feature space; the covariance estimate is well-conditioned.
- **Inputs required**: a declared reference feature set.
- **Access**: black-box with respect to any model (we use our own features).
- **Strengths**: a single interpretable number in the reference's own geometry;
  cheap.
- **Weaknesses**: a single Gaussian cannot express a multi-modal reference
  distribution; a 614-dimensional covariance from a few hundred samples is
  singular without regularisation.
- **Implementation decision**: applied to a **reference-fitted PCA projection**,
  with covariance estimated by Ledoit–Wolf shrinkage. PCA is fitted on the
  reference set *only* — fitting on the whole dataset would let inserted samples
  define the very subspace used to judge them.

### 7. Ledoit–Wolf covariance shrinkage

- **Origin**: Ledoit, O. & Wolf, M. (2004), *A well-conditioned estimator for
  large-dimensional covariance matrices*, J. Multivariate Analysis.
- **Original purpose**: well-conditioned covariance estimation when
  dimension is comparable to sample count.
- **Implementation decision**: used via `sklearn.covariance.LedoitWolf`. Its
  one non-obvious consequence drove a real bug fix: the shrinkage intensity
  depends on `n`, so a Mahalanobis threshold derived from K-fold fits is on a
  *different scale* from scores produced by a full fit. See §"Measured
  corrections" below.

### 8. k-NN distance for OOD

- **Origin**: Sun, Y., Ming, Y., Zhu, X. & Li, Y. (2022), *Out-of-Distribution
  Detection with Deep Nearest Neighbors*, ICML.
- **Original purpose**: non-parametric OOD detection by distance to the k-th
  nearest in-distribution neighbour.
- **Assumptions**: the reference set samples the in-distribution manifold
  densely enough for distance to be meaningful.
- **Strengths**: makes no distributional assumption; catches samples at a normal
  Mahalanobis radius that sit in a region the reference never populates.
- **Weaknesses**: scales with reference density, so its scores are not
  comparable across differently-sized reference sets (see §"Measured
  corrections").
- **Implementation decision**: mean distance to the `k` nearest reference
  points in the same reference-fitted PCA space, `k` configurable.

### 9. PCA reconstruction residual for OOD

- **Origin**: classical subspace anomaly detection (reconstruction error against
  a PCA subspace fitted to normal data); the same idea underlies subspace-based
  novelty detection across domains.
- **Original purpose**: novelty detection where anomalies lie outside the
  normal subspace.
- **Assumptions**: the reference distribution occupies a lower-dimensional
  subspace and anomalies have energy outside it.
- **Implementation decision**: **added after measurement, not by intuition.**
  Reducing dimension before measuring distance discards exactly the directions
  in which the reference set has no variance — and a genuinely different
  acquisition process (different sensor band, different optical train) differs
  precisely there. Measured on this build's attack lab, Mahalanobis + k-NN
  alone gave out-of-distribution **recall 0.00 at AUROC ≈ 0.75**: the ranking
  survived, the decision did not. Adding the residual term took recall to
  **1.00 at AUROC ≈ 1.00**. This is the clearest example in the project of why
  the evaluation harness exists.

### 10. Quantile-derived thresholds with cross-fitting

- **Origin**: standard practice in conformal/empirical-calibration settings;
  cross-fitting to avoid in-sample optimism is textbook.
- **Implementation decision**: each OOD threshold is the `1 − α` quantile of
  **cross-fitted** reference scores, so it has a stated meaning ("flags at most
  α of reference-distribution samples") instead of being a chosen constant. The
  per-method rate is Bonferroni-corrected by the number of methods, because a
  sample is flagged if *any* method exceeds its threshold and three
  uncorrected 1% tests give roughly 3%. Measured clean-corpus false-alarm rate
  after correction: **0.89% against a 1.0% target** (336 samples).

### 11. Wilson score interval for calibrated confidence

- **Origin**: Wilson, E. B. (1927), *Probable Inference, the Law of Succession,
  and Statistical Inference*, JASA.
- **Original purpose**: interval estimation for a binomial proportion.
- **Strengths**: stays inside [0, 1] and behaves correctly at `k = 0` and
  `k = n`, both of which occur routinely in a small calibration bin. The normal
  approximation does neither.
- **Implementation decision**: `CALIBRATED` confidence is the **95% lower
  bound** of the measured precision in the score bin, not the point estimate.
  A bin supported by 4 observations therefore yields visibly weaker confidence
  than one supported by 400 — which is the honest behaviour when calibration
  comes from a small synthetic run.

---

## Method cards — Module 2 (model forensics)

Module 2 implements **four** backdoor-relevant methods, chosen for being
well-understood rather than impressive, plus the identity and behavioural
machinery around them. Two of the four turned out **not to work in this
setting**, and their cards say so with the measurement; that is the point of
keeping cards for rejected and failed methods rather than only successful ones.

### 12. Neural Cleanse — trigger reconstruction

- **Origin**: Wang, B., Yao, Y., Shan, S., Li, H., Viswanath, B., Zheng, H. &
  Zhao, B. Y. (2019), *Neural Cleanse: Identifying and Mitigating Backdoor
  Attacks in Neural Networks*, IEEE S&P.
- **Original purpose**: detect a backdoor by finding, per class, the minimal
  input perturbation that forces that class, and flagging the class whose
  minimal perturbation is anomalously small.
- **Threat model / attack assumptions**: a *universal, static patch* trigger
  installed by data poisoning; one target class; the trigger is small relative
  to the input.
- **Model architecture assumptions**: differentiable, with enough classes for a
  MAD statistic over per-class mask norms to be stable. The paper's smallest
  evaluated dataset has 10 classes.
- **Required access**: **white-box with input gradients.** This is the binding
  constraint — ONNX Runtime does not differentiate, so this method cannot run on
  an ONNX artifact.
- **Required data**: a set of clean inputs. No labels needed.
- **Computational cost**: one optimisation per candidate class. Measured here:
  ~6.4 s for 6 classes × 300 steps on a single CPU core.
- **Strengths**: the only implemented method that *reconstructs* a trigger
  rather than testing for one it already knows. Not limited to a declared
  family.
- **Weaknesses**: blind to sample-specific, semantic and large-by-design
  triggers — the ``‖m‖₁`` penalty that makes it work is what makes it blind.
  The paper itself reports false positives on clean models whose classes are
  close in input space.
- **Known failure cases**: adaptive backdoors trained to keep the reconstructed
  mask norm inside the clean range; low class counts (below).
- **Implementation decision**: implemented, **including the paper's dynamic λ
  scheduler**, which is not optional. With a fixed penalty each class converges
  to whatever its own loss landscape allows, per-class norms are not comparable,
  and the MAD is dominated by that incomparability — measured here, a fixed
  penalty gave the true backdoor class an anomaly index of **1.31**, below the
  threshold of 2, a miss. With the schedule the ranking becomes correct on every
  backdoored model (true target has the smallest mask, by 5–50×).
  **But the index still does not discriminate at 6 classes**: the clean
  `clean_retrain_0` has a class with mask L1 6.8 at success 1.00, against the
  backdoored model's 5.9 at 1.00. So the implementation declares the index
  **uninterpretable below 8 classes**, reports the per-class ranking as evidence
  instead, and flags nothing. Full numbers in `docs/model-security.md` §6.2.

### 13. Gradient-free trigger-family probe

- **Origin**: our adaptation of the BadNets threat model (Gu, T., Dolan-Gavitt,
  B. & Garg, S., 2017, *BadNets: Identifying Vulnerabilities in the Machine
  Learning Model Supply Chain*) to a black-box sweep. **Not a published
  detection method**, and labelled as such everywhere it appears.
- **Original purpose**: n/a — the *attack* is published; the sweep is ours.
- **Threat model**: a patch trigger from a declared, finite family.
- **Required access**: `inference` only. Works under full black-box access,
  which is what makes the black-box pathway able to say anything about
  backdoors at all.
- **Required data**: clean probes, supplied by the battery.
- **Computational cost**: one forward pass per (family member × clean probe).
  Measured: ~20 ms for a 7-member family over 24 probes.
- **Strengths**: cheap, interpretable, and — measured — the **strongest backdoor
  signal in this build**: P=1.00, R=1.00, FPR=0.00 over 15 lab models, with
  clean models at attack success 0.000–0.083 and backdoored at 0.500–0.833.
- **Weaknesses**: finds a trigger **only if the trigger is in the family**. It
  performs no optimisation and reconstructs nothing.
- **Known failure cases**: any trigger outside the declared family. The lab's
  blended low-opacity scenarios are deliberately outside it; one was detected
  anyway by feature overlap, which is luck rather than coverage, and is reported
  as such.
- **Implementation decision**: implemented under the method name
  `trigger_family_probe`, with the declared family printed in the report and the
  `method_version` encoding which mechanism ran. **A gradient-free sweep is
  never described as reconstruction**, in the title, the evidence or the JSON.

### 14. Spectral signatures — *implemented, measured non-discriminating*

- **Origin**: Tran, B., Li, J. & Madry, A. (2018), *Spectral Signatures in
  Backdoor Attacks*, NeurIPS.
- **Original purpose**: find poisoned examples **inside a poisoned training
  set** by projecting each class's learned representations onto their top
  singular direction and removing the top ε fraction.
- **Attack assumptions**: the poisoned subset is a minority within its class and
  is separated along the dominant singular direction.
- **Required access**: white-box activations **and the training set**.
- **Implementation decision**: implemented, then **demoted to context-only after
  measurement.** We do not have the supplier's training set — that is Module 2's
  premise — so the method is applied to the probe battery instead, with the
  trigger probes standing in for the poisoned subset. Across the lab, the
  trigger-coincidence lift over a 0.447 base rate was **0.00–0.90 for backdoored
  models against 0.42–1.64 for clean ones**: the backdoored range lies *inside*
  the clean range and the highest lift belongs to a clean model. An earlier
  revision thresholded it and fired backwards — flagging `clean_retrain_0` and
  missing `backdoor_badnets`. It now reports evidence at INFO severity beside an
  already-established behavioural signal, with `Coverage.PARTIAL` and the
  measurement as the stated reason.

### 15. Activation clustering — *implemented, measured non-discriminating*

- **Origin**: Chen, B., Carvalho, W., Baracaldo, N., Ludwig, H., Edwards, B.,
  Lee, T., Molloy, I. & Srivastava, B. (2019), *Detecting Backdoor Attacks on
  Deep Neural Networks by Activation Clustering*, AAAI-19 SafeAI workshop.
- **Original purpose**: within each class of a poisoned **training set**,
  separate clean from poisoned activations by 2-means; a well-separated split
  with a small minority cluster is the backdoor signature.
- **Required access**: white-box activations **and the training set**.
- **Implementation decision**: implemented with **PCA in place of the paper's
  ICA**, because FastICA's fixed-point iteration is seed-dependent and its
  component order is not stable across runs, and determinism is not negotiable
  here. Demoted to context-only for the same measured reason as §14, plus a
  second mechanical one: on a backdoored model the triggered probes are driven
  onto the target class and become its **majority**, so the minority cluster the
  method reports is the *clean* subset — it flags the wrong half.

### 16. Jensen–Shannon divergence for behavioural comparison

- **Origin**: Lin, J. (1991), *Divergence measures based on the Shannon
  entropy*, IEEE Trans. Information Theory.
- **Original purpose**: a symmetric, bounded dissimilarity between probability
  distributions.
- **Implementation decision**: chosen over **Kullback–Leibler**, which is
  **deliberately not implemented**. KL is unbounded and undefined wherever one
  model assigns a class zero probability — which float32 softmax underflow
  produces routinely. A metric that is sometimes `inf` cannot be thresholded,
  averaged or compared across artifacts. JS is symmetric (there is no privileged
  model in a comparison), always finite, and bounded by 1 bit, so a value means
  the same thing across runs and models.

### 17. Robust z-scoring with a finite-sample MAD correction

- **Origin**: Iglewicz, B. & Hoaglin, D. (1993), *How to Detect and Handle
  Outliers* for the robust z; Croux, C. & Rousseeuw, P. J. (1992),
  *Time-efficient algorithms for two highly robust estimators of scale* for the
  finite-sample consistency factor.
- **Implementation decision**: median/MAD rather than mean/standard deviation,
  because the outlier being searched for is in the sample and would inflate a
  standard deviation enough to hide itself. The conventional threshold of **3.5
  was measured and rejected**: this screening tests four statistics per peer
  group on groups often smaller than ten tensors, and at 3.5 roughly a third of
  *clean* models carry a finding. Raised to **8.0** with the Croux–Rousseeuw
  correction applied, measured at ≤3% family-wise false alarms. A second defect
  found at the same time: grouping peers by operator type alone pooled BatchNorm
  scales with running variances, whose shared median and MAD describe nothing;
  role-aware grouping took a clean model from 8 reported outliers to 0.

---

## Method cards — Module 3 (inference provenance)

Module 3 adapts almost nothing from the ML literature, because its problem is
not an ML problem. Its sources are standards: RFC 8032, RFC 8785, TUF and
in-toto. The cards below record what was taken from each and, more usefully,
what was deliberately *not*.

### 18. Ed25519 / EdDSA

- **Origin**: Bernstein, Duif, Lange, Schwabe & Yang (2011), *High-speed
  high-security signatures*; standardised as RFC 8032 (2017).
- **Original purpose**: general-purpose digital signatures.
- **Assumptions**: discrete-log hardness on Curve25519; the private key is
  secret.
- **Inputs required**: a byte string. Nothing else.
- **Access**: not applicable — no model involved.
- **Strengths**: deterministic (no per-signature nonce to leak the key through),
  64-byte signature, 32-byte public key, no parameter choices, constant-time
  reference implementations, small enough to embed in every record.
- **Weaknesses**: no built-in key management, no revocation, no expiry — all of
  which have to be built around it, which is what the trust store is.
- **Implementation decision**: used through `cryptography`, never reimplemented.
  Chosen over ECDSA specifically for determinism: ECDSA's per-signature nonce
  has cost real deployments their private keys through reuse or bias, and the
  determinism additionally lets the attack lab be regenerated and byte-diffed
  rather than merely re-run. Chosen over RSA because a 384-byte signature per
  inference is a sixfold log-size increase for no gain at this level.

### 19. Hash chains for tamper-evident logging

- **Origin**: Haber & Stornetta (1991), *How to time-stamp a digital document* —
  the linking scheme, which predates and underlies every blockchain.
- **Original purpose**: making a document's position in a sequence
  unforgeable without a trusted third party.
- **Assumptions**: collision resistance; the verifier sees the entries in the
  order they appear.
- **Strengths**: detects modification, deletion, insertion, reordering and
  duplication with one digest per entry and no consensus layer.
- **Weaknesses**: **cannot detect truncation at the tail**, because a truncated
  chain is a valid shorter chain. This is inherent, not an implementation gap.
- **Implementation decision**: the chained digest covers the record payload
  **and** its signature envelope, not the payload alone. A payload-only chain
  reports itself intact when a signature has been swapped on an already-linked
  entry, and a chain that reports itself intact over a tampered entry is worse
  than no chain. Sequence numbers are carried alongside, adding no cryptographic
  guarantee but turning "link 7 does not match" into "an entry was deleted
  between 6 and 8". Truncation is addressed by an out-of-band anchor and
  reported `NOT_DETECTABLE` without one — see method card §20.

### 20. Log anchoring — *the honest answer to an unsolvable problem*

- **Origin**: the checkpoint/witness pattern in certificate transparency (RFC
  6962) and in TUF's timestamp role, reduced to its offline essentials.
- **Original purpose**: letting a verifier detect that a log has been rolled
  back or truncated, by holding a digest the log's operator cannot influence.
- **Assumptions**: the anchor is stored where the log's producer cannot write.
  **This assumption is the whole mechanism**, and no software can enforce it.
- **Strengths**: turns an undetectable attack into a detected one, with one
  digest and one integer.
- **Weaknesses**: covers only entries written before the anchor was taken;
  covers the head and the count, not the interior; and an anchor kept beside the
  log it anchors protects against nothing.
- **Implementation decision**: implemented, with the CLI writing anchors to an
  explicitly separate path and printing the storage requirement. The alternative
  — a gossip protocol or a witness network, as certificate transparency uses —
  requires exactly the network the air-gap forbids. Without an anchor the
  verifier reports `NOT_DETECTABLE` rather than clean, which is the substantive
  part: the limitation is visible in the report, not only in this file.

### 21. Replay detection by observation memory

- **Origin**: standard practice in authentication protocols (nonce caches in
  Kerberos, WS-Security, OAuth `jti` blacklists).
- **Original purpose**: preventing a captured, valid message from being
  accepted twice.
- **Assumptions**: the verifier keeps state, and that state is protected.
- **Strengths**: deterministic; detects exact re-presentation, nonce reuse and
  sequence collision, all with a local lookup.
- **Weaknesses**: the database *is* the security property. Delete it and every
  record becomes first-seen again. It is also local, so two verifiers each
  accept replays the other would catch, and retention bounds every negative
  result.
- **Implementation decision**: implemented with an explicit fourth verdict,
  `DUPLICATE_SUBJECT`, for the same input legitimately processed twice. Every
  real pipeline does this, and a detector that called it replay would be
  switched off within a day. Three replay verdicts are failures and that one is
  an observation; the separation is encoded in one tuple (`REPLAY_VERDICTS`) so
  it cannot drift, and `legitimate_reprocess` in the lab asserts it produces
  zero findings. The alternative — a shared ledger, so that all verifiers see
  the same history — is what ADR-009 declined.

### 22. TUF / in-toto — *the model, not the implementation*

- **Origin**: Samuel et al. (2010), *Survivable key compromise in software
  update systems* (TUF); Torres-Arias et al. (USENIX Security 2019) (in-toto).
- **What was taken**: signed metadata *about* artifacts kept distinct from the
  artifacts themselves; identity separated from location; an attestation per
  step in a supply chain; explicit key roles with distinct authority.
- **What was not taken**: TUF's role hierarchy (root, targets, snapshot,
  timestamp), threshold signatures, and the delegation tree. All of them solve
  the problem of *distributing* trust among multiple parties with partial
  authority, which a single air-gapped analyst authority does not have. Adopting
  them would have added four metadata roles and a delegation resolver to solve a
  problem nobody has.
- **Implementation decision**: the record is an in-toto-shaped attestation
  reduced to one step — input, model, configuration, output, signer — and the
  key-role idea survives as the two-value `KeyPurpose`, which is the one
  distinction that earns its keep: a key trusted to sign inference records must
  not be able to attest that a log is complete, or the producer could mint its
  own anchor.

### 23. RFC 8785 — *adopted, with one documented divergence*

Recorded in full under ADR-004 and carried forward unchanged: the
key-ordering, whitespace and UTF-8 rules are adopted; number canonicalisation is
**not**, and floats are rejected on the digest path in favour of fixed-point
integers. Module 3 is the module that would have paid for that subtlety, since
it is the one that signs these structures, and the decision was made in Module 1
precisely in anticipation of it.

One Module 3 addition: **Unicode strings are not normalised**. NFC and NFD forms
of the same label are different byte strings and get different digests. Silently
normalising would mean the digest covers something other than what the producer
emitted, and an analyst comparing a record against a model's actual label
vocabulary would find them disagreeing for reasons invisible in both. A
deployment that needs them unified normalises before binding, where the choice is
visible.

---

## Method cards — Module 4 (distribution shift and evidence fusion)

Module 4 asks a different question from the first three. Modules 1–3 ask *is
this artifact what it claims to be*; Module 4 asks *has the operating population
moved, and what does the accumulated evidence permit us to say*. The first half
is a two-sample testing problem. The second half is not a statistics problem at
all — see the fusion card at the end, which is the most important one here.

**The selection principle was deliberately restrictive.** Five methods are
implemented, not fifteen. A long list of shift detectors would inflate the
apparent capability while making the multiple-comparison problem worse and the
report harder to read. One omnibus test decides whether there is a shift;
everything else is *supporting detail* that localises it and is never decisive
on its own.

### 24. Energy distance, two-sample, with a permutation null — **the omnibus test**

- **Purpose.** Decide whether the current population is drawn from the same
  distribution as the reference, over the whole 614-dimensional feature space.
- **Source.** Székely & Rizzo, *Testing for equal distributions in high
  dimension* (2004); Sejdinovic, Sriperumbudur, Gretton & Fukumizu (Annals of
  Statistics, 2013) establish that the energy-distance family and the MMD family
  are equivalent up to the choice of kernel.
- **Input assumptions.** Finite second moments; exchangeability under the null.
  No distributional form, no independence between coordinates, no Gaussianity.
- **Reference requirements.** A reference population whose identity, digest and
  declared provenance are recorded. **Not assumed to be uncontaminated** — see
  the reference-contamination note below.
- **Sample-size requirements.** 20 per side (configurable floor). Below that the
  metric reports `INSUFFICIENT_SAMPLE` and contributes nothing. The statistic is
  quadratic in sample count, so points are deterministically subsampled to 400
  per side; both the number used and the number available are reported, so a
  capped run cannot be read as a full one.
- **Strengths.** Parameter-free — this is why it was chosen over MMD, which is
  mathematically equivalent but carries a bandwidth knob that would have to be
  set, justified, and defended, and which silently determines what "different"
  means. Consistent against **all** alternatives, not only mean shifts. The
  permutation null is exact under exchangeability, so the p-value does not rest
  on an asymptotic approximation at n=120.
- **Weaknesses.** Quadratic cost. Low power against a shift confined to a few of
  614 coordinates — which is exactly why the marginal test exists alongside it.
  The p-value floor is 1/(B+1) and is reported next to every p-value so a floor
  is never mistaken for certainty.
- **Failure modes.** A contaminated reference makes a clean population look
  shifted and a shifted one look clean, and nothing in the statistic can detect
  this. Both populations drawn from a *mixture* that has changed proportions
  register as a shift, correctly, but the test says nothing about which
  component moved.
- **Calibration.** None required and none invented: the null is constructed from
  the data at analysis time by permutation. `alpha = 0.01`, deliberately strict,
  because the operational cost of a false shift alarm is an analyst
  investigating a legitimate seasonal change.
- **Interpretation.** A significant result means *these two populations differ
  more than random relabelling of the same points would produce*. It is not a
  statement about cause, and never a statement about attack.
- **Implementation decision.** **Implemented and decisive.** It is the only
  metric whose result determines the shift verdict.

### 25. Per-block mean displacement — **localisation, not detection**

- **Purpose.** Say *where* in the feature space a movement occurred, using the
  five measured spans of the classical extractor (structure 0–256, colour
  256–384, gradient 384–528, DCT 528–591, acquisition 591–614).
- **Input assumptions.** Only that the blocks are meaningful, which they are by
  construction (ADR-005).
- **Sample-size requirements.** Inherits the omnibus floors.
- **Strengths.** Directly interpretable, and it is what makes the declared-context
  explanation possible at all: "the movement is 93% in the colour view" is a
  sentence an analyst can check against "we moved to a night collection".
- **Weaknesses.** Squared-displacement *shares* only, with **no significance
  test of its own** — `significant` is explicitly `None`. Shares sum to one, so
  a tiny overall movement and an enormous one are described identically.
- **Failure modes.** Illumination, season and terrain changes all place ~93% of
  their displacement in the colour view, so this measurement **cannot
  distinguish between them**. That limitation is printed on every explanation
  and is the reason a season declaration is accepted as covering an illumination
  movement (see the measured corrections below).
- **Calibration.** None; it is descriptive.
- **Interpretation.** A share, not a score. It never fires a rule.
- **Implementation decision.** **Implemented, explicitly non-decisive.**

  *A standardised variant was implemented, measured and discarded.* Dividing
  displacement by the per-coordinate reference standard deviation gave
  `colour = 1.000` on **every** pair including the clean baseline: the
  near-zero-variance HSV bins explode under standardisation. Raw squared-
  displacement shares were kept, and the failed attempt is recorded here rather
  than deleted.

### 26. Covariance comparison by cross-fitted log-determinant ratio

- **Purpose.** Detect a change in *spread or correlation structure* that leaves
  the mean where it was — a population that has become more or less diverse.
- **Source.** The generalised-variance ratio is classical; the cross-fitting is
  the same device Module 1 uses for its quantile thresholds (method card §10).
- **Input assumptions.** A non-singular covariance in the projected subspace.
- **Reference requirements.** At least `2 × components × samples_per_component`
  reference samples — 80 at the defaults — because the basis is fitted on one
  half and evaluated on the other.
- **Sample-size requirements.** A 614×614 covariance from a few hundred samples
  is singular and its determinant is not evidence, so the comparison is made in
  the top 8 principal directions only, with 5 samples required per direction.
- **Strengths.** Catches the case the mean test misses entirely. Cross-fitting
  removes the bias that made the in-sample version unusable.
- **Weaknesses.** Only 8 directions, chosen by reference variance; a spread
  change orthogonal to them is invisible. The log-determinant is a single
  summary of a matrix and discards which direction moved.
- **Failure modes.** **The measured one:** an in-sample PCA basis made every
  current population look contracted — log-det ratio **−2.35 on two independent
  clean draws**, a guaranteed false positive. Cross-fitting moved the same
  comparison to **+0.56**.
- **Calibration.** The original fixed threshold (`log_det_threshold = 0.5`) was
  **removed from the configuration entirely** and replaced by a permutation null
  over the pooled projected points. A fixed threshold on a quantity whose null
  distribution depends on dimension and sample size is folklore, not calibration.
- **Interpretation.** Supporting detail. A significant result strengthens a
  shift the omnibus test already found; it cannot produce one alone.
- **Implementation decision.** **Implemented as supporting evidence.**

### 27. Population Stability Index with a permutation null and BH correction

- **Purpose.** Per-quantity marginal shift on the 23 named acquisition
  statistics, which are the ones an analyst can reason about physically
  (exposure, saturation, edge density, block artifacts, …).
- **Source.** PSI is standard credit-risk practice; the 0.10/0.25 bands are
  industry folklore with no published derivation.
- **Input assumptions.** Reference-quantile binning with a continuity floor of
  `1/(2n)` so an empty bin does not produce an infinite index.
- **Sample-size requirements.** 10 bins with ≥5 samples each, so ≥50 per side.
- **Strengths.** Names the physical quantity that moved, which is what makes a
  shift actionable rather than merely detected.
- **Weaknesses.** 23 simultaneous tests. Marginal only — it cannot see a change
  in the joint structure that leaves every margin intact.
- **Failure modes.** **Two measured, both fixed:**
  1. The conventional 0.25 band fired at **0.37 on a clean pair**. Measured
     against a clean reference split in half, max-PSI across the 23 quantities
     had **mean 0.49 and p95 0.65** — the band is roughly twice as strict as the
     null warrants at this sample size. The band was demoted from a decision
     rule to a **reporting label**, documented in the report as unvalidated, and
     the configuration key was renamed `psi_reporting_band` to make its status
     unmistakable.
  2. After switching to a permutation null with Benjamini–Hochberg correction,
     significance became **unreachable by construction**: at B=199 with m=23
     quantities the smallest achievable BH-adjusted q is 0.115, so `alpha=0.01`
     could never be met. Measured on a quantity displaced 4 standard deviations
     with PSI 5.31 and reported *not significant*. Fixed by auto-scaling the
     budget to `ceil(m/alpha) − 1` = 2299 permutations, capped at 4999; when the
     cap binds, the metric reports
     `significance_resolvable_after_correction: false` and states that
     significance **could not be resolved**, which is explicitly *not* a finding
     of stability.
- **Calibration.** Permutation null per quantity, BH across quantities. No
  operational calibration exists and none is claimed.
- **Interpretation.** Supporting detail that names quantities.
- **Implementation decision.** **Implemented as supporting evidence, with its
  conventional threshold demoted to a label after measurement.**

### 28. Jensen–Shannon divergence for class-mix and metadata comparison

- **Purpose.** Compare categorical distributions — class labels, declared
  contributor, declared batch, declared source — between the two populations.
- **Source.** Lin (IEEE Trans. Inf. Theory, 1991). Already used in Module 2 for
  behavioural comparison (method card §16), so the interpretation is shared
  across modules rather than invented twice.
- **Input assumptions.** Both sides have at least a minimum count per side.
- **Strengths.** Symmetric, bounded in [0, 1] bit, and **finite on disjoint
  support** — which is exactly why it was chosen over KL divergence, whose
  infinity on a newly introduced class would be an unusable number in a report.
- **Weaknesses.** A bounded divergence compresses large differences; a
  permutation test of homogeneity is run alongside it so the decision does not
  rest on the magnitude alone.
- **Failure modes.** Declared metadata is a **claim by the supplying side**.
  `declared_sensor = Sensor-A` does not establish what physically produced an
  image, and a shift in declared contributor is evidence about the declaration,
  not about the imagery.
- **Calibration.** Permutation null.
- **Interpretation.** Supporting detail. A change in who supplied the data is a
  genuine operational signal and is reported as such — not as evidence of
  manipulation.
- **Implementation decision.** **Implemented as supporting evidence.**

### 29. Explicit rule-based evidence fusion — **why there is no score**

This is a design card rather than a method card, because the decision was to
*not* adopt a method.

- **The problem.** Four scopes (dataset, model, provenance, distribution), each
  producing findings with a severity, a confidence and one of four confidence
  bases. Produce one disposition.
- **The obvious solution, rejected.** Weight each scope, sum, threshold. A
  calibrated probabilistic model would be the defensible version of this, and
  building one honestly requires (a) a prior over attack-class incidence in
  multi-contributor pipelines, (b) per-detector error rates measured on
  operational data, and (c) an independence structure. **None of the three
  exists here**, and the project's own method cards say so: §14 and §15 record
  two Module 2 detectors measured non-discriminating, and the
  `HEURISTIC_UNCALIBRATED` basis exists precisely because several detectors have
  no measured error rate at all. Weights chosen without those three inputs are
  numbers picked to make a demo look right, stated with a precision they do not
  have — and, worse, they are unarguable: an analyst who disagrees with
  `trust = 0.62` has nothing to point at.
- **What was implemented instead.** 23 explicit rules, each with an id, scope,
  conditions, required evidence, exclusions, disposition and rationale, printed
  in full in every report. Four scope dispositions, kept separate. The overall
  disposition is the **strictest** across scopes with the scope named — never a
  mean, because one confident `QUARANTINE` among three quiet scopes is exactly
  the case a mean would bury.
- **The one aggregation performed, and how it is bounded.** Corroboration.
  Attack classes map to **evidence families**, and a family contributes at most
  **one unit of independent support** no matter how many findings or detectors
  it contains — measured directly: five distinct duplicate detectors firing on
  one cluster yield `corroboration = 5` distinct detectors and
  `independent_family_count = 1` phenomenon. A second table records the single
  confounding relationship the project can justify (`DATASET_LABELLING` ←
  `DISTRIBUTION_SHIFT`); every other entry is empty on purpose.
- **Sample-size / data sensitivity.** None — the rules are deterministic
  functions of the evidence. This is a genuine advantage over a calibrated
  model, which would need its calibration re-established for every deployment.
- **Operational interpretation.** An analyst can name the rule that produced a
  disposition and disagree with it by id. A reviewer can diff the table between
  policy versions. The policy version is bound into the decision, the run
  context and the report digest.
- **Failure cases, stated plainly.** The table is coarser than a calibrated
  model would be. It cannot express "three weak signals from unrelated families
  together warrant escalation", because quantifying "together" is precisely the
  part that needs the missing independence structure. A genuine dataset attack
  that coincides with a legitimate distribution shift is held at `REVIEW` rather
  than escalated, because the confounding table cannot separate them — an
  accepted, documented cost, not an oversight.
- **Implementation limitation.** Independence is decided by a **curated table,
  not measured from data**. Two detectors correlated in a way the table does not
  record would still be counted as two phenomena. The table is printed in every
  report so that assumption can be challenged rather than trusted.

### The reference population is not ground truth

Every one of the five metrics above compares against a reference, and **nothing
in this system establishes that the reference is clean.** A contaminated
reference makes a clean population look shifted and a shifted one look clean,
and no amount of statistical rigour in the comparison can detect it.

What is done instead: the reference carries an identity (`REF-…`), a content
digest that **binds the feature space** — so the same images under a different
extractor are a different reference, and two incomparable runs cannot be
diffed — an explicit `mode` (`DECLARED_CORPUS`, the strong form, or
`DECLARED_SUBSET`, where the population under assessment contributed to its own
baseline), a declared provenance, a version, and a trust level that **defaults
to `UNKNOWN` and is never inferred**. The caveat is printed on every assessment.

---

## Module 4 — considered and rejected

| Method | Why not |
|---|---|
| **Maximum Mean Discrepancy with an RBF kernel** | Mathematically equivalent to energy distance for the corresponding kernel (Sejdinovic et al. 2013), but carries a bandwidth parameter that silently determines what "different" means. The median heuristic is a convention, not a derivation. Energy distance gives the same test with nothing to tune and nothing to defend. |
| **Kolmogorov–Smirnov per coordinate** | 614 simultaneous univariate tests, all of them blind to joint structure, in exchange for a multiple-comparison problem an order of magnitude worse than PSI's 23. The marginal question is already answered on the 23 *physically interpretable* acquisition statistics, where a result is actionable. |
| **Wasserstein / earth-mover distance** | Attractive and interpretable in one dimension; in 614 dimensions it needs either an optimal-transport solve per permutation (prohibitive inside a 999-draw null) or a sliced approximation that reintroduces a projection parameter to justify. |
| **A learned drift detector** (autoencoder residual, domain classifier) | A neural network that predicts whether a population has drifted, whose own provenance would then need assuring — circular, exactly as MNTD is for Module 2. It would also be uninterpretable in the one place interpretation matters most: distinguishing operational drift from manipulation. |
| **Kullback–Leibler divergence for class mix** | Infinite on disjoint support. A newly introduced class is the *normal* case in an operational pipeline, and a report field that reads `inf` is not a report field. |
| **Fixed PSI bands (0.10 / 0.25) as a decision rule** | Measured false-positive on a clean pair at 0.37, with a measured null whose p95 is 0.65. Retained as a label, demoted from a decision. |
| **A universal trust score `0–100`** | ADR-016. See method card §29. |
| **Weighted scoring across modules** (`model 40% + dataset 30% + …`) | ADR-016. The weights would be unjustifiable, unarguable and load-bearing. |
| **Treating unexplained shift as evidence of attack** | ADR-018. Terrain, season, sensor and illumination changes are the normal condition of this problem domain and produce the same signature. The strongest statement the distribution scope makes is `REVIEW`. |
| **Treating a declared context as validated** | A declaration is a claim by the supplying side. Every explanation carries `declaration_validated: false`, and consistency between an observed shift and a declared change is reported as consistency, never as confirmation. |
| **A "population health" or "drift score" field in the report** | The same failure as a trust score, one scope down. The report carries verdicts from a closed vocabulary and per-metric statistics with their p-values, and no summary number. |

---

## Module 3 — considered and rejected

| Method | Why not |
|---|---|
| **A blockchain / distributed ledger** | ADR-009, and it predates this module. A ledger buys Byzantine agreement among mutually distrusting writers. This deployment has one writer, no network to gossip over, and no second party whose disagreement about ordering must be resolved. It would add nodes, key distribution, fork resolution and a synchronisation requirement that directly contradicts the air-gap. |
| **A Merkle tree over the log** | ADR-009 listed it as a possible addition "if justified by volume". It is not. A Merkle tree buys efficient *inclusion proofs* — proving one record is in a log without shipping the log — which matters when a verifier holds a root and a prover holds the data. Here the analyst holds the whole log and verifies 200 entries in 8.8 ms. It would add a second set of invariants to get wrong in exchange for solving a problem nobody has. The point to add it is when membership must be proved to a party that does not hold the log. |
| **RFC 3161 trusted timestamping** | Requires a timestamp authority, which requires a network. There is none, so the module does not pretend a timestamp proves time — it reports the timestamp as a claim and says what the claim establishes. |
| **X.509 certificates and a PKI** | A certificate is a signed assertion that a key belongs to an identity, made by an authority. With no network there is no authority to consult, no revocation service, and no chain to build — so a certificate would reduce to "a public key plus a local decision to trust it", which is exactly what the trust store already is, minus a large parsing surface. |
| **HMAC instead of signatures** | Anyone who can verify an HMAC can also forge one. Non-repudiation requires asymmetry. |
| **Encrypting the provenance records** | Confidentiality is not the property being sought and encryption would provide none of it usefully — the analyst is the reader. It would, however, make a log unverifiable by anyone who loses the key, turning an integrity tool into an availability risk. |
| **A "provenance confidence score"** | The specific failure ADR-014 exists to prevent. A digest matches or it does not; expressing that as 0.93 would be a lie with a decimal point. |
| **Deriving signing keys from a passphrase** | Would make key strength a function of operator password choice, silently. Real key generation from the OS CSPRNG, plus passphrase *encryption* of the stored key, keeps the two concerns separate. |
| **Merging the ML assurance verdict with the cryptographic one** | ADR-014. They are different kinds of evidence with different failure modes, and a system that averaged them could report a forged record of a clean model and a valid record of a backdoored one as the same number. |

---

## Module 2 — considered and rejected

| Method | Why not |
|---|---|
| **STRIP** (Gao et al., ACSAC 2019) | Detects a trigger by superimposing inputs and measuring prediction entropy. The superimposition assumption does not hold for low-opacity blended triggers, and it costs N× inference per query, which is the wrong trade for an offline artifact assessment where we can simply probe the trigger family directly. |
| **Fine-Pruning** (Liu, Dolan-Gavitt & Garg, RAID 2018) | A **mitigation**, not a detector, and it *modifies the artifact under assessment*. An assurance tool that alters its subject has destroyed the thing it was asked to describe. |
| **MNTD** (Xu et al., IEEE S&P 2021) | Trains a meta-classifier over thousands of shadow models to predict whether a model is trojaned. This is precisely "a neural network that predicts whether another neural network is malicious", which the Module 2 brief forbids on the grounds that it is unexplainable and its own provenance is unassured. It also needs a shadow-model corpus far beyond an air-gapped deployment's budget. |
| **ABS** (Liu et al., CCS 2019) | Artificial Brain Stimulation: scans neurons for ones that dominate an output regardless of input. Large, fragile implementation surface relative to what it would add over Neural Cleanse here, and it inherits the same low-class-count problem we already measured. |
| **A learned "model trust score"** | Collapses severity, confidence and coverage into one unexplainable number, which is the specific failure mode the assessment matrix exists to prevent. |
| **Weight-statistic backdoor classification** | No published result establishes that unusual weight statistics imply a backdoor. Quantisation-aware training, unusual initialisation, weight decay and layer saturation all produce them in clean models — and the lab contains `clean_unusual_init` specifically to keep that honest. |

---

## Measured corrections — things the evaluation harness caught

Recorded because they are the substance of the engineering, and because a
reviewer should be able to see that the numbers were measured rather than
assumed.

1. **OOD recall was zero at AUROC 0.75.** Reference-fitted PCA was discarding
   the directions in which the inserted sensor differed. Fixed by adding the
   reconstruction residual (§9). Recall 0.00 → 1.00.
2. **OOD false-alarm rate was 8.9% against a nominal 1%.** The threshold came
   from K-fold-fitted models while the scores came from a full fit, and *every*
   scorer here is `n`-dependent — Ledoit–Wolf shrinkage strengthens as `n`
   falls, k-NN distance grows as the reference thins, and the PCA subspace
   tightens with more data. Comparing the two was comparing different scales.
   Fixed by scoring reference and candidate samples under the same fitting
   regime (`_cross_fitted_scores`). 8.9% → 2.7%.
3. **Family-wise rate was 3× the configured rate.** Three methods, each at 1%,
   unioned. Fixed by Bonferroni-correcting the per-method rate. 2.7% → 0.89%.
4. **Corpus generation was not reproducible across processes.** Per-sample seeds
   were derived from Python's `hash()`, which is salted per interpreter. Every
   reproducibility claim built on the corpus was therefore false between runs.
   Fixed by deriving seeds from SHA-256; pinned by a subprocess test.
5. **COCO format detection failed on large annotation files.** The detector
   sniffed the first 4 KB for `"images"`, which a sorted-key COCO file can push
   hundreds of kilobytes in. A detection failure looked identical to an
   unsupported format. Fixed by parsing with an mtime-keyed cache.
6. **Label findings fired on out-of-distribution samples whose labels were
   correct.** A sample outside the reference distribution has an
   unrepresentative neighbourhood, so disagreement is the expected consequence
   rather than evidence of a flip. Fixed by running the OOD detector first and
   having the label detector qualify such findings explicitly — severity capped
   to LOW, with the reason recorded as evidence. The finding is kept, because
   suppressing a real observation is worse than qualifying it.

7. **Activation-based backdoor detection fired backwards.** Spectral signatures
   and activation clustering, applied to the probe battery rather than the
   training set they were published for, flagged a *clean* model
   (`clean_retrain_0`, coincidence lift 1.64) and stayed silent on a backdoored
   one. Measured across the whole lab, the backdoored range sits inside the
   clean range. Demoted from an independent detector to context-only, with the
   measurement published as the reason. `docs/model-security.md` §6.1.
8. **Neural Cleanse missed the backdoor it was pointed at.** A *fixed* mask
   penalty leaves per-class mask norms incomparable, and the true target class
   scored an anomaly index of 1.31 against a threshold of 2. Fixed by
   implementing the paper's dynamic λ scheduler, after which the ranking is
   correct on every backdoored model. The index itself still does not
   discriminate at 6 classes, so it is declared uninterpretable below 8 rather
   than reported as a verdict. §6.2.
9. **Peer-group weight screening had a ~35% false-alarm rate.** The conventional
   Iglewicz–Hoaglin threshold of 3.5 is for one statistic on a large sample;
   this screening tests four on groups smaller than ten. Fixed with the
   Croux–Rousseeuw finite-sample MAD correction and a measured threshold of 8.0
   (≤3%). Separately, grouping peers by operator type alone pooled BatchNorm
   scales with running variances and produced 8 "outliers" on a clean model;
   role-aware grouping took that to 0. §6.3.
10. **The trigger probe silently ignored a caller's declared opacity.** The
    family sweep overrode each spec's `opacity` with its own parameter, so a
    blended-trigger probe was measuring a full-opacity patch and reporting it as
    the blended result. Caught by an adversarial test that asserted a faint
    trigger should be *less* effective and found it exactly equal.
11. **Model lab seeds escaped the canonical integer range.** Seeds derived from
    a SHA-256 prefix exceeded IEEE-754 exact range and were rejected by
    `canonical_json` when fed back into another digest — Module 1's ADR-004
    guard catching a Module 2 defect at the boundary, which is what it is for.
12. **A covariance comparison fitted in-sample was a guaranteed false
    positive.** The PCA basis fitted on the reference made every current
    population look contracted: log-determinant ratio **−2.35 on two
    independent clean draws**. Cross-fitting — fit the basis on one half of the
    reference, compare the held-out half against the current population — moved
    the same comparison to **+0.56**. The fixed threshold was then deleted from
    the configuration and replaced by a permutation null. §26.
13. **The conventional PSI band fired on clean data.** Max-PSI across the 23
    acquisition statistics reached **0.37** on a clean pair, against an industry
    band of 0.25. The null, measured by splitting a clean 144-sample reference
    in half, had **mean 0.49 and p95 0.65**. The band was demoted to a reporting
    label and the config key renamed `psi_reporting_band`. §27.
14. **PSI significance was then unreachable by construction.** With 199
    permutations and 23 quantities, the smallest achievable Benjamini–Hochberg
    q is 0.115 — so `alpha = 0.01` could never be met. Measured on a quantity
    displaced 4 SD with PSI 5.31, reported *not significant*. Fixed by
    auto-scaling the budget to `ceil(m/alpha) − 1` (2299 at the defaults), and
    by reporting `significance_resolvable_after_correction: false` when the cap
    binds — which is stated as "could NOT be resolved", never as stability. §27.
15. **Standardised block attribution was discarded after measurement.**
    Dividing displacement by per-coordinate reference SD gave `colour = 1.000`
    on every pair *including the clean baseline*, because near-zero-variance HSV
    bins explode under standardisation. Raw squared-displacement shares kept.
    §25.
16. **The `sensor` context table was wrong, and a legitimate platform swap paid
    for it.** 81% of the sensor transform's displacement landed in the
    `gradient` view, which the table did not predict, so a declared, legitimate
    sensor change read as `SHIFT_PARTIALLY_EXPLAINED`. `gradient` was added to
    the table with the measurement recorded next to it: softer optics *is* an
    edge-statistics change.
17. **A six-sample batch was reported `NOT_ASSESSED` instead of
    `INSUFFICIENT_SAMPLE`.** The verdict resolver checked "no metric was
    assessed" before the sufficiency branch, so a refusal-for-lack-of-data was
    reported as a refusal-for-lack-of-a-detector. The two have different
    remedies. Reordered, with the lab pair that caught it named in the comment.
18. **A scope could vanish from the report entirely.** When every dataset
    finding was confounded by a coincident shift, `RULE-DATA-002` (needs
    unconfounded evidence) and `RULE-DATA-010` (needs no evidence) both declined
    to fire, and the dataset scope disappeared — reading as "nothing to say
    about the dataset" when the truth was "there is a finding and it cannot be
    separated from the shift". `RULE-DATA-004` was added: **a confounded finding
    is not a refuted one.**
19. **Per-sample OOD evidence reached no rule at all** when no population-level
    shift assessment was supplied. `RULE-SHIFT-050` was added to catch it, and
    is silenced when a shift assessment exists so the same phenomenon is not
    counted twice.
20. **Three lab expectations were wrong and the engine was right.** A
    `misdeclared_illumination` scenario expected `PARTIALLY_EXPLAINED`, but
    illumination, season and terrain all place ~93% of their displacement in the
    colour view, so a season declaration genuinely does cover an illumination
    movement. The scenario was renamed `misdeclared_illumination_as_season` and
    kept as the **explicit negative control** for the explanation mechanism,
    with `misdeclared_sensor_as_illumination` added to show the check has teeth.
    Similarly, a `dataset_only` scenario expected `ACCEPT` and received
    `NOT_ASSESSED` — correct, because three scopes had no input; the property
    was made explicit in `overall()` and published as
    `accept_requires_full_coverage`. And the clean model baseline was
    `clean_retrain_0`, which is an *independently retrained* model and therefore
    genuinely mismatches the reference; it was replaced by a self-comparison.


---

## Rejected, with reasons

| Method | Why not |
|---|---|
| **LSH / banding prefilter** for near-duplicate search | An approximate answer in an assurance context trades a guarantee for a constant factor. Exact blocked popcount handles the target dataset sizes at ~5,000 samples/s; above `max_pairwise_samples` the detector **refuses and reports NOT_ASSESSED** rather than silently sampling. |
| **Pretrained CNN embeddings** as the default feature space | Requires downloading weights, which the air-gap forbids, and makes every downstream number depend on an artifact whose provenance we would then have to assure — circular, in an integrity tool. Available as an opt-in backend with a locally vendored, hash-recorded weight file. |
| **Spectral signatures** (Tran, Li & Madry, NeurIPS 2018) and **activation clustering** (Chen et al., 2018) for poisoning | Both operate on a model's internal activations. Module 2 scope; implementing them here would mean partial backdoor detection with no model-side counterpart (ADR-008). **Implemented in Module 2 and measured non-discriminating** — see method cards §14–15. |
| **Neural Cleanse** trigger reconstruction (Wang et al., IEEE S&P 2019) | White-box, model-dependent. Module 2. **Implemented there**; see method card §12 for its measured limit at low class counts. |
| **A distributed ledger / blockchain** | ADR-009. A single-authority air-gapped analyst deployment has no Byzantine multi-writer consensus problem to solve. Hash-chained append-only logs with Ed25519 signatures give tamper-evidence at a fraction of the complexity. **Module 3 built exactly that** and still has no ledger; see method cards §19–21. |
| **RFC 8785 float canonicalisation** | Implementable but subtle, and every subtlety becomes a signature-verification bug once Module 3 signs these structures. Floats are instead rejected on the digest path and carried as fixed-unit integers (ADR-004). **Module 3 signed those structures and the decision held** — no float has ever reached a signature. |
| **Full-image histogram equalisation before hashing** | Would add photometric invariance that pHash already has via DC exclusion, while destroying the exposure statistics the OOD detector's acquisition block depends on. |
