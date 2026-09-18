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

---

## Rejected, with reasons

| Method | Why not |
|---|---|
| **LSH / banding prefilter** for near-duplicate search | An approximate answer in an assurance context trades a guarantee for a constant factor. Exact blocked popcount handles the target dataset sizes at ~5,000 samples/s; above `max_pairwise_samples` the detector **refuses and reports NOT_ASSESSED** rather than silently sampling. |
| **Pretrained CNN embeddings** as the default feature space | Requires downloading weights, which the air-gap forbids, and makes every downstream number depend on an artifact whose provenance we would then have to assure — circular, in an integrity tool. Available as an opt-in backend with a locally vendored, hash-recorded weight file. |
| **Spectral signatures** (Tran, Li & Madry, NeurIPS 2018) and **activation clustering** (Chen et al., 2018) for poisoning | Both operate on a model's internal activations. Module 2 scope; implementing them here would mean partial backdoor detection with no model-side counterpart (ADR-008). |
| **Neural Cleanse** trigger reconstruction (Wang et al., IEEE S&P 2019) | White-box, model-dependent. Module 2. |
| **A distributed ledger / blockchain** | ADR-009. A single-authority air-gapped analyst deployment has no Byzantine multi-writer consensus problem to solve. Hash-chained append-only logs with Ed25519 signatures give tamper-evidence at a fraction of the complexity. Recorded in `docs/architecture.md`. |
| **RFC 8785 float canonicalisation** | Implementable but subtle, and every subtlety becomes a signature-verification bug once Module 3 signs these structures. Floats are instead rejected on the digest path and carried as fixed-unit integers (ADR-004). |
| **Full-image histogram equalisation before hashing** | Would add photometric invariance that pHash already has via DC exclusion, while destroying the exposure statistics the OOD detector's acquisition block depends on. |
