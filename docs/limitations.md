# Limitations

Stated plainly, in one place. The tool prints the headline items on every
report; this is the complete list.

## 1. Scope of this build

**Modules 1 and 2 of 5 are implemented.** Inference provenance,
distribution-shift characterisation and the analyst web UI do not exist yet.
They are declared `NOT_ASSESSED` in the coverage statement of every report, with
the owning module named — not silently omitted.

A clean report is a statement about the attack classes marked `SUPPORTED` or
`PARTIAL` in `docs/coverage.md`, and about nothing else.

**A model assurance report never states that a model is safe.** The strongest
positive statement available is `NO_ANOMALY_DETECTED`, which is a statement
about the tests that ran under the recorded access mode and probe battery, not
about the model. This is enforced by a test, not by review.

## 2. What a finding is, and is not

Statistical and threshold-based findings identify patterns inconsistent with a
stated null model. **They are not proof of intent.** An unfamiliar annotation
guideline, a new collection platform, a seasonal change or a sensor swap can
produce the same signature as a deliberate attack. Every such finding carries
that limitation, and the disposition policy is built so that no uncalibrated
finding can, on its own, quarantine an asset.

**Out-of-distribution is never treated as equivalent to malicious.** OOD
severity is capped at `MEDIUM` by design, and distinguishing operational drift
from deliberate manipulation requires population-level evidence that Module 4
will provide.

## 3. Per-detector limitations

| Detector | Limitation |
|---|---|
| `integrity` | Detects contradictions *within* a dataset. A **consistent lie** — annotations that are internally coherent but describe the wrong reality — is structurally valid and invisible. Structural validity never implies semantic correctness. |
| `exact_duplicate` | Exact-match only, by design. Any pixel change defeats it (that is `near_duplicate`'s job). Duplication is not inherently malicious: burst capture, video frames and tiled imagery produce it legitimately. |
| `near_duplicate` | **No invariance to rotation, reflection or heavy crop.** Tested and asserted. Low-entropy imagery (uniform sky, sea, sand) has low-entropy hashes and raises false-positive pressure; stage-2 confirmation mitigates but does not eliminate this. Flooding is inferred from cluster size and contributor concentration, both of which have legitimate causes. |
| `label_consistency` | A **screening signal, not a verdict**. Genuinely ambiguous and boundary samples produce the same evidence as a flipped label. Strongly dependent on the feature space. **Cannot detect a uniformly mislabelled class**, which is internally consistent. Recall degrades as the flip rate rises, because flipped samples begin forming a consistent neighbourhood of their own. |
| `systematic_mislabel` | Inherits the label detector's feature-space dependence: wrong suggestions mean wrong directional structure. A mapping applied uniformly by *every* contributor has no cohort baseline to stand out against. Sample-level attribution is a screening signal (measured recall 0.67–0.75); the contributor-level claim is the strong one. |
| `ood` | Requires a **trustworthy, representative** declared reference set. Without one it self-references, which an adversary supplying a large share of the data can shift in their favour — the report states this. An adversary who matches the reference's low-level statistics is not detected. Detects distributional distance, not intent or provenance. |
| `model_identity` | Detects that an artifact **changed**, never that the change was malicious: a legitimate retrain, re-export or recompilation produces the same observation. Says nothing about whether the *reference* is trustworthy. Requires a reference obtained through a channel independent of the one that supplied the artifact — an assumption that stays unverified until Module 3 signs manifests. |
| `model_structure` | Weight-blind **by design**: a model whose weights were replaced entirely has an identical structural fingerprint. A cross-format comparison (ONNX vs TorchScript) differs for benign exporter reasons and is severity-capped accordingly. |
| `model_parameters` | Against a reference this is deterministic and localising. **Without** one it falls back to peer-group screening, which is a statement about weight statistics within one model and nothing more — no published result connects unusual weight statistics to backdoors. Needs ≥6 comparable tensors per (operator, role) group; smaller groups are skipped and reported as skipped, which on small architectures means *every* group. |
| `model_behaviour` | Scoped to the battery. Two models that agree on every probe may differ elsewhere. Establishes behavioural *difference*, not which model is correct nor that the difference is malicious. |
| `model_activation` | **Measured non-discriminating in this build.** Applied to a probe battery rather than the training set the methods were published for, the backdoored lift range lies inside the clean range. Reports context at INFO severity; contributes no independent detection. `docs/model-security.md` §6.1. |
| `model_trigger` | Coverage is bounded by the **declared patch family**: a trigger outside it is outside the claim. Neural Cleanse reconstruction needs input gradients (so never on ONNX), and its anomaly index is **uninterpretable below 8 classes** — at 6 classes a clean model produced a mask as small as a backdoored one. Sample-specific, semantic, large-by-design and adaptive triggers are not assessed. §6.2. |
| `contributor_aggregation` | Inherits every limitation of the detectors feeding it. A contributor whose data is *uniformly* affected has no clean portion to contrast against. Over-representation is evidence of a different data-generating process, not of intent. Rests on contributor attribution, which is untrusted metadata. |

## 3a. Model-specific limitations

**Access determines what can run, and formats differ.** ONNX exposes no input
gradients, so trigger reconstruction cannot run on it. TorchScript refuses
forward hooks, so activation capture cannot run on it. Both facts are reported
in every affected run; neither is worked around, because a weaker method
reported under a stronger name would be worse than an honest gap.

**Deserialisation is an attack surface.** A `torch.save`d `nn.Module` is a
pickle, and unpickling executes code from an artifact this tool treats as
untrusted. `weights_only=True` is the default and a module pickle is **refused**
unless an operator explicitly opts in. Ask suppliers for ONNX or TorchScript.

**Evaluation population.** 15 synthetic model artifacts of one architecture
family (~24k parameters, 6 classes), trained from published seeds on the Module
1 synthetic corpus. The unit of evaluation is the *model*, so every measured
rate rests on few observations. Model-side `CALIBRATED` confidence will look
weak, and it should.

**Backdoor coverage is bounded by the declared trigger family, and one lab
backdoor is missed because of it.** Measured attack success rates were
0.000–0.333 on non-backdoor models and 0.667–0.833 on the five backdoors whose
family the probe sweeps, with the threshold at 0.50 — a genuinely empty region
on both sides. The sixth, `backdoor_blended_faint`, is a blended trigger at
opacity 0.08 built to sit *outside* that family; it scores 0.292 and is missed,
exactly as its ground truth predicts. It is a real, fully effective backdoor
(true attack success rate 1.000). Lowering the threshold would not fix this — it
would fall below a non-backdoor model at 0.333 and start manufacturing findings.
The honest answer to an out-of-family trigger is declared coverage.

**Adaptive adversaries are not defended against.** An attacker who optimises a
backdoor against these specific detectors — regularising the reconstructed mask
norm toward the clean population, or suppressing the spectral signature during
training — is known in the literature to succeed.

**Data-side `trigger_injection` remains unimplemented** — see ADR-011 and
`docs/model-security.md` §10. It is an open item, not a dropped one.

## 4. Attribution

Contributor metadata comes from the untrusted side. Precedence is explicit and
recorded per sample (`sidecar` > `adapter_native` > `path_pattern` > `none`),
path-pattern attribution is opt-in and off by default, and a dataset with no
attribution resolves to `unknown` rather than being guessed from filenames. But
until Module 3 signs the sidecar, **attribution is a claim, not a fact**.

An adversary can dilute contributor-level detection by spreading a campaign
across every contributor — by construction there is then no cohort to stand out
against. Sample-level findings survive, which is why the report carries both
levels.

## 5. Feature space

The default embedding is a 614-dimensional deterministic classical descriptor,
chosen because a pretrained CNN would require downloading weights (violating the
air gap) and would make every downstream number depend on an artifact whose own
provenance we would then have to assure.

A task-trained embedding would improve label-consistency and OOD sensitivity.
Measured recall in this build reflects the classical space. The optional CNN
backend exists behind the same interface for deployments that can vendor
weights.

The clearest path to better label-flip recall is **Confident Learning**
(Northcutt et al., 2021), which needs a model's cross-validated predicted
probabilities. That becomes available once Module 2 can vouch for a model's
integrity; see `docs/research.md` §4.

## 6. Calibration

`CALIBRATED` confidence is the Wilson 95% lower bound of precision **measured on
the synthetic attack-lab corpus**. That is a defensible lower bound on evidence
quality and an honest statement about detector behaviour on those scenarios. It
is **not** an operational guarantee for imagery the system has never seen.
Recalibration against representative data is a deployment step. Every report
that uses a calibration table prints its provenance and this caveat.

With no calibration table loaded, threshold-based detectors report
`HEURISTIC_UNCALIBRATED` confidence capped at 0.60, and cannot recommend
quarantine.

## 7. Evaluation population

All metrics in this repository were measured on a synthetic corpus generated by
`cvtrust.attack_lab.synth` under published seeds. A generated corpus is the only
kind where *clean* ground truth is known with certainty, which is what makes a
measured false-positive rate meaningful — but it is not operational imagery, and
the synthetic classes are more separable in the classical feature space than
real aerial or ground imagery would be. Expect the label and OOD detectors to
perform worse on real data, and recalibrate.

## 8. Cryptographic and operational limitations

- **Manifests are unsigned until Module 3.** Manifest *self*-tampering is
  detected, but an adversary with write access could replace a manifest stored
  alongside the dataset or model with a self-consistent forgery. **Store
  baseline manifests separately.** This applies to model manifests exactly as it
  does to dataset manifests.
- **A reference model is a trust assumption, not a fact.** Every
  reference-dependent model claim assumes the reference came through a channel
  independent of the one that supplied the artifact under assessment.
- `dataset_tamper` detection requires the analyst to hold a manifest from before
  the tampering. A scan alone cannot tell you a dataset changed; only a
  comparison against an earlier baseline can.
- The tool trusts its own configuration file; protect it with filesystem
  permissions.
- Image decoding is not sandboxed. A Pillow/libjpeg vulnerability would be
  reachable from a malicious image. Model **deserialisation** is a larger
  surface still: an ONNX protobuf, a TorchScript archive and above all a torch
  pickle are all parsed by third-party code. For a hostile deployment, run scans
  and model assessments as an unprivileged user in a container or VM with no
  network.

## 9. Scale

Near-duplicate search is exact all-pairs — deliberately, because an approximate
answer in an assurance context trades a guarantee for a constant factor. Above
`near_duplicate.max_pairwise_samples` (default 50,000) the detector **refuses and
reports `NOT_ASSESSED`** rather than silently subsampling. Datasets beyond that
need either a raised limit and more time, or an approximate-search extension
whose approximation would have to be declared in the coverage statement.

## 10. What this system does not claim

It does not claim to detect every possible attack on a computer-vision pipeline.
It claims to detect the threats listed as `SUPPORTED` or `PARTIAL`, to produce
recomputable evidence for every finding, to quantify confidence with a declared
basis, and to state explicitly what it did not assess.

It does not claim that any model is safe. It claims that specified tests ran
under a recorded access mode against a recorded probe battery, and reports what
they found — including, in two documented cases, that a published method did not
work here and was demoted rather than shipped firing incorrectly.
