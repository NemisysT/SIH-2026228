"""Activation analysis: spectral signatures and activation clustering.

Two published backdoor-detection methods, and one important honesty note about
how we apply them.

The methods
-----------
**Spectral signatures** — Tran, Li & Madry, *Spectral Signatures in Backdoor
Attacks*, NeurIPS 2018.  The observation is that a backdoor installed by data
poisoning leaves the poisoned examples separated from the clean ones along the
**top singular direction** of the class's learned representation matrix.  The
detector centres the representations of one predicted class, takes the top right
singular vector, and scores each example by its squared projection onto it.  The
top ε fraction by that score is the candidate poisoned set.

**Activation clustering** — Chen, Carvalho, Baracaldo, Ludwig, Edwards, Lee,
Molloy & Srivastava, *Detecting Backdoor Attacks on Deep Neural Networks by
Activation Clustering*, AAAI-19 SafeAI workshop.  The observation is that within
one class the activations of clean and poisoned examples form **two separable
clusters**, with the poisoned cluster being the small one.  The detector reduces
the class's activations to a few dimensions and runs 2-means; a high silhouette
score with a small minority cluster is the backdoor signature.

The honesty note that matters
-----------------------------
Both were published as **training-set** poisoning detectors.  They assume access
to the poisoned training data and look for the poisoned subset *inside it*.  We
do not have the supplier's training set — the premise of Module 2 is that we
have the model and nothing else we can trust.

So we apply them to the **probe battery** instead, whose trigger-probe portion
plays the role the poisoned subset plays in the original setting.  That
adaptation changes what the methods can claim, and the change is reported with
every finding:

* They no longer detect "this training set was poisoned".
* They detect "this model maps a subset of *our probes* into an anomalously
  separated representation region", which is a real and useful signal when the
  separated subset coincides with the trigger probes — and is a materially
  weaker claim than the papers make.
* A clean model shown a battery containing trigger probes may legitimately
  separate them (a bright patch *is* a visual difference), so separation alone
  is not the finding.  The finding requires the separation to **coincide with
  the trigger probes and be accompanied by a targeted transition**, which is why
  this module reports the coincidence rather than the raw cluster split.

This is recorded in ``docs/research.md`` as an adaptation, not presented as the
original method.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from ..core.errors import DetectorUnavailable
from ..core.logging import get_logger
from .base import Capability, ModelAdapter, ModelHandle
from .battery import TRIGGER_PROBE, ReferenceBattery

log = get_logger("models.activations")

ACTIVATION_ANALYSIS_VERSION = "1.0"

#: Fraction of a class's examples the spectral-signature method removes as
#: candidates.  Tran et al. use 1.5× the assumed poison rate; with no assumed
#: rate available we use 0.15, which is the operating point their evaluation
#: reports for an unknown-rate setting, and we report it so the choice is
#: visible rather than buried.
DEFAULT_SPECTRAL_EPSILON = 0.15

#: Minimum examples in a predicted class before either method is attempted.
#: Below this, a top singular vector and a 2-means split are both fitting noise,
#: and the honest output is "not assessed for this class" rather than a number.
MIN_CLASS_SUPPORT = 12

#: Dimensions retained before clustering.  Chen et al. use ICA to 10
#: independent components; we use PCA to the same dimensionality because it is
#: deterministic (FastICA's fixed-point iteration is seed-dependent and its
#: component order is not stable), and determinism is a hard requirement here.
CLUSTER_COMPONENTS = 10


def capture_representations(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    *,
    layer: str | None = None,
    batch_size: int = 32,
) -> tuple[np.ndarray, str]:
    """Capture a flattened representation for every probe.

    Returns ``(N, D)`` plus the name of the layer it came from.  The default
    layer is the **last** tap the adapter offers, which is the penultimate
    representation in every architecture we support — that is the layer both
    papers operate on, because it is where class structure is most linearly
    expressed.
    """
    handle.require(Capability.ACTIVATIONS, "activation analysis")
    taps = adapter.activation_layers(handle)
    if not taps:
        raise DetectorUnavailable(
            f"activation analysis unavailable: the '{handle.model_format}' adapter "
            "exposes no intermediate tensors for this artifact"
        )
    chosen = layer if layer in taps else taps[-1]

    chunks: list[np.ndarray] = []
    total = battery.tensor.shape[0]
    for start in range(0, total, batch_size):
        output = adapter.infer(
            handle, battery.tensor[start:start + batch_size], capture=(chosen,)
        )
        captured = output.activations.get(chosen)
        if captured is None:
            raise DetectorUnavailable(
                f"activation analysis unavailable: layer {chosen!r} produced no "
                "tensor during capture"
            )
        chunks.append(np.asarray(captured, dtype=np.float64).reshape(captured.shape[0], -1))
    matrix = np.concatenate(chunks, axis=0)
    log.info("captured activations from %s: %s", chosen, matrix.shape)
    return matrix, chosen


def spectral_signature(
    representations: np.ndarray,
    predictions: np.ndarray,
    *,
    epsilon: float = DEFAULT_SPECTRAL_EPSILON,
    min_support: int = MIN_CLASS_SUPPORT,
) -> dict[str, Any]:
    """Tran, Li & Madry (NeurIPS 2018), applied per predicted class.

    For each class: centre the representation matrix, take the top right
    singular vector ``v``, and score each row by ``(r · v)²``.  The top
    ``epsilon`` fraction is the candidate set.

    ``separation`` is reported per class as the ratio of the mean score inside
    the candidate set to the mean score outside it.  A large ratio means the
    class's representations really do have a dominant outlier direction; a ratio
    near 1 means the top singular direction is describing ordinary variance, and
    the "candidates" are just the tail of a unimodal distribution.
    """
    representations = np.asarray(representations, dtype=np.float64)
    predictions = np.asarray(predictions, dtype=int)
    by_class: dict[int, dict[str, Any]] = {}
    skipped: dict[str, int] = {}

    for class_index in sorted(set(predictions.tolist())):
        members = np.flatnonzero(predictions == class_index)
        if members.size < min_support:
            skipped[str(class_index)] = int(members.size)
            continue
        block = representations[members]
        centred = block - block.mean(axis=0, keepdims=True)
        try:
            # Only the top singular vector is needed; full_matrices=False keeps
            # the decomposition to the economy size.
            _, singular_values, right = np.linalg.svd(centred, full_matrices=False)
        except np.linalg.LinAlgError as exc:  # pragma: no cover - defensive
            skipped[str(class_index)] = -1
            log.warning("SVD failed for class %s: %s", class_index, exc)
            continue
        top = right[0]
        scores = (centred @ top) ** 2
        k = max(1, int(np.ceil(epsilon * members.size)))
        order = np.argsort(-scores)
        candidate_local = order[:k]
        rest_local = order[k:]
        inside = float(np.mean(scores[candidate_local]))
        outside = float(np.mean(scores[rest_local])) if rest_local.size else 0.0
        spectral_energy = (
            float(singular_values[0] ** 2 / np.sum(singular_values**2))
            if singular_values.size and np.sum(singular_values**2) > 0
            else 0.0
        )
        by_class[int(class_index)] = {
            "class": int(class_index),
            "n": int(members.size),
            "epsilon": epsilon,
            "candidates": [int(members[i]) for i in candidate_local.tolist()],
            "mean_score_inside": round(inside, 6),
            "mean_score_outside": round(outside, 6),
            "separation_ratio": round(inside / outside, 4) if outside > 1e-12 else None,
            "top_singular_energy_share": round(spectral_energy, 4),
        }

    return {
        "method": "spectral_signature",
        "origin": "Tran, Li & Madry, NeurIPS 2018",
        "analysis_version": ACTIVATION_ANALYSIS_VERSION,
        "epsilon": epsilon,
        "by_class": by_class,
        "skipped_classes_low_support": skipped,
        "min_support": min_support,
        "adaptation": (
            "the original method scores the poisoned TRAINING SET; here it scores "
            "the probe battery, so it identifies probes the model maps into an "
            "outlying representation direction, not poisoned training examples"
        ),
    }


def activation_clustering(
    representations: np.ndarray,
    predictions: np.ndarray,
    *,
    components: int = CLUSTER_COMPONENTS,
    min_support: int = MIN_CLASS_SUPPORT,
    seed: int = 0,
) -> dict[str, Any]:
    """Chen et al. (AAAI-19 SafeAI), applied per predicted class.

    Per class: reduce to ``components`` dimensions, run 2-means, report the
    silhouette score and the minority-cluster share.  The published backdoor
    signature is a **well-separated** split (high silhouette) with a **small**
    minority cluster — a clean class splits either poorly or evenly.

    ``n_init`` and the seed are pinned, and PCA is used rather than the paper's
    ICA, because FastICA's component order is not stable across runs and this
    system's determinism requirement is not negotiable.
    """
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    from sklearn.metrics import silhouette_score

    representations = np.asarray(representations, dtype=np.float64)
    predictions = np.asarray(predictions, dtype=int)
    by_class: dict[int, dict[str, Any]] = {}
    skipped: dict[str, int] = {}

    for class_index in sorted(set(predictions.tolist())):
        members = np.flatnonzero(predictions == class_index)
        if members.size < min_support:
            skipped[str(class_index)] = int(members.size)
            continue
        block = representations[members]
        n_components = int(min(components, block.shape[0] - 1, block.shape[1]))
        if n_components < 2:
            skipped[str(class_index)] = int(members.size)
            continue
        reduced = PCA(n_components=n_components, random_state=seed).fit_transform(block)
        kmeans = KMeans(n_clusters=2, n_init=10, random_state=seed).fit(reduced)
        labels = kmeans.labels_
        if len(set(labels.tolist())) < 2:
            skipped[str(class_index)] = int(members.size)
            continue
        counts = np.bincount(labels, minlength=2)
        minority = int(counts.argmin())
        silhouette = float(silhouette_score(reduced, labels))
        by_class[int(class_index)] = {
            "class": int(class_index),
            "n": int(members.size),
            "components": n_components,
            "silhouette": round(silhouette, 4),
            "cluster_sizes": [int(counts[0]), int(counts[1])],
            "minority_share": round(float(counts[minority] / members.size), 4),
            "minority_members": [
                int(members[i]) for i in np.flatnonzero(labels == minority).tolist()
            ],
        }

    return {
        "method": "activation_clustering",
        "origin": "Chen et al., AAAI-19 SafeAI workshop",
        "analysis_version": ACTIVATION_ANALYSIS_VERSION,
        "by_class": by_class,
        "skipped_classes_low_support": skipped,
        "min_support": min_support,
        "dimensionality_reduction": "PCA (deterministic) in place of the paper's "
                                    "ICA, whose component order is not stable "
                                    "across runs",
        "adaptation": (
            "the original method clusters TRAINING-SET activations; here it "
            "clusters battery activations, so a separated minority cluster is a "
            "statement about probes, not about the supplier's training data"
        ),
    }


def trigger_coincidence(
    candidate_indices: Sequence[int], battery: ReferenceBattery
) -> dict[str, Any]:
    """How far a flagged set coincides with the battery's trigger probes.

    This is the step that turns a raw cluster split into evidence.  A clean
    model *will* separate a bright corner patch from a clean image — that is a
    visual difference, not a backdoor — so separation alone must never be the
    finding.  What distinguishes a backdoored model is that the separated set
    is the trigger set *and* the model's predictions on it are targeted.

    Precision and recall are both reported because they fail in opposite
    directions: high recall with low precision means the method flagged
    everything, and high precision with low recall means it found one trigger
    variant out of many.
    """
    trigger_indices = set(int(i) for i in battery.indices(TRIGGER_PROBE).tolist())
    candidates = set(int(i) for i in candidate_indices)
    if not candidates:
        return {"n_candidates": 0, "precision": None, "recall": None}
    hits = candidates & trigger_indices
    return {
        "n_candidates": len(candidates),
        "n_trigger_probes": len(trigger_indices),
        "n_candidates_that_are_trigger_probes": len(hits),
        "precision": round(len(hits) / len(candidates), 4),
        "recall": (
            round(len(hits) / len(trigger_indices), 4) if trigger_indices else None
        ),
        "note": "coincidence with the trigger probes is what distinguishes a "
                "backdoor signature from a model simply separating visually "
                "distinct inputs, which a clean model also does",
    }


def analyse_activations(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    predictions: np.ndarray,
    *,
    layer: str | None = None,
    epsilon: float = DEFAULT_SPECTRAL_EPSILON,
    min_support: int = MIN_CLASS_SUPPORT,
    seed: int = 0,
) -> dict[str, Any]:
    """Run both methods and report their coincidence with the trigger probes."""
    representations, used_layer = capture_representations(
        handle, adapter, battery, layer=layer
    )
    spectral = spectral_signature(
        representations, predictions, epsilon=epsilon, min_support=min_support
    )
    clustering = activation_clustering(
        representations, predictions, min_support=min_support, seed=seed
    )

    spectral_candidates: list[int] = []
    for entry in spectral["by_class"].values():
        spectral_candidates.extend(entry["candidates"])
    clustering_candidates: list[int] = []
    for entry in clustering["by_class"].values():
        clustering_candidates.extend(entry["minority_members"])

    # The tap session has served its purpose; releasing it here keeps one
    # extra runtime session (and its thread pools) from outliving the analysis.
    handle.release_caches()

    return {
        "analysis_version": ACTIVATION_ANALYSIS_VERSION,
        "access_mode": handle.access_mode.value,
        "layer_inspected": used_layer,
        "layers_available": list(adapter.activation_layers(handle)),
        "representation_shape": list(representations.shape),
        "spectral_signature": spectral,
        "activation_clustering": clustering,
        "spectral_trigger_coincidence": trigger_coincidence(spectral_candidates, battery),
        "clustering_trigger_coincidence": trigger_coincidence(
            clustering_candidates, battery
        ),
    }
