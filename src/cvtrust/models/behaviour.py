"""Behavioural fingerprinting and the behavioural difference metrics.

A behavioural fingerprint is what a model *does*, measured over a fixed,
digested battery.  It is the only assessment available when the model is a black
box, and it is the assessment that stays meaningful when a white-box one is
ambiguous: parameters can be unusual for benign reasons, but a targeted
transition concentrated on one class under a trigger is a behaviour, not a
statistic about weights.

Choice of metrics
-----------------
The brief asks for a *small* number of strong, explainable metrics rather than
every metric that exists.  Five are implemented, and each is here for a reason
that is written down next to it:

1. ``prediction_agreement`` — the most directly interpretable difference there
   is; an analyst can be shown the disagreeing probes.
2. ``js_divergence`` — Jensen–Shannon, base 2, bounded in [0, 1].
3. ``confidence_shift`` — catches "same answers, different model".
4. ``metamorphic_consistency`` — absolute, needs **no reference model**, which
   is what keeps the black-box pathway meaningful on its own.
5. ``targeted_transition`` — the asymmetry that separates a fragile model from
   backdoor-like behaviour.

Why Jensen–Shannon and not Kullback–Leibler
-------------------------------------------
KL is unbounded and undefined wherever one model assigns a class zero
probability, which softmax underflow produces routinely at float32.  A metric
that is sometimes ``inf`` cannot be thresholded, cannot be averaged, and cannot
be compared across models.  JS is symmetric (there is no privileged model in a
comparison), always finite, and bounded by 1 bit, so values mean the same thing
across runs and across artifacts.  KL is deliberately **not** implemented.

Determinism
-----------
Every float that reaches a digest or a finding id passes through
``digest_safe``/``quantize`` first (ADR-004).  The fingerprint digest is taken
over quantised values, so two runs of the same assessment agree bit for bit even
though the underlying logits are floats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..core.canonical import digest_safe, quantize
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger
from .base import ModelAdapter, ModelHandle
from .battery import CLEAN, OOD, PERTURBATION, TRIGGER_PROBE, ReferenceBattery

log = get_logger("models.behaviour")

FINGERPRINT_VERSION = "1.0"

#: Decimal places used when folding a probability into the fingerprint digest.
#: Four places is finer than any difference these metrics act on and coarse
#: enough to be stable across BLAS implementations.
FINGERPRINT_PLACES = 4


@dataclass
class BehaviouralFingerprint:
    """What one model does on one battery.

    Deterministic for a fixed ``(model, battery, configuration, seed)``: that
    property is asserted by a test, because every behavioural comparison below
    is meaningless without it.
    """

    version: str
    model_id: str
    battery_digest: str
    battery_version: str
    n_probes: int
    n_classes: int
    predictions: np.ndarray            # (N,) int
    probabilities: np.ndarray          # (N, C) float64
    confidence: np.ndarray             # (N,) float64 top-1 probability
    class_frequency: dict[int, int]
    confidence_stats: dict[str, float]
    per_category: dict[str, dict[str, Any]]
    digest: str
    runtime: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "fingerprint_version": self.version,
            "fingerprint_digest": self.digest,
            "battery_digest": self.battery_digest,
            "battery_version": self.battery_version,
            "n_probes": self.n_probes,
            "n_classes": self.n_classes,
            "class_frequency": {str(k): v for k, v in sorted(self.class_frequency.items())},
            "confidence_stats": {k: round(v, 4) for k, v in self.confidence_stats.items()},
            "per_category": self.per_category,
        }


def compute_fingerprint(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    *,
    model_id: str,
    batch_size: int = 32,
) -> BehaviouralFingerprint:
    """Run the battery through a model and summarise what it did."""
    logits = run_battery(handle, adapter, battery, batch_size=batch_size)
    from .base import softmax

    probabilities = softmax(logits) if not _already_normalised(handle, adapter, battery) else logits
    predictions = np.argmax(probabilities, axis=1)
    confidence = probabilities[np.arange(len(predictions)), predictions]

    frequency: dict[int, int] = {}
    for value in predictions.tolist():
        frequency[int(value)] = frequency.get(int(value), 0) + 1

    stats = {
        "mean": float(np.mean(confidence)),
        "p05": float(np.quantile(confidence, 0.05)),
        "median": float(np.median(confidence)),
        "p95": float(np.quantile(confidence, 0.95)),
        "min": float(np.min(confidence)),
        "max": float(np.max(confidence)),
        # A model that is confident on *everything*, including out-of-
        # distribution probes, is behaving differently from one that is not,
        # and this is the cheapest way to see it.
        "fraction_above_0_99": float(np.mean(confidence > 0.99)),
    }

    per_category: dict[str, dict[str, Any]] = {}
    for category in sorted({p.category for p in battery.probes}):
        idx = battery.indices(category)
        if idx.size == 0:
            continue
        cat_conf = confidence[idx]
        cat_pred = predictions[idx]
        per_category[category] = {
            "n": int(idx.size),
            "mean_confidence": round(float(np.mean(cat_conf)), 4),
            "distinct_predictions": int(len(set(cat_pred.tolist()))),
            "modal_class": int(np.bincount(cat_pred, minlength=probabilities.shape[1]).argmax()),
            "modal_share": round(
                float(np.max(np.bincount(cat_pred, minlength=probabilities.shape[1])) / idx.size),
                4,
            ),
        }

    digest = sha256_canonical(
        digest_safe(
            {
                "fingerprint_version": FINGERPRINT_VERSION,
                "battery_digest": battery.digest,
                "predictions": [int(v) for v in predictions.tolist()],
                "probabilities": [
                    [quantize(float(v), FINGERPRINT_PLACES) for v in row]
                    for row in probabilities.tolist()
                ],
            }
        )
    )
    return BehaviouralFingerprint(
        version=FINGERPRINT_VERSION,
        model_id=model_id,
        battery_digest=battery.digest,
        battery_version=battery.version,
        n_probes=int(probabilities.shape[0]),
        n_classes=int(probabilities.shape[1]),
        predictions=predictions,
        probabilities=probabilities,
        confidence=confidence,
        class_frequency=frequency,
        confidence_stats=stats,
        per_category=per_category,
        digest=digest,
        runtime=dict(handle.runtime),
    )


def _already_normalised(
    handle: ModelHandle, adapter: ModelAdapter, battery: ReferenceBattery
) -> bool:
    """Whether the model's primary output is already a distribution.

    Determined once, from a single probe, via the adapter's own declaration
    (which for ONNX reads the graph rather than the values).  Getting this wrong
    means applying softmax twice, which flattens every distribution and silently
    shrinks every divergence toward zero — a failure that would look like "the
    models agree".
    """
    cached = handle.native.get("_already_normalised") if isinstance(handle.native, dict) else None
    if cached is not None:
        return bool(cached)
    output = adapter.infer(handle, battery.tensor[:1])
    value = bool(output.already_normalised)
    if isinstance(handle.native, dict):
        handle.native["_already_normalised"] = value
    return value


def run_battery(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    *,
    batch_size: int = 32,
) -> np.ndarray:
    """Forward the whole battery in fixed-size batches, returning raw outputs.

    Batch size is fixed and recorded rather than adaptive: on some runtimes the
    reduction order inside a batched matmul depends on the batch dimension, so a
    variable batch size would make logits — and therefore an argmax at a
    boundary — depend on how many probes happened to be left over.
    """
    outputs: list[np.ndarray] = []
    total = battery.tensor.shape[0]
    for start in range(0, total, batch_size):
        chunk = battery.tensor[start:start + batch_size]
        result = adapter.infer(handle, chunk)
        outputs.append(np.asarray(result.logits, dtype=np.float64))
    return np.concatenate(outputs, axis=0)


# ----------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------


def js_divergence(p: np.ndarray, q: np.ndarray) -> np.ndarray:
    """Row-wise Jensen–Shannon divergence in bits, bounded in [0, 1].

    ``JS(P‖Q) = ½ KL(P‖M) + ½ KL(Q‖M)`` with ``M = ½(P+Q)``, in base 2.
    Terms where ``p_i = 0`` contribute zero by the convention ``0 log 0 = 0``,
    which is what makes this finite where KL is not.
    """
    p = np.clip(np.asarray(p, dtype=np.float64), 0.0, None)
    q = np.clip(np.asarray(q, dtype=np.float64), 0.0, None)
    p = p / np.clip(p.sum(axis=1, keepdims=True), 1e-12, None)
    q = q / np.clip(q.sum(axis=1, keepdims=True), 1e-12, None)
    m = 0.5 * (p + q)

    def _kl(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        mask = a > 0
        ratio = np.zeros_like(a)
        ratio[mask] = a[mask] * np.log2(a[mask] / np.clip(b[mask], 1e-300, None))
        return ratio.sum(axis=1)

    value = 0.5 * _kl(p, m) + 0.5 * _kl(q, m)
    # Clip the last-bit overshoot that float arithmetic produces at the bound.
    return np.clip(value, 0.0, 1.0)


def prediction_agreement(
    left: BehaviouralFingerprint, right: BehaviouralFingerprint, indices: np.ndarray | None = None
) -> dict[str, Any]:
    """Metric 1 — fraction of probes where two models choose the same class.

    The first thing that moves under substitution, and the easiest thing to show
    an analyst: the disagreeing probe ids are returned so the claim is
    inspectable rather than a number.
    """
    idx = np.arange(left.n_probes) if indices is None else np.asarray(indices, dtype=int)
    if idx.size == 0:
        return {"n": 0, "agreement": None, "disagreements": 0}
    agree = left.predictions[idx] == right.predictions[idx]
    disagreeing = idx[~agree]
    return {
        "n": int(idx.size),
        "agreement": float(np.mean(agree)),
        "disagreements": int(disagreeing.size),
        "disagreement_rate": float(1.0 - np.mean(agree)),
        "disagreeing_indices": [int(v) for v in disagreeing[:20].tolist()],
    }


def distribution_divergence(
    left: BehaviouralFingerprint, right: BehaviouralFingerprint, indices: np.ndarray | None = None
) -> dict[str, Any]:
    """Metric 2 — Jensen–Shannon divergence between the two output distributions."""
    idx = np.arange(left.n_probes) if indices is None else np.asarray(indices, dtype=int)
    if idx.size == 0:
        return {"n": 0, "mean_js": None}
    values = js_divergence(left.probabilities[idx], right.probabilities[idx])
    return {
        "n": int(idx.size),
        "metric": "jensen_shannon_divergence_bits",
        "mean_js": float(np.mean(values)),
        "median_js": float(np.median(values)),
        "p95_js": float(np.quantile(values, 0.95)),
        "max_js": float(np.max(values)),
        "bounded_in": [0.0, 1.0],
        "why_not_kl": "KL is unbounded and undefined at zero probability; JS is "
                      "symmetric, finite and bounded, so values are comparable "
                      "across models and runs",
    }


def confidence_shift(
    left: BehaviouralFingerprint, right: BehaviouralFingerprint, indices: np.ndarray | None = None
) -> dict[str, Any]:
    """Metric 3 — change in top-1 confidence, supplied minus reference.

    Moves under retraining and fine-tuning even when argmax is preserved, which
    is the "same answers, different model" case that agreement alone misses.
    """
    idx = np.arange(left.n_probes) if indices is None else np.asarray(indices, dtype=int)
    if idx.size == 0:
        return {"n": 0, "mean_shift": None}
    delta = left.confidence[idx] - right.confidence[idx]
    return {
        "n": int(idx.size),
        "supplied_mean_confidence": float(np.mean(left.confidence[idx])),
        "reference_mean_confidence": float(np.mean(right.confidence[idx])),
        "mean_shift": float(np.mean(delta)),
        "mean_absolute_shift": float(np.mean(np.abs(delta))),
        "max_absolute_shift": float(np.max(np.abs(delta))),
    }


def metamorphic_consistency(
    fingerprint: BehaviouralFingerprint, battery: ReferenceBattery
) -> dict[str, Any]:
    """Metric 4 — prediction stability under semantics-preserving change.

    Each battery perturbation is chosen so that the correct answer does not
    change, so a flip is a measurement of instability rather than a matter of
    interpretation.  Absolute: no reference model is required, which is what
    keeps the black-box pathway able to say something on its own.
    """
    pairs = battery.metamorphic_pairs()
    if not pairs:
        return {"n_pairs": 0, "consistency": None}
    preserved = 0
    by_kind: dict[str, dict[str, int]] = {}
    flips: list[dict[str, Any]] = []
    for source, perturbed, meta in pairs:
        kind = str(meta.get("kind", "unknown"))
        bucket = by_kind.setdefault(kind, {"n": 0, "preserved": 0})
        bucket["n"] += 1
        same = int(fingerprint.predictions[source]) == int(fingerprint.predictions[perturbed])
        if same:
            preserved += 1
            bucket["preserved"] += 1
        else:
            flips.append({
                "transformation": kind,
                "amount": str(meta.get("amount")),
                "source_prediction": int(fingerprint.predictions[source]),
                "perturbed_prediction": int(fingerprint.predictions[perturbed]),
            })
    return {
        "n_pairs": len(pairs),
        "consistency": preserved / len(pairs),
        "flips": len(pairs) - preserved,
        "by_transformation": {
            k: {**v, "consistency": round(v["preserved"] / v["n"], 4)}
            for k, v in sorted(by_kind.items())
        },
        "flip_examples": flips[:10],
        "interpretation": "each transformation preserves the semantic content of "
                          "the input, so a changed prediction is instability, not "
                          "a different correct answer",
    }


def targeted_transition(
    fingerprint: BehaviouralFingerprint, battery: ReferenceBattery
) -> dict[str, Any]:
    """Metric 5 — do trigger probes push predictions onto *one* class?

    The discriminating observation for a backdoor.  A merely fragile model flips
    predictions in scattered directions under a patch; a backdoored model flips
    them onto the attacker's target class.  So the reported quantity is not "how
    many predictions changed" but "what share of the changes landed on the same
    class, and what is the attack success rate for that class".

    Reported per trigger family member as well as overall, because a family
    member that succeeds while the others do not is far more informative than an
    average over the family.
    """
    pairs = battery.trigger_pairs()
    if not pairs:
        return {"n_pairs": 0, "assessed": False,
                "reason": "battery contains no trigger probes"}

    by_trigger: dict[str, dict[str, Any]] = {}
    overall_flips: list[int] = []
    for source, triggered, meta in pairs:
        key = f"{meta.get('position')}|{meta.get('size_fraction')}|{meta.get('pattern')}"
        bucket = by_trigger.setdefault(
            key, {"trigger": {k: str(v) for k, v in meta.items() if k != "source"},
                  "n": 0, "flips": 0, "targets": {}}
        )
        bucket["n"] += 1
        source_pred = int(fingerprint.predictions[source])
        triggered_pred = int(fingerprint.predictions[triggered])
        if source_pred != triggered_pred:
            bucket["flips"] += 1
            bucket["targets"][triggered_pred] = bucket["targets"].get(triggered_pred, 0) + 1
            overall_flips.append(triggered_pred)

    results: list[dict[str, Any]] = []
    for key, bucket in sorted(by_trigger.items()):
        targets = bucket["targets"]
        if targets:
            target_class, target_count = max(targets.items(), key=lambda kv: (kv[1], -kv[0]))
        else:
            target_class, target_count = None, 0
        results.append({
            "trigger": bucket["trigger"],
            "n_probes": bucket["n"],
            "flips": bucket["flips"],
            "flip_rate": round(bucket["flips"] / bucket["n"], 4),
            "dominant_target_class": target_class,
            # Attack success rate as the backdoor literature defines it: the
            # fraction of *all* triggered probes that land on the single
            # dominant class, not the fraction of flips.
            "attack_success_rate": round(target_count / bucket["n"], 4),
            "target_concentration": round(target_count / max(1, bucket["flips"]), 4),
            "target_histogram": {str(k): v for k, v in sorted(targets.items())},
        })

    best = max(results, key=lambda r: r["attack_success_rate"]) if results else None
    overall_target = None
    overall_concentration = 0.0
    if overall_flips:
        counts: dict[int, int] = {}
        for value in overall_flips:
            counts[value] = counts.get(value, 0) + 1
        overall_target, top = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
        overall_concentration = top / len(overall_flips)

    return {
        "assessed": True,
        "n_pairs": len(pairs),
        "per_trigger": results,
        "best_trigger": best,
        "max_attack_success_rate": max((r["attack_success_rate"] for r in results), default=0.0),
        "overall_dominant_target_class": overall_target,
        "overall_target_concentration": round(overall_concentration, 4),
        "scope": "this measurement is scoped to the declared trigger family in the "
                 "battery; a trigger outside that family is outside this claim",
    }


def ood_confidence_guard(
    fingerprint: BehaviouralFingerprint, battery: ReferenceBattery
) -> dict[str, Any]:
    """Not a detection metric — a guard against the inverse error.

    Module 1's rule that out-of-distribution input is never equated with
    malicious applies here too.  A model behaving strangely on OOD probes is a
    model being shown input outside its declared distribution, which is expected,
    so this measurement exists to be *quoted in limitations* rather than to
    raise a finding.
    """
    idx = battery.indices(OOD)
    if idx.size == 0:
        return {"n": 0, "assessed": False}
    predictions = fingerprint.predictions[idx]
    counts = np.bincount(predictions, minlength=fingerprint.n_classes)
    return {
        "assessed": True,
        "n": int(idx.size),
        "mean_confidence": round(float(np.mean(fingerprint.confidence[idx])), 4),
        "modal_class": int(counts.argmax()),
        "modal_share": round(float(counts.max() / idx.size), 4),
        "note": "out-of-distribution behaviour is reported for context only; it is "
                "never treated as evidence of a backdoor",
    }


def compare_fingerprints(
    supplied: BehaviouralFingerprint,
    reference: BehaviouralFingerprint,
    battery: ReferenceBattery,
) -> dict[str, Any]:
    """All reference-dependent metrics, computed overall and per category.

    Per category matters: a model that agrees on ``clean`` probes but diverges on
    ``borderline`` ones has been retrained, and an average over the battery would
    hide exactly that.
    """
    if supplied.n_classes != reference.n_classes:
        return {
            "comparable": False,
            "reason": (
                f"output dimensions differ: supplied has {supplied.n_classes} "
                f"classes, reference has {reference.n_classes}. The models do not "
                "share a label space, so distributional comparison is undefined; "
                "this is itself strong evidence of substitution."
            ),
            "supplied_classes": supplied.n_classes,
            "reference_classes": reference.n_classes,
        }
    if supplied.battery_digest != reference.battery_digest:
        return {
            "comparable": False,
            "reason": "fingerprints were computed on different batteries; a "
                      "comparison across batteries is not a measurement",
            "supplied_battery_digest": supplied.battery_digest,
            "reference_battery_digest": reference.battery_digest,
        }

    out: dict[str, Any] = {
        "comparable": True,
        "battery_digest": battery.digest,
        "overall": {
            "prediction_agreement": prediction_agreement(supplied, reference),
            "distribution_divergence": distribution_divergence(supplied, reference),
            "confidence_shift": confidence_shift(supplied, reference),
        },
        "by_category": {},
    }
    for category in (CLEAN, "borderline", PERTURBATION, OOD, TRIGGER_PROBE):
        idx = battery.indices(category)
        if idx.size == 0:
            continue
        out["by_category"][category] = {
            "prediction_agreement": prediction_agreement(supplied, reference, idx),
            "distribution_divergence": distribution_divergence(supplied, reference, idx),
            "confidence_shift": confidence_shift(supplied, reference, idx),
        }
    return out
