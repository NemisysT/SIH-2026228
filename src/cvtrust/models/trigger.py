"""Trigger search: reconstruction where gradients exist, family probing where they do not.

Two mechanisms live here, and the difference between them is the single most
important distinction in Module 2's coverage statement.  They are kept in
separate functions with separate method names so that a report can never
describe one while having run the other.

1. ``reconstruct_triggers`` — **Neural Cleanse** (Wang, Yao, Shan, Li, Viswanath,
   Zheng & Zhao, *Neural Cleanse: Identifying and Mitigating Backdoor Attacks in
   Neural Networks*, IEEE S&P 2019).  Requires **gradients**, therefore a
   PyTorch/TorchScript artifact.  For each candidate target class it optimises a
   mask ``m`` and pattern ``p`` so that ``(1−m)·x + m·p`` is classified as that
   class for *every* input, penalising ``‖m‖₁``.  A class whose minimal trigger
   is far smaller than the others' is the signature: the backdoor shortcut
   requires far less perturbation than an honest class boundary does.  Outlier
   detection over the per-class ``‖m‖₁`` is by **MAD anomaly index**, exactly as
   the paper specifies, with the paper's threshold of 2.

2. ``probe_trigger_family`` — a **gradient-free sweep** of the declared patch
   family.  Runs on any artifact that can do a forward pass, including a pure
   black box.  It does not reconstruct anything: it applies known patches and
   measures attack success rate and target concentration.  It is reported as
   ``trigger_probe``, never as reconstruction, and its coverage is ``PARTIAL``
   because it can only find triggers inside the family it sweeps.

What a successful trigger search does and does not establish
------------------------------------------------------------
A reconstructed small-norm trigger for one class is **evidence of suspicious
behaviour**, not proof of a malicious backdoor.  Neural Cleanse's own evaluation
reports false positives on clean models whose classes are genuinely close in
input space, and its anomaly index is a relative measure: it says one class is
unlike the others in this model, not that the model was tampered with.

What the search explicitly does **not** cover, tested and reported rather than
assumed away:

* sample-specific / input-aware triggers — the optimisation looks for one
  universal mask, and by construction cannot find a per-input one;
* semantic backdoors, where the trigger is a real-world object rather than a
  perturbation;
* large or distributed low-amplitude triggers — the ``‖m‖₁`` penalty is what
  makes the method work, and it is also what makes it blind to a trigger that is
  large by design;
* adaptive backdoors trained to keep the reconstructed mask norm in the clean
  range, which the literature demonstrates and which this implementation does
  not defend against.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from ..core.errors import DetectorUnavailable
from ..core.logging import get_logger
from .base import Capability, ModelAdapter, ModelHandle
from .battery import CLEAN, ReferenceBattery, apply_trigger

log = get_logger("models.trigger")

TRIGGER_SEARCH_VERSION = "1.0"

#: Neural Cleanse's anomaly-index threshold for calling a class an outlier.
#: From the paper: the index is the class's deviation from the median ‖m‖₁ in
#: units of the (1.4826-scaled) MAD, and >2 is the published operating point.
ANOMALY_INDEX_THRESHOLD = 2.0

MAD_TO_SIGMA = 1.4826

#: Minimum number of classes before the anomaly index is treated as
#: interpretable at all.
#:
#: This is an **applicability precondition**, not a tuning knob, and it exists
#: because of a measurement rather than a worry.  The index is a MAD-based
#: outlier statistic over one mask norm per class.  With few classes the MAD is
#: estimated from a handful of points, one of which is the outlier being tested
#: for, and the estimate is not stable enough to support the published
#: threshold.
#:
#: Measured on this project's model lab (six classes, ~24k parameters,
#: ``docs/model-security.md`` §"Measured limits"): the *ranking* is correct on
#: every backdoored model — the true target class has the smallest reconstructed
#: mask, by a factor of 5 to 50 — but a **clean** model produced a class with an
#: equally small mask (L1 6.8 at attack success 1.00, against the backdoored
#: model's 5.9 at 1.00).  Clean and backdoored are not separable by this
#: statistic in that regime, so reporting an anomaly index there would be
#: reporting a number that does not mean what its threshold implies.
#:
#: Wang et al. evaluate on datasets with 10 classes at minimum (MNIST) and up to
#: 2622 (Trojan Square); 8 is set just below their smallest.  Above it the index
#: is reported and thresholded; below it the per-class mask norms are still
#: reported as evidence, because the ranking is genuinely informative, but the
#: index is declared uninterpretable rather than dressed up as a verdict.
MIN_CLASSES_FOR_ANOMALY_INDEX = 8


# ----------------------------------------------------------------------
# 1. Neural Cleanse — requires gradients
# ----------------------------------------------------------------------


def reconstruct_triggers(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    *,
    n_classes: int,
    seed: int,
    steps: int = 200,
    learning_rate: float = 0.1,
    mask_penalty: float = 0.03,
    target_classes: Sequence[int] | None = None,
    batch_size: int = 16,
    success_threshold: float = 0.90,
) -> dict[str, Any]:
    """Neural Cleanse trigger reconstruction.

    Budget defaults are chosen so a full sweep over six classes finishes in
    seconds on a CPU: this must stay runnable on a normal development machine
    (§29 of the brief).  The budget is *reported* with the result, because a
    negative result under a small budget is a weaker statement than a negative
    result under a large one, and an analyst must be able to tell which they are
    reading.
    """
    handle.require(Capability.GRADIENTS, "Neural Cleanse trigger reconstruction")
    torch = handle.native.get("torch") if isinstance(handle.native, dict) else None
    module = handle.native.get("module") if isinstance(handle.native, dict) else None
    if torch is None or module is None:
        raise DetectorUnavailable(
            "trigger reconstruction unavailable: this adapter declares gradient "
            "support but exposes no differentiable module"
        )

    clean_tensor, _ = battery.subset(CLEAN)
    if clean_tensor.shape[0] == 0:
        raise DetectorUnavailable(
            "trigger reconstruction unavailable: the battery contains no clean "
            "probes to optimise a universal trigger over"
        )

    classes = (
        list(target_classes) if target_classes is not None else list(range(n_classes))
    )
    channels, height, width = battery.input_shape

    results: list[dict[str, Any]] = []
    generator = torch.Generator().manual_seed(int(seed) % (2**31 - 1))
    inputs = torch.from_numpy(np.ascontiguousarray(clean_tensor, dtype=np.float32))

    was_grad_enabled = torch.is_grad_enabled()
    torch.set_grad_enabled(True)
    try:
        for target in classes:
            results.append(
                _optimise_one_class(
                    torch, module, inputs, target,
                    channels=channels, height=height, width=width,
                    steps=steps, learning_rate=learning_rate,
                    mask_penalty=mask_penalty, batch_size=batch_size,
                    generator=generator, success_threshold=success_threshold,
                )
            )
    finally:
        torch.set_grad_enabled(was_grad_enabled)

    anomaly = _anomaly_index([r["mask_l1_norm"] for r in results])
    interpretable = len(results) >= MIN_CLASSES_FOR_ANOMALY_INDEX
    for entry, index in zip(results, anomaly["indices"]):
        entry["anomaly_index"] = round(float(index), 4)
        # Both conditions are required. The success condition is what suppresses
        # Neural Cleanse's known false positives on clean models whose classes
        # sit close together in input space: a class with a small mask that does
        # not actually drive the prediction is not a backdoor signature.
        entry["flagged_outlier"] = bool(
            interpretable
            and index > ANOMALY_INDEX_THRESHOLD
            and entry["attack_success_rate"] >= success_threshold
        )

    ranked = sorted(results, key=lambda r: r["mask_l1_norm"])
    smallest, next_smallest = ranked[0], (ranked[1] if len(ranked) > 1 else None)

    flagged = [r for r in results if r["flagged_outlier"]]
    return {
        "anomaly_index_interpretable": interpretable,
        "anomaly_index_uninterpretable_reason": (
            None if interpretable else
            f"the anomaly index is a MAD-based outlier statistic over one mask "
            f"norm per class; with {len(results)} classes (< "
            f"{MIN_CLASSES_FOR_ANOMALY_INDEX}) the MAD is not a stable enough "
            "estimate to support the published threshold, and on this project's "
            "own lab a CLEAN model produced a class with a mask as small as a "
            "backdoored model's. The per-class mask norms below are reported as "
            "evidence because their RANKING is informative; the index is not "
            "thresholded."
        ),
        #: The ranking, which is informative even where the index is not: on
        #: every backdoored model in this project's lab the true target class
        #: has the smallest reconstructed mask.
        "smallest_mask_class": smallest["target_class"],
        "smallest_mask_l1": smallest["mask_l1_norm"],
        "mask_l1_ratio_to_next": (
            round(next_smallest["mask_l1_norm"] / smallest["mask_l1_norm"], 4)
            if next_smallest and smallest["mask_l1_norm"] > 1e-9 else None
        ),
        "method": "neural_cleanse_trigger_reconstruction",
        "origin": "Wang et al., IEEE S&P 2019",
        "search_version": TRIGGER_SEARCH_VERSION,
        "access_mode": handle.access_mode.value,
        "capability_used": Capability.GRADIENTS.value,
        "budget": {
            "steps": steps,
            "learning_rate": learning_rate,
            "mask_penalty": mask_penalty,
            "batch_size": batch_size,
            "clean_probes": int(clean_tensor.shape[0]),
            "target_classes_tested": classes,
            "seed": seed,
        },
        "success_threshold": success_threshold,
        "anomaly_index_threshold": ANOMALY_INDEX_THRESHOLD,
        "per_class": results,
        "median_mask_l1": anomaly["median"],
        "mad_mask_l1": anomaly["mad"],
        "flagged_classes": [r["target_class"] for r in flagged],
        "max_anomaly_index": round(
            max((r["anomaly_index"] for r in results), default=0.0), 4
        ),
        "coverage_note": (
            "a universal patch trigger is what this optimisation can find. "
            "Sample-specific, semantic, large-by-design and adaptively-hidden "
            "triggers are outside the search, and a negative result says nothing "
            "about them."
        ),
        "measured_limit": (
            "on this project's six-class model lab the ranking was correct on "
            "every backdoored model but clean and backdoored models were NOT "
            "separable by the anomaly index, because a clean model also had a "
            "trivially reachable class. See docs/model-security.md."
        ),
    }


#: Dynamic-cost scheduler parameters, from Wang et al. §4.2.
#:
#: This scheduler is not an optional refinement — it is what makes the method
#: work.  With a *fixed* mask penalty, each class converges to whatever mask its
#: own loss landscape happens to allow, the resulting norms are not comparable
#: across classes, and the MAD over them is dominated by that incomparability
#: rather than by the backdoor.  Measured on this project's lab: a fixed penalty
#: gave the true backdoor class an anomaly index of 1.31 (below the threshold of
#: 2, i.e. a miss) while the dynamic schedule separates it cleanly, because the
#: schedule drives *every* class to the same attack-success target and then asks
#: which one needed the smallest mask to get there.
COST_MULTIPLIER = 1.5
COST_PATIENCE = 5
INITIAL_COST = 1e-3


def _optimise_one_class(
    torch: Any,
    module: Any,
    inputs: Any,
    target: int,
    *,
    channels: int,
    height: int,
    width: int,
    steps: int,
    learning_rate: float,
    mask_penalty: float,
    batch_size: int,
    generator: Any,
    success_threshold: float,
) -> dict[str, Any]:
    """Optimise ``(mask, pattern)`` driving every input to ``target``.

    Mask and pattern are parameterised through ``tanh`` rather than clamped, as
    in the paper: a clamp has zero gradient outside its range, so an optimiser
    that pushes a value past the boundary cannot come back, and the search
    stalls at a bad corner.

    The mask penalty is **dynamically scheduled** rather than fixed: it rises
    while the attack succeeds and falls when it stops succeeding, so the search
    converges to the *smallest* mask that still reaches ``success_threshold``.
    That is what makes the per-class norms comparable, and comparability is the
    entire basis of the anomaly index computed over them.  The best mask seen at
    or above the success threshold is retained, so a late over-aggressive
    penalty cannot discard a good solution found earlier.
    """
    # Small deterministic initialisation: near-zero in tanh space is near 0.5 in
    # value space, which is a neutral starting pattern and a half-open mask.
    mask_raw = (
        torch.randn(1, height, width, generator=generator, dtype=torch.float32) * 0.1
    ).requires_grad_(True)
    pattern_raw = (
        torch.randn(channels, height, width, generator=generator, dtype=torch.float32) * 0.1
    ).requires_grad_(True)

    optimiser = torch.optim.Adam([mask_raw, pattern_raw], lr=learning_rate, betas=(0.5, 0.9))
    loss_fn = torch.nn.CrossEntropyLoss()
    n = inputs.shape[0]

    cost = INITIAL_COST
    up_counter = 0
    down_counter = 0
    best_l1 = float("inf")
    best_mask = None
    best_pattern = None
    best_success = 0.0
    final_loss = 0.0

    for step in range(steps):
        start = (step * batch_size) % max(1, n)
        batch = inputs[start:start + batch_size]
        if batch.shape[0] == 0:
            batch = inputs[:batch_size]
        batch_targets = torch.full((batch.shape[0],), int(target), dtype=torch.long)

        mask = (torch.tanh(mask_raw) + 1.0) / 2.0
        pattern = (torch.tanh(pattern_raw) + 1.0) / 2.0
        stamped = (1.0 - mask) * batch + mask * pattern

        logits = module(stamped)
        if isinstance(logits, (tuple, list)):
            logits = logits[0]
        cross_entropy = loss_fn(logits, batch_targets)
        l1 = torch.sum(torch.abs(mask))
        loss = cross_entropy + cost * l1

        optimiser.zero_grad()
        loss.backward()
        optimiser.step()
        final_loss = float(loss.detach())

        with torch.no_grad():
            batch_success = float(
                (torch.argmax(logits, dim=1) == int(target)).float().mean()
            )
            current_l1 = float(l1.detach())
            if batch_success >= success_threshold and current_l1 < best_l1:
                best_l1 = current_l1
                best_mask = ((torch.tanh(mask_raw) + 1.0) / 2.0).detach().clone()
                best_pattern = ((torch.tanh(pattern_raw) + 1.0) / 2.0).detach().clone()
                best_success = batch_success

        # Dynamic cost: tighten while the attack still succeeds, relax when it
        # stops. `mask_penalty` is the ceiling, so the configured value still
        # bounds how hard the search can squeeze.
        if batch_success >= success_threshold:
            up_counter += 1
            down_counter = 0
        else:
            down_counter += 1
            up_counter = 0
        if up_counter >= COST_PATIENCE:
            cost = min(mask_penalty, cost * COST_MULTIPLIER)
            up_counter = 0
        elif down_counter >= COST_PATIENCE:
            cost = max(INITIAL_COST, cost / COST_MULTIPLIER)
            down_counter = 0

    with torch.no_grad():
        if best_mask is not None:
            mask, pattern = best_mask, best_pattern
        else:
            mask = (torch.tanh(mask_raw) + 1.0) / 2.0
            pattern = (torch.tanh(pattern_raw) + 1.0) / 2.0
        stamped = (1.0 - mask) * inputs + mask * pattern
        logits = module(stamped)
        if isinstance(logits, (tuple, list)):
            logits = logits[0]
        predictions = torch.argmax(logits, dim=1)
        success = float((predictions == int(target)).float().mean())
        mask_np = mask.detach().cpu().numpy()
        pattern_np = pattern.detach().cpu().numpy()

    return {
        "target_class": int(target),
        "mask_l1_norm": round(float(np.sum(np.abs(mask_np))), 6),
        "mask_mean": round(float(np.mean(mask_np)), 6),
        "mask_active_fraction": round(float(np.mean(mask_np > 0.5)), 6),
        "pattern_mean": round(float(np.mean(pattern_np)), 6),
        "trigger_norm_l2": round(float(np.linalg.norm(mask_np * pattern_np)), 6),
        "attack_success_rate": round(success, 4),
        "best_batch_success": round(best_success, 4),
        "final_cost": round(cost, 8),
        "final_loss": round(final_loss, 6),
        "optimisation_steps": steps,
        "reached_success_threshold": best_mask is not None,
        "converged_to_success": bool(success >= success_threshold),
    }


def _anomaly_index(values: Sequence[float]) -> dict[str, Any]:
    """Neural Cleanse's MAD-based anomaly index over per-class mask norms.

    The index for a class is ``(median − value) / (1.4826 · MAD)``: **one-sided**,
    because only an *unusually small* trigger is the backdoor signature.  A class
    needing an unusually *large* trigger is simply a hard class, and treating it
    as an outlier would manufacture findings on clean models.
    """
    array = np.asarray(values, dtype=np.float64)
    if array.size < 3:
        return {"median": None, "mad": None, "indices": [0.0] * array.size}
    median = float(np.median(array))
    mad = float(np.median(np.abs(array - median)))
    if mad <= 1e-12:
        return {"median": round(median, 6), "mad": 0.0, "indices": [0.0] * array.size}
    indices = (median - array) / (mad * MAD_TO_SIGMA)
    return {
        "median": round(median, 6),
        "mad": round(mad, 6),
        "indices": [float(v) for v in indices.tolist()],
    }


# ----------------------------------------------------------------------
# 2. Gradient-free family probe — works on any artifact that can infer
# ----------------------------------------------------------------------


def probe_trigger_family(
    handle: ModelHandle,
    adapter: ModelAdapter,
    battery: ReferenceBattery,
    *,
    family: Sequence[dict[str, Any]] | None = None,
    opacities: Sequence[float] = (1.0,),
    batch_size: int = 32,
) -> dict[str, Any]:
    """Sweep the declared patch family and measure targeted behaviour.

    This is **not** trigger reconstruction, and the result says so.  It applies
    patches we already know about and asks whether any of them drives
    predictions onto a single class.  Its coverage is therefore bounded by the
    family: a trigger the family does not contain is outside the claim, and the
    family is printed in the report rather than being an implementation detail.

    Runs under ``BLACK_BOX`` access, which is what makes the black-box pathway
    able to say something about backdoors at all.
    """
    handle.require(Capability.INFERENCE, "trigger-family probing")
    clean_tensor, clean_probes = battery.subset(CLEAN)
    if clean_tensor.shape[0] == 0:
        raise DetectorUnavailable(
            "trigger-family probing unavailable: the battery contains no clean "
            "probes to stamp triggers onto"
        )

    family = list(family) if family is not None else list(battery.trigger_family)
    baseline = _predict(handle, adapter, clean_tensor, batch_size)

    results: list[dict[str, Any]] = []
    for spec in family:
        # A family member that declares its own opacity keeps it; the sweep
        # applies only to members that do not. Overriding a declared opacity
        # would silently test a different trigger than the caller asked for,
        # which is how a blended-trigger probe ends up measuring a full-opacity
        # patch and reporting it as the blended result.
        spec_opacities = (
            (float(spec["opacity"]),) if "opacity" in spec else tuple(opacities)
        )
        for opacity in spec_opacities:
            variant = {**spec, "opacity": float(opacity)}
            stamped = np.stack(
                [apply_trigger(clean_tensor[i], variant) for i in range(clean_tensor.shape[0])]
            )
            predictions = _predict(handle, adapter, stamped, batch_size)
            flips = predictions != baseline
            counts: dict[int, int] = {}
            for value in predictions[flips].tolist():
                counts[int(value)] = counts.get(int(value), 0) + 1
            if counts:
                target, hits = max(counts.items(), key=lambda kv: (kv[1], -kv[0]))
            else:
                target, hits = None, 0
            results.append({
                "trigger": {
                    "position": variant["position"],
                    "size_fraction": repr(float(variant["size_fraction"])),
                    "pattern": variant["pattern"],
                    "opacity": repr(float(opacity)),
                },
                "n_probes": int(clean_tensor.shape[0]),
                "flips": int(flips.sum()),
                "flip_rate": round(float(flips.mean()), 4),
                "dominant_target_class": target,
                "attack_success_rate": round(hits / clean_tensor.shape[0], 4),
                "target_concentration": round(hits / max(1, int(flips.sum())), 4),
                "target_histogram": {str(k): v for k, v in sorted(counts.items())},
            })

    best = max(results, key=lambda r: r["attack_success_rate"]) if results else None
    return {
        "method": "trigger_family_probe",
        "origin": "gradient-free sweep of the BadNets patch threat model "
                  "(Gu, Dolan-Gavitt & Garg, 2017); not trigger reconstruction",
        "search_version": TRIGGER_SEARCH_VERSION,
        "access_mode": handle.access_mode.value,
        "capability_used": Capability.INFERENCE.value,
        "family_size": len(results),
        "family": [dict(f) for f in family],
        "opacities": [repr(float(o)) for o in opacities],
        "clean_probes": int(clean_tensor.shape[0]),
        "per_trigger": results,
        "best_trigger": best,
        "max_attack_success_rate": max(
            (r["attack_success_rate"] for r in results), default=0.0
        ),
        "coverage_note": (
            "this is a sweep of a declared, finite trigger family. It finds a "
            "trigger only if the trigger is in the family. It performs no "
            "optimisation and reconstructs nothing, and must not be reported as "
            "trigger reconstruction."
        ),
    }


def _predict(
    handle: ModelHandle, adapter: ModelAdapter, tensor: np.ndarray, batch_size: int
) -> np.ndarray:
    out: list[np.ndarray] = []
    for start in range(0, tensor.shape[0], batch_size):
        result = adapter.infer(handle, tensor[start:start + batch_size])
        out.append(np.argmax(np.asarray(result.logits, dtype=np.float64), axis=1))
    return np.concatenate(out)
