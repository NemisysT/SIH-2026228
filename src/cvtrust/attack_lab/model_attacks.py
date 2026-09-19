"""Reproducible model-security scenarios.

Extends the Module 1 attack lab; replaces none of it.  The contract is
identical, and it is the contract that makes the measurements trustworthy:

    <scenario>/
      model.onnx            <- the only thing a detector ever sees
      model.pt              <- TorchScript form of the same weights
      ground_truth.json     <- what was actually done
      attack_config.json    <- seed and parameters, sufficient to regenerate

Ground truth lives **outside** the artifact a detector reads, so a detector
cannot read the answer key.  Each scenario is a pure function of
``(reference corpus, seed, parameters)``, so re-running produces identical
models and a reviewer who does not trust our numbers can regenerate them.

The scenario matrix is designed around a principle from §27 of the brief: a lab
containing only attacks our detectors are good at measures nothing.  So it
deliberately includes

* **clean models that look odd** — unusual initialisation scale, a fine-tune —
  because a clean model with unusual weights must not become a finding;
* **a re-serialisation** — identical weights, different bytes — because the
  identity-versus-behaviour distinction is one of the things Module 2 claims and
  must therefore be measured;
* **a blended low-opacity backdoor** (Chen et al. 2017), which is deliberately
  *outside* the patch family our gradient-free probe sweeps, so the measured
  result is expected to be a **miss** — reported as degraded coverage rather
  than hidden.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np

from ..core.evidence import utc_now_iso
from ..core.hashing import sha256_file
from ..core.logging import get_logger
from .model_synth import (
    MODEL_LAB_VERSION,
    export_onnx,
    generate_corpus,
    lab_seed,
    measure_backdoor,
    poison_corpus,
    save_torch,
    train_model,
)

log = get_logger("attack_lab.model_attacks")

MODEL_ATTACK_LAB_VERSION = "1.0"

#: Ground-truth attack-class labels, using the same identifiers the coverage
#: registry already declares.  ``clean`` is not an attack class; it is the
#: absence of one, and it is present so false-positive behaviour is measurable.
CLEAN = "clean"


@dataclass
class ModelScenario:
    """One built scenario, on disk."""

    name: str
    out_dir: Path
    onnx_path: Path
    torchscript_path: Path
    attack_classes: list[str]
    ground_truth: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)

    def write(self) -> None:
        (self.out_dir / "ground_truth.json").write_text(
            json.dumps(self.ground_truth, indent=2, sort_keys=True), encoding="utf-8"
        )
        (self.out_dir / "attack_config.json").write_text(
            json.dumps(self.config, indent=2, sort_keys=True), encoding="utf-8"
        )


@dataclass
class ReferenceBundle:
    """The trusted reference model every scenario is compared against."""

    root: Path
    onnx_path: Path
    torchscript_path: Path
    spec: dict[str, Any]
    corpus_seed: int
    per_class: int
    classes: tuple[str, ...]


def build_reference(
    lab_dir: Path,
    *,
    seed: int = 20260917,
    per_class: int = 60,
    epochs: int = 30,
) -> ReferenceBundle:
    """Train and export the trusted reference model.

    Built once and shared by every scenario, which is what lets the comparison
    be a comparison: if each scenario trained its own reference, a difference
    between supplied and reference would conflate the attack with training
    noise.
    """
    root = Path(lab_dir) / "_reference"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    corpus = generate_corpus(seed=lab_seed(seed, "reference_corpus"), per_class=per_class)
    model, spec = train_model(corpus, seed=lab_seed(seed, "reference_train"), epochs=epochs)

    onnx_path = export_onnx(
        model, root / "reference.onnx",
        metadata={"architecture": "cvtrust_small_cnn", "role": "trusted-reference"},
    )
    torchscript_path = save_torch(model, root / "reference.pt")

    spec = {
        **spec,
        "role": "trusted reference",
        "lab_seed": seed,
        "per_class": per_class,
        "corpus_spec": corpus.spec,
        "onnx_sha256": sha256_file(onnx_path),
        "torchscript_sha256": sha256_file(torchscript_path),
        "created_at": utc_now_iso(),
    }
    (root / "training_spec.json").write_text(
        json.dumps(spec, indent=2, sort_keys=True), encoding="utf-8"
    )
    log.info("reference model built at %s", root)
    return ReferenceBundle(
        root=root,
        onnx_path=onnx_path,
        torchscript_path=torchscript_path,
        spec=spec,
        corpus_seed=lab_seed(seed, "reference_corpus"),
        per_class=per_class,
        classes=corpus.classes,
    )


def _prepare(lab_dir: Path, name: str) -> Path:
    out_dir = Path(lab_dir) / name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    return out_dir


def _finish(
    out_dir: Path,
    name: str,
    attack_classes: Sequence[str],
    seed: int,
    parameters: dict[str, Any],
    detail: dict[str, Any],
    reference: ReferenceBundle,
) -> ModelScenario:
    onnx_path = out_dir / "model.onnx"
    torchscript_path = out_dir / "model.pt"
    scenario = ModelScenario(
        name=name,
        out_dir=out_dir,
        onnx_path=onnx_path,
        torchscript_path=torchscript_path,
        attack_classes=list(attack_classes),
        ground_truth={
            "schema": "cvtrust.model_ground_truth/1.0",
            "scenario": name,
            "attack_classes": list(attack_classes),
            "is_clean": list(attack_classes) == [CLEAN],
            "seed": seed,
            "created_at": utc_now_iso(),
            "supplied_onnx_sha256": sha256_file(onnx_path),
            "supplied_torchscript_sha256": sha256_file(torchscript_path),
            "reference_onnx_sha256": reference.spec["onnx_sha256"],
            "reference_torchscript_sha256": reference.spec["torchscript_sha256"],
            **detail,
        },
        config={
            "model_attack_lab_version": MODEL_ATTACK_LAB_VERSION,
            "model_lab_version": MODEL_LAB_VERSION,
            "scenario": name,
            "attack_classes": list(attack_classes),
            "seed": seed,
            "parameters": parameters,
        },
    )
    scenario.write()
    log.info("model scenario '%s': %s", name, ", ".join(attack_classes))
    return scenario


def _export_pair(model: Any, out_dir: Path, *, architecture: str = "cvtrust_small_cnn") -> None:
    export_onnx(model, out_dir / "model.onnx", metadata={"architecture": architecture})
    save_torch(model, out_dir / "model.pt")


# ----------------------------------------------------------------------
# Clean scenarios — the false-positive floor
# ----------------------------------------------------------------------


def clean_retrain(
    lab_dir: Path, reference: ReferenceBundle, *, seed: int = 101, variant: int = 0,
    epochs: int = 30,
) -> ModelScenario:
    """A clean model, honestly trained, with a different training seed.

    This is the hardest clean case and the most important one: the weights
    legitimately differ from the reference's everywhere, so identity and
    parameter comparison will both say "different". If the backdoor and
    behavioural assessments cannot keep their heads here, the system is
    unusable, because a retrained model is an ordinary operational event.
    """
    name = f"clean_retrain_{variant}"
    out_dir = _prepare(lab_dir, name)
    corpus = generate_corpus(
        seed=lab_seed(seed, "clean_corpus", variant), per_class=reference.per_class
    )
    model, spec = train_model(
        corpus, seed=lab_seed(seed, "clean_train", variant), epochs=epochs
    )
    _export_pair(model, out_dir)
    return _finish(
        out_dir, name, [CLEAN], seed,
        {"variant": variant, "epochs": epochs, "training_seed_differs": True},
        {"training_spec": spec,
         "note": "clean model trained independently of the reference; weights "
                 "differ everywhere for entirely benign reasons"},
        reference,
    )


def clean_unusual_init(
    lab_dir: Path, reference: ReferenceBundle, *, seed: int = 111, init_scale: float = 2.6,
    epochs: int = 30,
) -> ModelScenario:
    """A clean model with deliberately odd weight statistics.

    The adversarial test for the parameter analysis: weights scaled well outside
    the usual initialisation range produce heavy tails, large norms and peer
    outliers, and none of it is an attack. A system that reports this as
    suspicious has learned to detect unusual arithmetic rather than tampering.
    """
    name = "clean_unusual_init"
    out_dir = _prepare(lab_dir, name)
    corpus = generate_corpus(seed=lab_seed(seed, "unusual_corpus"), per_class=reference.per_class)
    model, spec = train_model(
        corpus, seed=lab_seed(seed, "unusual_train"), epochs=epochs, init_scale=init_scale
    )
    _export_pair(model, out_dir)
    return _finish(
        out_dir, name, [CLEAN], seed,
        {"init_scale": repr(init_scale), "epochs": epochs},
        {"training_spec": spec,
         "note": "clean model whose weight statistics are unusual by construction; "
                 "an unusual statistic is not an attack and must not be reported "
                 "as one"},
        reference,
    )


def clean_finetuned(
    lab_dir: Path, reference: ReferenceBundle, *, seed: int = 121, epochs: int = 4,
) -> ModelScenario:
    """The reference, fine-tuned on additional clean data.

    The realistic shape of a *legitimate* weight change: every tensor moves a
    little, behaviour stays close, no backdoor. The parameter analysis should
    describe it as ``distributed`` rather than ``localised``, which is the
    distinction that separates a fine-tune from a targeted edit.
    """
    name = "clean_finetuned"
    out_dir = _prepare(lab_dir, name)
    # A scripted module cannot be fine-tuned in place, so the reference is
    # retrained from its own seed and then tuned. The starting weights are
    # identical to the reference's because training is deterministic — that
    # property is exactly what is being relied on here.
    corpus_ref = generate_corpus(seed=reference.corpus_seed, per_class=reference.per_class)
    start, _ = train_model(
        corpus_ref, seed=lab_seed(reference.spec["lab_seed"], "reference_train"),
        epochs=int(reference.spec["epochs"]),
    )
    extra = generate_corpus(seed=lab_seed(seed, "finetune_corpus"), per_class=max(8, reference.per_class // 3))
    model, spec = train_model(
        extra, seed=lab_seed(seed, "finetune_train"), epochs=epochs,
        learning_rate=0.002, initial_model=start,
    )
    _export_pair(model, out_dir)
    return _finish(
        out_dir, name, [CLEAN], seed,
        {"epochs": epochs, "learning_rate": "0.002", "from": "reference weights"},
        {"training_spec": spec,
         "note": "legitimate fine-tune of the reference on additional clean data; "
                 "weights move everywhere by a small amount"},
        reference,
    )


# ----------------------------------------------------------------------
# Identity scenarios
# ----------------------------------------------------------------------


def reserialised(
    lab_dir: Path, reference: ReferenceBundle, *, seed: int = 131,
) -> ModelScenario:
    """The reference model, re-exported: new bytes, identical weights.

    The case that proves identity and behaviour are separate claims. A
    byte-level check says MISMATCH; the graph and parameter digests say the
    model is the same one; the behavioural fingerprint says behaviour is
    unchanged. A system that collapses those into a single "model changed" flag
    cannot tell an analyst what actually happened.
    """
    name = "reserialised"
    out_dir = _prepare(lab_dir, name)
    corpus_ref = generate_corpus(seed=reference.corpus_seed, per_class=reference.per_class)
    model, _ = train_model(
        corpus_ref, seed=lab_seed(reference.spec["lab_seed"], "reference_train"),
        epochs=int(reference.spec["epochs"]),
    )
    # Re-export with different metadata so the container bytes differ while the
    # weights do not: exactly what a re-packaging step in a supply chain does.
    export_onnx(
        model, out_dir / "model.onnx",
        metadata={"architecture": "cvtrust_small_cnn", "repackaged_at": "lab",
                  "note": "re-exported artifact"},
    )
    save_torch(model, out_dir / "model.pt")
    return _finish(
        out_dir, name, ["model_substitution"], seed,
        {"kind": "reserialisation"},
        {"expected_identity": "MISMATCH",
         "expected_graph": "MATCH",
         "expected_parameters": "MATCH",
         "expected_behaviour": "UNCHANGED",
         "note": "identity mismatch with unchanged weights and behaviour; the "
                 "correct report separates the three rather than merging them"},
        reference,
    )


def substitution_different_architecture(
    lab_dir: Path, reference: ReferenceBundle, *, seed: int = 141, width: int = 24,
    epochs: int = 30,
) -> ModelScenario:
    """A structurally different model served in place of the reference."""
    name = "substitution_architecture"
    out_dir = _prepare(lab_dir, name)
    corpus = generate_corpus(seed=lab_seed(seed, "sub_corpus"), per_class=reference.per_class)
    model, spec = train_model(
        corpus, seed=lab_seed(seed, "sub_train"), epochs=epochs, width=width
    )
    _export_pair(model, out_dir, architecture="cvtrust_small_cnn")
    return _finish(
        out_dir, name, ["model_substitution"], seed,
        {"width": width, "reference_width": reference.spec["width"]},
        {"training_spec": spec,
         "expected_identity": "MISMATCH", "expected_graph": "MISMATCH",
         "note": "a different architecture entirely; the declared architecture "
                 "metadata still says 'cvtrust_small_cnn', which is why the "
                 "manifest treats declared metadata as untrusted"},
        reference,
    )


# ----------------------------------------------------------------------
# Tampering scenarios
# ----------------------------------------------------------------------


def parameter_tamper(
    lab_dir: Path,
    reference: ReferenceBundle,
    *,
    seed: int = 151,
    magnitude: float = 0.5,
    fraction: float = 0.02,
    variant: str = "small",
) -> ModelScenario:
    """Post-training modification of a subset of one layer's weights.

    Modelled as an edit to the *final* linear layer, which is where a
    weight-level attack has the most direct effect on outputs per bit changed.
    The change is localised by construction, so the parameter analysis should
    describe it as ``localised`` and name the tensor.
    """
    name = f"parameter_tamper_{variant}"
    out_dir = _prepare(lab_dir, name)
    from .model_synth import _require_torch

    torch = _require_torch()
    corpus_ref = generate_corpus(seed=reference.corpus_seed, per_class=reference.per_class)
    model, _ = train_model(
        corpus_ref, seed=lab_seed(reference.spec["lab_seed"], "reference_train"),
        epochs=int(reference.spec["epochs"]),
    )

    rng = np.random.default_rng(lab_seed(seed, "tamper", 0))
    target_name, target_param = [
        (n, p) for n, p in model.named_parameters() if n.endswith("weight")
    ][-1]
    with torch.no_grad():
        flat = target_param.view(-1)
        count = max(1, int(round(fraction * flat.numel())))
        indices = np.sort(rng.choice(flat.numel(), size=count, replace=False))
        deltas = rng.normal(0.0, magnitude, size=count)
        for index, delta in zip(indices.tolist(), deltas.tolist()):
            flat[index] += float(delta)

    _export_pair(model, out_dir)
    return _finish(
        out_dir, name, ["model_tampering"], seed,
        {"magnitude": repr(magnitude), "fraction": repr(fraction), "variant": variant},
        {"tampered_tensor": target_name,
         "tampered_elements": int(count),
         "total_elements": int(target_param.numel()),
         "expected_identity": "MISMATCH", "expected_graph": "MATCH",
         "expected_parameters": "MISMATCH",
         "expected_concentration": "localised",
         "note": "a targeted edit to one tensor after training; graph unchanged"},
        reference,
    )


# ----------------------------------------------------------------------
# Backdoor scenarios
# ----------------------------------------------------------------------


def backdoor(
    lab_dir: Path,
    reference: ReferenceBundle,
    *,
    seed: int = 201,
    trigger: dict[str, Any] | None = None,
    target_class: int = 2,
    poison_rate: float = 0.10,
    # Longer than the clean scenarios on purpose: a backdoor that costs clean
    # accuracy is a bad backdoor, and a bad backdoor is trivially detectable by
    # behaviour alone. Training to convergence gives an attack that preserves
    # clean accuracy, which is the case the detectors actually have to handle.
    epochs: int = 40,
    label: str = "badnets",
) -> ModelScenario:
    """A model trained on poisoned data: BadNets, or Blended at low opacity.

    The attack is installed by **data poisoning and training**, not by editing
    weights afterwards. That matters: a backdoor learned during training is
    distributed through the network the way a real one is, so the detectors face
    the problem they claim to address rather than an easier proxy for it.
    """
    trigger = trigger or {"position": "bottom_right", "size_fraction": 0.20,
                          "pattern": "white"}
    name = f"backdoor_{label}"
    out_dir = _prepare(lab_dir, name)

    corpus = generate_corpus(
        seed=lab_seed(seed, "backdoor_corpus"), per_class=reference.per_class
    )
    poisoned, attack_truth = poison_corpus(
        corpus, seed=lab_seed(seed, "backdoor_poison"), trigger=trigger,
        target_class=target_class, poison_rate=poison_rate,
    )
    model, spec = train_model(
        poisoned, seed=lab_seed(seed, "backdoor_train"), epochs=epochs
    )
    effectiveness = measure_backdoor(
        model, corpus, trigger=trigger, target_class=target_class
    )
    _export_pair(model, out_dir)

    in_declared_family = float(trigger.get("opacity", 1.0)) >= 1.0
    return _finish(
        out_dir, name, ["model_backdoor"], seed,
        {"trigger": {k: (repr(v) if isinstance(v, float) else v) for k, v in trigger.items()},
         "target_class": target_class, "poison_rate": repr(poison_rate),
         "epochs": epochs},
        {
            "training_spec": spec,
            "attack": attack_truth,
            "effectiveness": effectiveness,
            "trigger_in_declared_probe_family": in_declared_family,
            "note": (
                "the trigger is a full-opacity patch inside the declared probe "
                "family, so the gradient-free probe is expected to find it"
                if in_declared_family else
                "the trigger is a low-opacity blend, deliberately OUTSIDE the "
                "declared patch probe family. The gradient-free probe is expected "
                "to MISS it. This scenario exists to measure that miss rather than "
                "to be detected."
            ),
        },
        reference,
    )


# ----------------------------------------------------------------------
# The matrix
# ----------------------------------------------------------------------

#: The scenario matrix.  Backdoor variants sweep trigger size, position,
#: pattern, target class, poison rate and opacity, because a detector measured
#: against one operating point has been measured at one operating point.
SCENARIO_MATRIX: tuple[tuple[str, Callable[..., ModelScenario], dict[str, Any]], ...] = (
    ("clean_retrain_0", clean_retrain, {"variant": 0, "seed": 101}),
    ("clean_retrain_1", clean_retrain, {"variant": 1, "seed": 102}),
    ("clean_retrain_2", clean_retrain, {"variant": 2, "seed": 103}),
    ("clean_unusual_init", clean_unusual_init, {}),
    ("clean_finetuned", clean_finetuned, {}),
    ("reserialised", reserialised, {}),
    ("substitution_architecture", substitution_different_architecture, {}),
    ("parameter_tamper_small", parameter_tamper,
     {"variant": "small", "magnitude": 0.25, "fraction": 0.01, "seed": 151}),
    ("parameter_tamper_large", parameter_tamper,
     {"variant": "large", "magnitude": 1.5, "fraction": 0.10, "seed": 152}),
    # Patch backdoors, inside the declared probe family.
    ("backdoor_badnets", backdoor,
     {"label": "badnets", "seed": 201,
      "trigger": {"position": "bottom_right", "size_fraction": 0.20, "pattern": "white"},
      "target_class": 2, "poison_rate": 0.10}),
    ("backdoor_small_patch", backdoor,
     {"label": "small_patch", "seed": 202,
      "trigger": {"position": "top_left", "size_fraction": 0.12, "pattern": "checker"},
      "target_class": 4, "poison_rate": 0.10}),
    ("backdoor_low_rate", backdoor,
     {"label": "low_rate", "seed": 203,
      "trigger": {"position": "top_right", "size_fraction": 0.16, "pattern": "magenta"},
      "target_class": 1, "poison_rate": 0.03}),
    ("backdoor_high_rate", backdoor,
     {"label": "high_rate", "seed": 204,
      "trigger": {"position": "centre", "size_fraction": 0.16, "pattern": "checker"},
      "target_class": 5, "poison_rate": 0.25}),
    # Outside the declared probe family: expected to be missed by the probe.
    ("backdoor_blended", backdoor,
     {"label": "blended", "seed": 205,
      "trigger": {"position": "bottom_right", "size_fraction": 0.60,
                  "pattern": "checker", "opacity": 0.12},
      "target_class": 3, "poison_rate": 0.15}),
    ("backdoor_blended_faint", backdoor,
     {"label": "blended_faint", "seed": 206,
      "trigger": {"position": "centre", "size_fraction": 0.80,
                  "pattern": "magenta", "opacity": 0.08},
      "target_class": 0, "poison_rate": 0.20}),
)

SCENARIOS: dict[str, Callable[..., ModelScenario]] = {
    name: builder for name, builder, _ in SCENARIO_MATRIX
}


def build_lab(
    lab_dir: Path,
    *,
    seed: int = 20260917,
    per_class: int = 60,
    epochs: int = 30,
    scenarios: Sequence[str] | None = None,
) -> tuple[ReferenceBundle, list[ModelScenario]]:
    """Build the reference model and the requested scenarios."""
    lab_dir = Path(lab_dir)
    lab_dir.mkdir(parents=True, exist_ok=True)
    reference = build_reference(lab_dir, seed=seed, per_class=per_class, epochs=epochs)

    wanted = set(scenarios) if scenarios else None
    built: list[ModelScenario] = []
    for name, builder, kwargs in SCENARIO_MATRIX:
        if wanted is not None and name not in wanted:
            continue
        built.append(builder(lab_dir, reference, **kwargs))
    return reference, built
