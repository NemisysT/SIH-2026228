"""A small, reproducible CNN and its trainer — the substrate of the model lab.

Why train our own model at all
------------------------------
Every claim Module 2 makes about detecting a backdoor has to be measured against
a model that is *known* to be backdoored, and a model that is *known* to be
clean.  Downloading a pretrained network is forbidden by the air gap, and
"known clean" is not a property any downloaded artifact has.  Training a small
network from a seed is the only way to get ground truth that is actually true.

Constraints this design is under, all from §29 of the brief:

* **CPU only.**  No GPU is assumed; one is used if present but never required.
* **Seconds, not hours.**  A 32×32, six-class, ~90k-parameter CNN over a few
  hundred synthetic images trains in a couple of seconds on a laptop core, and
  the whole scenario matrix stays inside a test suite's patience.
* **No downloads.**  The training data is the Module 1 synthetic generator.

Reproducibility
---------------
Every source of randomness — weight initialisation, batch order, poison
selection — is derived from SHA-256 over ``(seed, scenario, index)``, never from
Python's salted ``hash()`` and never from global RNG.  Training the same
scenario twice produces byte-identical weights, which is what lets the model
lab's ground truth be checked by someone who does not trust our numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from ..core.errors import DetectorUnavailable
from ..core.canonical import MAX_SAFE_INT
from ..core.hashing import sha256_canonical
from ..core.logging import get_logger
from ..models.battery import apply_trigger

log = get_logger("attack_lab.model_synth")

MODEL_LAB_VERSION = "1.0"

#: Input geometry of the lab's models.  32×32 keeps training fast while leaving
#: a corner patch of 12–20% of the side (4–6 px) large enough to be learnable,
#: which is the regime BadNets operates in.
INPUT_SIZE = 32
INPUT_CHANNELS = 3


def _require_torch() -> Any:
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - exercised by the extras test
        raise DetectorUnavailable(
            "the model attack lab requires PyTorch to train its models; it is not "
            "installed in this offline environment. Install the 'torch' extra "
            "from a local wheel directory."
        ) from exc
    torch.set_num_threads(1)
    return torch


def lab_seed(seed: int, scenario: str, index: int = 0) -> int:
    """A stable seed for one lab artifact, inside the canonical-safe integer range.

    SHA-256 over the inputs, never ``hash()``: Python salts string hashes per
    interpreter process, so seeding from one would make the lab differ between
    runs on the same machine and silently invalidate every measurement built on
    it.  Module 1 shipped that bug once; this is the rule that came out of it.

    The result is reduced modulo :data:`~cvtrust.core.canonical.MAX_SAFE_INT`
    because a derived seed is routinely fed back into another
    ``sha256_canonical`` call, and the canonical encoder rejects integers
    outside the IEEE-754 exact range (ADR-004).  53 bits is far more entropy
    than a seed needs, and staying inside the digest surface's own contract is
    worth more than the eleven bits.
    """
    digest = sha256_canonical({"seed": seed, "scenario": scenario, "index": index})
    return int(digest[:16], 16) % MAX_SAFE_INT


def build_cnn(torch: Any, *, seed: int, n_classes: int, width: int = 16) -> Any:
    """A small convolutional classifier with deterministic initialisation.

    Plain ``Conv → BN → ReLU → MaxPool`` blocks: a conventional architecture
    whose parameter tensors group naturally into operator-type peer groups, so
    the peer-outlier analysis in :mod:`cvtrust.models.params` has something
    meaningful to compare against.  ``width`` exists so the substitution
    scenario can produce a genuinely different architecture.
    """
    generator = torch.Generator().manual_seed(int(seed) % (2**31 - 1))

    model = torch.nn.Sequential(
        torch.nn.Conv2d(INPUT_CHANNELS, width, 3, padding=1),
        torch.nn.BatchNorm2d(width),
        torch.nn.ReLU(),
        torch.nn.MaxPool2d(2),                       # 16x16
        torch.nn.Conv2d(width, width * 2, 3, padding=1),
        torch.nn.BatchNorm2d(width * 2),
        torch.nn.ReLU(),
        torch.nn.MaxPool2d(2),                       # 8x8
        torch.nn.Conv2d(width * 2, width * 4, 3, padding=1),
        torch.nn.BatchNorm2d(width * 4),
        torch.nn.ReLU(),
        torch.nn.AdaptiveAvgPool2d(1),
        torch.nn.Flatten(),
        torch.nn.Linear(width * 4, n_classes),
    )
    with torch.no_grad():
        for module in model.modules():
            if isinstance(module, (torch.nn.Conv2d, torch.nn.Linear)):
                # Kaiming-uniform fan-in, seeded explicitly rather than relying
                # on torch's global RNG, which another component could perturb.
                fan_in = int(np.prod(module.weight.shape[1:]))
                bound = float(np.sqrt(6.0 / max(1, fan_in)))
                module.weight.copy_(
                    torch.empty_like(module.weight).uniform_(-bound, bound, generator=generator)
                )
                if module.bias is not None:
                    module.bias.zero_()
    return model


@dataclass
class TrainingCorpus:
    """Images and labels for the lab, as CHW float arrays in [0, 1]."""

    images: np.ndarray            # (N, C, H, W) float32
    labels: np.ndarray            # (N,) int64
    classes: tuple[str, ...]
    spec: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return int(self.images.shape[0])


def generate_corpus(
    *,
    seed: int,
    per_class: int = 60,
    classes: Sequence[str] | None = None,
    contributor_index: int = 0,
    size: int = INPUT_SIZE,
) -> TrainingCorpus:
    """Render a training corpus with the Module 1 synthetic generator.

    Reusing the Module 1 generator is deliberate: the dataset-side and
    model-side labs then share one data-generating process, so a poisoned
    dataset and the model trained on it are describable in the same terms.
    """
    from PIL import Image

    from .synth import CLASSES, DEFAULT_CONTRIBUTORS, render_sample

    classes = tuple(classes) if classes else CLASSES
    contributor = DEFAULT_CONTRIBUTORS[contributor_index % len(DEFAULT_CONTRIBUTORS)]

    images: list[np.ndarray] = []
    labels: list[int] = []
    for class_index, label in enumerate(classes):
        for n in range(per_class):
            digest = sha256_canonical(
                {"seed": seed, "stream": "corpus", "label": label, "index": n}
            )
            rng = np.random.default_rng(int(digest[:16], 16))
            image, _ = render_sample(label, contributor, rng)
            resized = image.convert("RGB").resize((size, size), Image.Resampling.BILINEAR)
            array = np.asarray(resized, dtype=np.float32).transpose(2, 0, 1) / 255.0
            images.append(np.ascontiguousarray(array))
            labels.append(class_index)

    return TrainingCorpus(
        images=np.stack(images).astype(np.float32),
        labels=np.asarray(labels, dtype=np.int64),
        classes=classes,
        spec={
            "generator": "cvtrust.attack_lab.synth",
            "seed": seed,
            "per_class": per_class,
            "size": size,
            "contributor": contributor.name,
        },
    )


def poison_corpus(
    corpus: TrainingCorpus,
    *,
    seed: int,
    trigger: dict[str, Any],
    target_class: int,
    poison_rate: float,
) -> tuple[TrainingCorpus, dict[str, Any]]:
    """Install a data-poisoning backdoor: BadNets, or Blended at low opacity.

    ``trigger`` is a spec from the same patch family the battery uses, with an
    optional ``opacity``.  ``opacity < 1`` gives the Blended attack of Chen et
    al. (2017), whose whole point is that the trigger is *not* a visible patch —
    which is exactly why it belongs in this lab: our patch probe is expected to
    do **worse** on it, and a lab that only contains attacks our detector is
    good at measures nothing.

    The label of every poisoned sample is rewritten to ``target_class``, which is
    the dirty-label BadNets setting (Gu, Dolan-Gavitt & Garg, 2017).
    """
    digest = sha256_canonical({"seed": seed, "stream": "poison"})
    rng = np.random.default_rng(int(digest[:16], 16))
    n = len(corpus)
    n_poison = max(1, int(round(poison_rate * n)))
    # Poison only samples that are not already the target class: relabelling a
    # target-class sample teaches the model nothing about the trigger and would
    # inflate the effective poison rate in the ground truth.
    eligible = np.flatnonzero(corpus.labels != target_class)
    chosen = np.sort(rng.choice(eligible, size=min(n_poison, eligible.size), replace=False))

    images = corpus.images.copy()
    labels = corpus.labels.copy()
    for index in chosen.tolist():
        images[index] = apply_trigger(images[index], trigger)
        labels[index] = target_class

    ground_truth = {
        "attack": "badnets" if float(trigger.get("opacity", 1.0)) >= 1.0 else "blended",
        "origin": (
            "Gu, Dolan-Gavitt & Garg 2017 (BadNets)"
            if float(trigger.get("opacity", 1.0)) >= 1.0
            else "Chen et al. 2017 (Blended)"
        ),
        "trigger": {k: (repr(v) if isinstance(v, float) else v) for k, v in trigger.items()},
        "target_class": int(target_class),
        "target_class_name": corpus.classes[target_class],
        "poison_rate_requested": repr(float(poison_rate)),
        "poison_rate_actual": repr(float(len(chosen) / n)),
        "poisoned_count": int(len(chosen)),
        "corpus_size": n,
        "label_policy": "dirty-label: every poisoned sample is relabelled to the target",
    }
    return (
        TrainingCorpus(images=images, labels=labels, classes=corpus.classes,
                       spec={**corpus.spec, "poisoned": True}),
        ground_truth,
    )


def train_model(
    corpus: TrainingCorpus,
    *,
    seed: int,
    epochs: int = 12,
    batch_size: int = 32,
    learning_rate: float = 0.01,
    width: int = 16,
    init_scale: float = 1.0,
    initial_model: Any = None,
) -> tuple[Any, dict[str, Any]]:
    """Train the CNN.  Deterministic for a fixed ``(corpus, seed, budget)``.

    ``init_scale`` scales the initial weights, used by the "clean model with
    naturally unusual weights" scenario: a clean model whose statistics are odd
    for benign reasons is precisely the false positive the parameter analysis
    must not produce.

    ``initial_model`` lets the fine-tune scenario continue from an existing
    model rather than starting fresh, which is the realistic shape of a
    legitimate weight change.
    """
    torch = _require_torch()
    n_classes = len(corpus.classes)
    model = initial_model if initial_model is not None else build_cnn(
        torch, seed=seed, n_classes=n_classes, width=width
    )
    if init_scale != 1.0:
        with torch.no_grad():
            for module in model.modules():
                if isinstance(module, (torch.nn.Conv2d, torch.nn.Linear)):
                    module.weight.mul_(init_scale)

    images = torch.from_numpy(np.ascontiguousarray(corpus.images, dtype=np.float32))
    labels = torch.from_numpy(np.ascontiguousarray(corpus.labels, dtype=np.int64))
    optimiser = torch.optim.SGD(model.parameters(), lr=learning_rate, momentum=0.9)
    loss_fn = torch.nn.CrossEntropyLoss()

    # Batch order from a seeded numpy generator rather than a torch DataLoader:
    # one fewer source of cross-version shuffling behaviour to depend on.
    order_rng = np.random.default_rng(lab_seed(seed, "batch_order"))
    n = len(corpus)

    model.train()
    was_grad_enabled = torch.is_grad_enabled()
    torch.set_grad_enabled(True)
    history: list[dict[str, float]] = []
    try:
        for epoch in range(epochs):
            permutation = order_rng.permutation(n)
            epoch_loss, correct = 0.0, 0
            for start in range(0, n, batch_size):
                index = torch.from_numpy(
                    np.ascontiguousarray(permutation[start:start + batch_size])
                )
                batch_x, batch_y = images[index], labels[index]
                logits = model(batch_x)
                loss = loss_fn(logits, batch_y)
                optimiser.zero_grad()
                loss.backward()
                optimiser.step()
                epoch_loss += float(loss.detach()) * batch_x.shape[0]
                correct += int((torch.argmax(logits, dim=1) == batch_y).sum())
            history.append({
                "epoch": epoch,
                "loss": round(epoch_loss / n, 6),
                "accuracy": round(correct / n, 6),
            })
    finally:
        torch.set_grad_enabled(was_grad_enabled)

    model.eval()
    with torch.no_grad():
        predictions = torch.argmax(model(images), dim=1)
        accuracy = float((predictions == labels).float().mean())

    spec = {
        "model_lab_version": MODEL_LAB_VERSION,
        "architecture": "cvtrust_small_cnn",
        "width": width,
        "n_classes": n_classes,
        "classes": list(corpus.classes),
        "input_shape": [INPUT_CHANNELS, INPUT_SIZE, INPUT_SIZE],
        "seed": seed,
        "epochs": epochs,
        "batch_size": batch_size,
        "learning_rate": repr(learning_rate),
        "init_scale": repr(init_scale),
        "final_train_accuracy": repr(round(accuracy, 6)),
        "history": history[-3:],
        "parameter_count": int(sum(p.numel() for p in model.parameters())),
        "device": "cpu",
    }
    log.info(
        "trained %s: %d params, train accuracy %.3f",
        spec["architecture"], spec["parameter_count"], accuracy,
    )
    return model, spec


def measure_backdoor(
    model: Any,
    corpus: TrainingCorpus,
    *,
    trigger: dict[str, Any],
    target_class: int,
) -> dict[str, Any]:
    """Ground-truth effectiveness of an installed backdoor.

    Written to ``ground_truth.json`` **outside** the directory a detector reads,
    exactly as Module 1 does.  This is the answer key, and a detector that could
    see it would be measuring nothing.
    """
    torch = _require_torch()
    model.eval()
    non_target = np.flatnonzero(corpus.labels != target_class)
    clean_x = torch.from_numpy(np.ascontiguousarray(corpus.images, dtype=np.float32))
    triggered = np.stack(
        [apply_trigger(corpus.images[i], trigger) for i in non_target.tolist()]
    )
    triggered_x = torch.from_numpy(np.ascontiguousarray(triggered, dtype=np.float32))
    with torch.no_grad():
        clean_pred = torch.argmax(model(clean_x), dim=1).numpy()
        triggered_pred = torch.argmax(model(triggered_x), dim=1).numpy()
    return {
        "clean_accuracy": repr(round(float(np.mean(clean_pred == corpus.labels)), 6)),
        "attack_success_rate": repr(
            round(float(np.mean(triggered_pred == target_class)), 6)
        ),
        "n_triggered_evaluated": int(non_target.size),
        "definition": "attack success rate is the fraction of non-target-class "
                      "samples classified as the target once the trigger is applied",
    }


def export_onnx(model: Any, path: Path, *, metadata: dict[str, Any] | None = None) -> Path:
    """Export to ONNX with a fixed batch axis and recorded metadata.

    A **fixed** batch dimension is used deliberately.  A dynamic axis would let
    a runtime choose a different reduction strategy per batch size, and the
    behavioural fingerprint would then depend on how the battery happened to be
    chunked.
    """
    torch = _require_torch()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    model.eval()
    dummy = torch.zeros(1, INPUT_CHANNELS, INPUT_SIZE, INPUT_SIZE, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        str(path),
        input_names=["input"],
        output_names=["logits"],
        dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )
    if metadata:
        import onnx

        proto = onnx.load(str(path))
        for key, value in sorted(metadata.items()):
            entry = proto.metadata_props.add()
            entry.key = str(key)
            entry.value = str(value)
        onnx.save(proto, str(path))
    return path


def save_torch(model: Any, path: Path) -> Path:
    """Save as TorchScript.

    TorchScript rather than a module pickle, on purpose: ``torch.jit.save``
    produces an artifact that loads without unpickling arbitrary Python globals,
    which is the format this project tells suppliers to use.  The lab should
    ship the artifact it recommends.
    """
    torch = _require_torch()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    model.eval()
    scripted = torch.jit.script(model)
    torch.jit.save(scripted, str(path))
    return path
