"""Shared fixtures.

The synthetic corpus is generated once per session and reused: generation is
deterministic, so sharing it costs nothing in isolation and saves the whole
suite from re-rendering several hundred images per test module.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from cvtrust.attack_lab.synth import generate_clean_dataset
from cvtrust.core.config import Config

logging.getLogger("cvtrust").setLevel(logging.ERROR)

#: Small enough for a fast suite, large enough that class-support minimums,
#: kNN neighbourhoods and the OOD covariance estimate are all satisfied.
PER_CLASS = 8
SEED = 20260917


@pytest.fixture(scope="session")
def clean_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("clean")
    generate_clean_dataset(
        out, seed=SEED, per_class_per_contributor=PER_CLASS, export_coco=True, export_yolo=True
    )
    return out


@pytest.fixture(scope="session")
def clean_root(clean_dir: Path) -> Path:
    return clean_dir / "dataset"


@pytest.fixture
def config() -> Config:
    return Config()


# ---------------------------------------------------------------------------
# Module 2 fixtures
#
# The model lab is expensive relative to the rest of the suite (it trains
# several small CNNs), so it is built once per session at a deliberately small
# size.  Training is deterministic, so sharing it across tests costs nothing in
# isolation.
# ---------------------------------------------------------------------------

#: Smaller than the shipped default: enough for the detectors to have something
#: to measure, small enough that the whole suite stays quick.
LAB_PER_CLASS = 30
LAB_EPOCHS = 20

#: Scenarios the test suite needs.  The full matrix is exercised by
#: `cvtrust lab model-evaluate`; the suite uses a representative subset that
#: covers every detector pathway and both false-positive cases.
TEST_SCENARIOS = (
    "clean_retrain_0",
    "clean_unusual_init",
    "reserialised",
    "substitution_architecture",
    "parameter_tamper_large",
    "backdoor_badnets",
)


def _require_model_runtime() -> None:
    """Skip a test when neither model runtime is installed.

    Module 2's runtimes are optional extras, exactly like Module 1's CNN
    backend.  A suite that failed without them would make an optional
    dependency mandatory by the back door.
    """
    from cvtrust.models import REGISTERED_ADAPTERS

    if not REGISTERED_ADAPTERS:
        pytest.skip(
            "no model runtime installed (onnx / torch extras); Module 2 model "
            "tests require at least one"
        )


@pytest.fixture(scope="session")
def model_lab(tmp_path_factory: pytest.TempPathFactory):
    """The shared model attack lab: reference model plus a scenario subset."""
    pytest.importorskip("torch", reason="the model lab trains its models with PyTorch")
    from cvtrust.attack_lab.model_attacks import build_lab

    out = tmp_path_factory.mktemp("model_lab")
    reference, scenarios = build_lab(
        out, per_class=LAB_PER_CLASS, epochs=LAB_EPOCHS,
        scenarios=list(TEST_SCENARIOS),
    )
    return {
        "root": out,
        "reference": reference,
        "scenarios": {s.name: s for s in scenarios},
    }


@pytest.fixture(scope="session")
def reference_onnx(model_lab):
    return model_lab["reference"].onnx_path


@pytest.fixture(scope="session")
def reference_torchscript(model_lab):
    return model_lab["reference"].torchscript_path


@pytest.fixture
def model_battery():
    """A small battery, built once per test that asks for one."""
    from cvtrust.models.battery import build_battery

    return build_battery(seed=SEED, input_shape=(3, 32, 32), clean_per_class=3,
                         borderline_pairs=3, ood_count=4, trigger_bases=3)


@pytest.fixture(autouse=True)
def _collect_model_runtimes():
    """Collect model runtime objects promptly rather than at interpreter exit.

    ONNX Runtime ``InferenceSession`` objects hold thread pools, and both ONNX
    Runtime and PyTorch install process-wide teardown handlers. Letting dozens
    of sessions accumulate across a test module and then destruct during CPython
    finalisation lets those handlers race: on macOS the process intermittently
    aborts with ``recursive_mutex lock failed`` and exit code 134 *after* every
    test has already passed.

    Collecting after each test keeps the live-session count near one, which both
    lowers peak memory and removes the pile-up that makes the race likely. See
    ``docs/testing.md`` for the residual caveat — this reduces the window, it
    does not fix a race inside third-party C++ destructors.
    """
    yield

    import gc

    gc.collect()


_EXIT_STATUS: dict[str, int] = {}


def pytest_sessionfinish(session, exitstatus):
    """Record pytest's own exit status for the hook below."""
    _EXIT_STATUS["status"] = int(exitstatus)


def pytest_unconfigure(config):
    """Exit with pytest's status before native runtimes finalise.

    ONNX Runtime and PyTorch both install process-wide teardown handlers that
    take their own locks. On macOS those handlers intermittently race during
    CPython finalisation and abort the process with ``recursive_mutex lock
    failed`` — **after** every test has passed and after pytest has printed its
    summary. Measured before this fix: exit code 134 on a fully green run,
    roughly one run in six, which a CI system reads as a failure.

    It is a race inside third-party C++ destructors and cannot be fixed from
    Python. Reducing session pressure (``_collect_model_runtimes`` and
    ``ModelHandle.release_caches``) narrows the window; this closes it, by
    skipping an interpreter finalisation whose only remaining work is destroying
    those runtimes.

    ``pytest_unconfigure`` rather than ``pytest_sessionfinish`` on purpose: the
    terminal reporter writes its summary line from ``sessionfinish``, and
    exiting there would swallow the one line a reviewer actually reads.

    Deliberately narrow: it runs only when a model runtime was actually
    imported, so a Module-1-only environment finalises normally and any teardown
    error there still surfaces. The status is pytest's own, so a real failure is
    still reported as one.
    """
    import os
    import sys

    status = _EXIT_STATUS.get("status")
    if status is None:
        return
    if not ({"onnxruntime", "torch"} & set(sys.modules)):
        return

    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(status)


# ---------------------------------------------------------------------------
# Module 3 fixtures
#
# The provenance lab is cheap relative to the other two — it signs a few dozen
# records and touches no model runtime — so it is built once per session purely
# to avoid repeating the work, not because it is slow.
# ---------------------------------------------------------------------------

#: Records in the lab's clean baseline. Six is the smallest size at which every
#: structural scenario is expressible: a genesis, an interior edit with a
#: successor, a deletion with records either side, and a head.
PROVENANCE_RECORDS = 6


@pytest.fixture(scope="session")
def provenance_lab(tmp_path_factory: pytest.TempPathFactory):
    """The built provenance attack lab: clean baseline plus every scenario."""
    from cvtrust.attack_lab.provenance_attacks import build_lab

    out = tmp_path_factory.mktemp("provenance_lab")
    clean, scenarios = build_lab(out, seed=SEED, record_count=PROVENANCE_RECORDS)
    return {
        "root": out,
        "clean": clean,
        "scenarios": {s.name: s for s in scenarios},
    }


@pytest.fixture
def signing_key():
    """An in-memory Ed25519 keypair. Never written to disk."""
    from cvtrust.provenance.keys import generate_keypair

    return generate_keypair(label="test-signer")


@pytest.fixture
def trust_store_with(signing_key):
    """A trust store trusting the ``signing_key`` fixture."""
    from cvtrust.provenance.trust import TrustStore, trust_key

    _, info = signing_key
    return trust_key(
        TrustStore.empty(),
        public_key=info.public_key_hex,
        label="test-signer",
        provenance="constructed in-process by the test fixture",
    )


@pytest.fixture
def make_record():
    """Factory for a minimal, valid provenance record.

    Keyword arguments override any part of it, so a test that cares about one
    field does not have to restate the other nine.
    """
    from cvtrust.provenance.binding import (
        ModelBinding,
        bind_config,
        bind_input_bytes,
        bind_output,
    )
    from cvtrust.provenance.output import classification_output
    from cvtrust.provenance.record import create_provenance_record

    def _make(
        *,
        payload: bytes = b"test-image-bytes",
        scores: dict[str, float] | None = None,
        preprocessing: dict | None = None,
        inference: dict | None = None,
        log_id: str = "test-log",
        sequence_number: int = 0,
        previous_record_digest: str | None = None,
        **kwargs,
    ):
        return create_provenance_record(
            input_binding=bind_input_bytes(payload, locator="test.png"),
            model_binding=ModelBinding(
                model_id="M-test", file_sha256="a" * 64, graph_digest="b" * 64,
                parameter_digest="c" * 64, parameter_count=100,
                model_format="onnx", declared_name="detector_v3",
            ),
            preprocessing=bind_config(preprocessing or {"resize": [32, 32]}),
            inference=bind_config(inference or {"threshold": 0.5}),
            output=bind_output(
                classification_output(scores or {"defect": 0.9, "clean": 0.1})
            ),
            log_id=log_id,
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
            **kwargs,
        )

    return _make


@pytest.fixture
def signed_log(signing_key, make_record):
    """A four-entry signed, chained log."""
    from cvtrust.provenance.log import ProvenanceLog

    key, _ = signing_key
    provenance_log = ProvenanceLog.new("test-log")
    for index in range(4):
        provenance_log.append_signed(
            lambda sequence_number, previous_record_digest, index=index: make_record(
                payload=f"image-{index}".encode(),
                sequence_number=sequence_number,
                previous_record_digest=previous_record_digest,
            ),
            key,
        )
    return provenance_log
