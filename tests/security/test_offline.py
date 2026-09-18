"""The offline guarantee.

The whole project rests on one operational claim: **nothing reaches the network
at run time**. This file is what makes that claim testable rather than a
statement of intent, and it checks it two independent ways, because either one
alone is defeatable.

1. **Dynamically** — ``socket.socket`` is replaced with something that raises,
   and a full dataset scan and a full model assessment are run through it. Any
   component that tried to open a connection fails loudly.
2. **Statically** — the shipped source is inspected for network imports and for
   the specific framework calls that download weights behind an innocuous API
   (``torch.hub``, ``torchvision.models(weights=...)``, ``from_pretrained``).
   The dynamic test cannot catch a path that simply was not exercised; this one
   can.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import cvtrust

SOURCE_ROOT = Path(cvtrust.__file__).parent

#: Modules that can reach a network.  ``socket`` itself is permitted nowhere in
#: the package; the test below asserts that too.
NETWORK_MODULES = frozenset({
    "urllib", "urllib.request", "urllib3", "requests", "httpx", "aiohttp",
    "http", "http.client", "ftplib", "telnetlib", "smtplib", "socket",
    "socketserver", "xmlrpc", "boto3", "google.cloud",
})

#: Framework calls whose whole purpose is to fetch a remote artifact.
FORBIDDEN_CALLS = ("torch.hub", "load_state_dict_from_url", "from_pretrained",
                   "hf_hub_download", "snapshot_download", "urlretrieve")


def _python_sources() -> list[Path]:
    return sorted(SOURCE_ROOT.rglob("*.py"))


# ---------------------------------------------------------------------------
# 1. Dynamic: run the real pipelines with the network amputated
# ---------------------------------------------------------------------------


class _NoNetwork(Exception):
    pass


@pytest.fixture
def no_network(monkeypatch):
    """Make any attempt to open a socket raise."""

    def _forbidden(*args, **kwargs):
        raise _NoNetwork(
            "a component attempted to open a network socket; cvtrust must be "
            "able to run in an air-gapped deployment"
        )

    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", _forbidden)
    return _forbidden


@pytest.mark.slow
def test_a_dataset_scan_completes_with_no_network(no_network, clean_root, config):
    from cvtrust.pipeline import analyse

    report, _, _ = analyse(clean_root, config)
    assert report.report_id


@pytest.mark.slow
def test_a_model_assessment_completes_with_no_network(
    no_network, model_lab, reference_onnx
):
    from cvtrust.core.config import Config
    from cvtrust.model_pipeline import assess_model

    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].onnx_path,
        Config(), reference_path=reference_onnx,
    )
    assert report.report_id
    assert report.findings


@pytest.mark.slow
def test_the_torchscript_pathway_completes_with_no_network(
    no_network, model_lab, reference_torchscript
):
    """Covers the gradient path, which loads and differentiates a model."""
    from cvtrust.core.config import Config
    from cvtrust.model_pipeline import assess_model

    report, _, _ = assess_model(
        model_lab["scenarios"]["backdoor_badnets"].torchscript_path,
        Config(), reference_path=reference_torchscript,
    )
    assert report.report_id


@pytest.mark.slow
def test_building_the_model_lab_needs_no_network(no_network, tmp_path):
    """Training the lab's models must not reach for a pretrained checkpoint."""
    from cvtrust.attack_lab.model_synth import generate_corpus, train_model

    corpus = generate_corpus(seed=1, per_class=4)
    model, spec = train_model(corpus, seed=1, epochs=1)
    assert spec["parameter_count"] > 0


# ---------------------------------------------------------------------------
# 2. Static: the source cannot even express a download
# ---------------------------------------------------------------------------


def test_no_cvtrust_module_imports_a_network_library():
    offenders: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in NETWORK_MODULES:
                        offenders.append(f"{path.name}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in NETWORK_MODULES:
                    offenders.append(f"{path.name}:{node.lineno} from {node.module}")
    assert not offenders, "network imports in shipped source: " + "; ".join(offenders)


def test_no_cvtrust_module_calls_a_weight_downloading_api():
    offenders: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN_CALLS:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert not offenders, "weight-download calls in shipped source: " + "; ".join(offenders)


def test_torchvision_models_are_never_constructed_with_remote_weights():
    """``weights=None`` is the only permitted form; anything else downloads."""
    offenders: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        if "torchvision.models" not in text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "weights=" in line and "weights=None" not in line:
                offenders.append(f"{path.name}:{line_number}")
    assert not offenders, "remote weights requested: " + "; ".join(offenders)


def test_no_url_literals_in_shipped_source():
    """A URL in an assurance tool is a download waiting to happen."""
    offenders: list[str] = []
    for path in _python_sources():
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith(("*", '"""', "'''")):
                continue
            if "http://" in line or "https://" in line:
                offenders.append(f"{path.name}:{line_number}")
    assert not offenders, "URL literals in shipped source: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# 3. Absent artifacts are NOT_ASSESSED, never auto-fetched
# ---------------------------------------------------------------------------


def test_an_absent_benchmark_is_not_assessed_rather_than_downloaded():
    from cvtrust.core.errors import DetectorUnavailable
    from cvtrust.models.benchmark import UNAVAILABLE_REASON, load_benchmark

    with pytest.raises(DetectorUnavailable) as excinfo:
        load_benchmark(None)
    assert UNAVAILABLE_REASON in str(excinfo.value)
    assert "never downloaded" in str(excinfo.value)


def test_a_missing_benchmark_directory_is_not_assessed(tmp_path):
    from cvtrust.core.errors import DetectorUnavailable
    from cvtrust.models.benchmark import load_benchmark

    with pytest.raises(DetectorUnavailable, match="required local artifact unavailable"):
        load_benchmark(tmp_path / "does-not-exist")


def test_benchmark_status_reports_unavailability_without_raising():
    from cvtrust.models.benchmark import benchmark_status

    status = benchmark_status(None)
    assert status["available"] is False
    assert status["coverage"] == "NOT_ASSESSED"
    assert status["downloads_attempted"] is False


def test_a_vendored_benchmark_is_ingested_locally(tmp_path, reference_onnx):
    """The supported path: artifacts placed on disk out of band."""
    import json
    import shutil

    from cvtrust.models.benchmark import load_benchmark

    root = tmp_path / "trojai"
    (root / "models" / "id-00000001").mkdir(parents=True)
    shutil.copy2(reference_onnx, root / "models" / "id-00000001" / "model.onnx")
    (root / "index.json").write_text(
        json.dumps({
            "benchmark": "trojai",
            "round": "test",
            "models": [{
                "id": "id-00000001",
                "path": "models/id-00000001/model.onnx",
                "ground_truth": {"poisoned": False},
            }],
        }),
        encoding="utf-8",
    )
    index = load_benchmark(root)
    assert index.benchmark == "trojai"
    assert len(index.models) == 1
    assert len(index.models[0].file_sha256) == 64


def test_the_optional_runtimes_degrade_rather_than_fail(monkeypatch):
    """A missing runtime must be an explained refusal, not a crash."""
    import builtins

    from cvtrust.core.errors import DetectorUnavailable

    real_import = builtins.__import__

    def _no_onnx(name, *args, **kwargs):
        if name in {"onnx", "onnxruntime"}:
            raise ImportError(f"no module named {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_onnx)
    from cvtrust.models.onnx_adapter import _require_onnx

    with pytest.raises(DetectorUnavailable) as excinfo:
        _require_onnx()
    message = str(excinfo.value)
    assert "not installed" in message
    assert "nothing is downloaded" in message.lower()


# ---------------------------------------------------------------------------
# 4. Module 3 — the whole cryptographic lifecycle, with the network amputated
#
# Signing systems are where network dependencies creep in: a key server, an OCSP
# responder, a remote timestamp authority, a CRL fetch. None of those exist
# here, and these tests are what keeps it that way — every stage of the key and
# provenance lifecycle runs with sockets replaced by something that raises.
# ---------------------------------------------------------------------------


def test_key_generation_works_offline(no_network, tmp_path):
    from cvtrust.provenance.keys import generate_keypair, load_private_key

    _, info = generate_keypair(
        private_path=tmp_path / "k.pem", passphrase="pw", label="offline"
    )
    assert info.key_id
    assert load_private_key(tmp_path / "k.pem", "pw")


def test_signing_and_verification_work_offline(no_network):
    from cvtrust.provenance.binding import (
        ModelBinding,
        bind_config,
        bind_input_bytes,
        bind_output,
    )
    from cvtrust.provenance.keys import generate_keypair
    from cvtrust.provenance.output import classification_output
    from cvtrust.provenance.record import create_provenance_record
    from cvtrust.provenance.signing import sign_record, verify_signature

    key, _ = generate_keypair()
    record = create_provenance_record(
        input_binding=bind_input_bytes(b"offline-image"),
        model_binding=ModelBinding(
            model_id="m", file_sha256="a" * 64, model_format="onnx"
        ),
        preprocessing=bind_config({"resize": [32, 32]}),
        inference=bind_config({"top_k": 1}),
        output=bind_output(classification_output({"defect": 0.9})),
        log_id="offline",
    )
    assert verify_signature(sign_record(record, key)).valid


def test_trust_and_revocation_need_no_revocation_service(no_network, tmp_path):
    """No CA, no OCSP, no CRL fetch. Trust is a local administrative record."""
    from cvtrust.provenance.keys import generate_keypair
    from cvtrust.provenance.trust import KeyStatus, TrustStore, revoke_key, trust_key

    _, info = generate_keypair()
    store = trust_key(
        TrustStore.empty(), public_key=info.public_key_hex, provenance="courier"
    )
    store.save(tmp_path / "trust.json")
    reloaded = TrustStore.load(tmp_path / "trust.json")
    assert reloaded.status_of(info.key_id) is KeyStatus.TRUSTED
    assert revoke_key(reloaded, info.key_id, reason="offline test").status_of(
        info.key_id
    ) is KeyStatus.REVOKED


@pytest.mark.slow
def test_a_full_log_verification_completes_with_no_network(no_network, tmp_path):
    from cvtrust.attack_lab.provenance_attacks import build_clean
    from cvtrust.core.config import Config
    from cvtrust.provenance.chain import build_anchor
    from cvtrust.provenance.replay import ReplayDatabase
    from cvtrust.provenance_pipeline import verify_log

    clean = build_clean(tmp_path / "lab", seed=7, record_count=6)
    report, _, database = verify_log(
        clean.log,
        Config(),
        trust_store=clean.trust_store,
        replay_database=ReplayDatabase.empty(),
        anchor=build_anchor(clean.log.entries),
    )
    assert report.report_id
    assert report.summary.overall == "PROVENANCE VERIFIED"
    assert database is not None and len(database) == 6


@pytest.mark.slow
def test_chain_and_replay_detection_work_offline(no_network, tmp_path):
    from cvtrust.attack_lab.provenance_attacks import build_clean
    from cvtrust.provenance.chain import verify_chain
    from cvtrust.provenance.replay import ReplayDatabase, ReplayVerdict

    clean = build_clean(tmp_path / "lab", seed=8, record_count=6)
    assert verify_chain(clean.log.entries).intact
    assert not verify_chain(list(reversed(clean.log.entries))).intact

    database = ReplayDatabase.empty().record(clean.log.entries[0])
    assert database.check(clean.log.entries[0]).verdict is ReplayVerdict.REPLAY_EXACT


@pytest.mark.slow
def test_the_provenance_lab_builds_and_evaluates_offline(no_network, tmp_path):
    from cvtrust.attack_lab.provenance_attacks import build_lab
    from cvtrust.attack_lab.provenance_evaluate import evaluate_lab
    from cvtrust.core.config import Config

    build_lab(tmp_path / "lab", seed=9, record_count=6)
    assert evaluate_lab(tmp_path / "lab", Config()).all_passed


def test_no_provenance_module_imports_a_certificate_or_key_fetching_api():
    """The specific APIs that would turn this into an online verifier."""
    forbidden = (
        "ocsp", "crl_distribution", "load_pem_x509_certificate", "x509.ocsp",
        "keyserver", "hkp://", "timestamp_authority", "rfc3161",
    )
    offenders: list[str] = []
    for path in _python_sources():
        if "provenance" not in str(path):
            continue
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert not offenders, (
        "online certificate/key/timestamp APIs in the provenance module: "
        + "; ".join(offenders)
    )


def test_the_only_cryptography_imported_is_the_vendored_library():
    """No invented primitives, and no second crypto stack to audit."""
    import ast

    allowed_roots = {"hashlib", "secrets", "cryptography"}
    seen: set[str] = set()
    for path in _python_sources():
        if "provenance" not in str(path):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in {"hashlib", "secrets", "cryptography", "nacl", "Crypto"}:
                        seen.add(root)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in {"hashlib", "secrets", "cryptography", "nacl", "Crypto"}:
                    seen.add(root)
    assert seen <= allowed_roots, f"unexpected crypto imports: {seen - allowed_roots}"
    assert "cryptography" in seen


def test_the_provenance_lab_key_derivation_is_confined_to_the_lab():
    """A key derived from a published seed must never reach the shipped path."""
    offenders: list[str] = []
    for path in _python_sources():
        text = path.read_text(encoding="utf-8")
        if "from_private_bytes" not in text:
            continue
        if path.name != "provenance_attacks.py":
            offenders.append(path.name)
    assert not offenders, (
        "seed-derived Ed25519 keys outside the attack lab: " + "; ".join(offenders)
    )
