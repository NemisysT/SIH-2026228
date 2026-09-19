"""Reproducible provenance-attack scenarios.

Same contract as the Module 1 and Module 2 labs, and it is the contract that
makes the measurements worth anything:

    <scenario>/
      log.jsonl           <- the only thing the verifier ever reads
      trust_store.json    <- and this
      anchor.json         <- and this, when the scenario supplies one
      artifacts/          <- input and model artifacts, when the scenario
                             mutates them
      ground_truth.json   <- what was actually done, OUTSIDE the verified set
      attack_config.json  <- seed and parameters, sufficient to regenerate

Ground truth lives outside the artifacts under verification, so the verifier
cannot read the answer key.  Each scenario is a pure function of
``(seed, parameters)``, so a reviewer who does not believe the results can
regenerate them byte for byte.

Unlike Modules 1 and 2, every expected outcome here is **exact**.  There is no
precision or recall to measure: a signature verifies or it does not, a digest
matches or it does not.  So the evaluation harness asserts set equality between
the failure codes a scenario is expected to produce and the ones it does — a
detector that produces an *extra* failure fails the evaluation just as surely as
one that misses a failure.  That is a much stricter test than an ROC curve, and
it is available precisely because this module is deterministic.

Determinism and the two test-only constructions
-----------------------------------------------
Records carry a nonce and a timestamp, both of which are non-deterministic in
production and both of which must be fixed for a lab to be reproducible.  So the
lab supplies them explicitly from a seeded stream, and it derives its signing
keys from a seeded value rather than generating them.

**Neither construction is ever used outside this file.**  A signing key derived
from a published seed is a key everyone has; ``docs/cryptographic-model.md`` §5
says so, the function that does it is named to make that obvious, and the
production path (:func:`cvtrust.provenance.keys.generate_keypair`,
:func:`cvtrust.provenance.record.new_nonce`) draws from the OS CSPRNG.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.canonical import canonical_json
from ..core.errors import ProvenanceError
from ..core.logging import get_logger
from ..provenance.binding import (
    ExecutionMetadata,
    ModelBinding,
    bind_config,
    bind_input,
    bind_output,
)
from ..provenance.chain import LogAnchor, build_anchor
from ..provenance.keys import export_public_key
from ..provenance.log import ProvenanceLog
from ..provenance.output import classification_output, detection_output
from ..provenance.record import SignedRecord, create_provenance_record
from ..provenance.signing import sign_record
from ..provenance.trust import KeyPurpose, TrustStore, revoke_key, trust_key
from ..provenance.verify import FailureCode

log = get_logger("attack_lab.provenance_attacks")

PROVENANCE_LAB_VERSION = "1.0"

#: Default lab seed, shared with the Module 1 and Module 2 labs so that one
#: seed reproduces the whole platform's synthetic evidence.
DEFAULT_SEED = 20260917

#: Fixed base instant for lab records.  A real record carries the producer's
#: clock; a reproducible lab cannot.
LAB_BASE_TIMESTAMP = "2026-03-01T09:00:00Z"

#: Smallest clean baseline the structural scenarios can be expressed over.
#:
#: The scenarios address positions by index -- edit record 4, delete record 2,
#: splice after record 2 -- because an attack on a chain is an attack on a
#: *position*, and a scenario that renumbered itself to fit a shorter log would
#: no longer be the attack its ground truth describes.  Six is the smallest size
#: that leaves room for a genesis, an interior edit with a successor after it, a
#: deletion with records on both sides, and an untouched head.
MIN_LAB_RECORDS = 6

CLEAN = "clean"


def lab_signing_key(seed: int, name: str) -> Ed25519PrivateKey:
    """Derive a **test-only** Ed25519 key from a seed.

    A key derived from a published seed is a key every reader of this source
    already has.  It exists so the lab is byte-reproducible and for no other
    reason.  Operational keys come from
    :func:`cvtrust.provenance.keys.generate_keypair`, which draws from the OS
    CSPRNG and cannot be reproduced by anyone.
    """
    material = hashlib.sha256(
        f"cvtrust-provenance-lab|{PROVENANCE_LAB_VERSION}|{seed}|{name}".encode("utf-8")
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(material)


def lab_nonce(seed: int, log_id: str, index: int) -> str:
    """A deterministic stand-in for :func:`cvtrust.provenance.record.new_nonce`."""
    return hashlib.sha256(
        f"nonce|{seed}|{log_id}|{index}".encode("utf-8")
    ).hexdigest()[:32]


def lab_timestamp(index: int, *, base_hour: int = 9) -> str:
    """One record per minute from the fixed base instant."""
    minute = index % 60
    hour = base_hour + (index // 60)
    return f"2026-03-01T{hour:02d}:{minute:02d}:00Z"


@dataclass
class ProvenanceScenario:
    """One built scenario on disk, with its ground truth beside it."""

    name: str
    out_dir: Path
    log_path: Path
    trust_store_path: Path
    anchor_path: Path | None
    artifacts_dir: Path | None
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
class CleanBundle:
    """The clean baseline every scenario is derived from."""

    root: Path
    log: ProvenanceLog
    trust_store: TrustStore
    anchor: LogAnchor
    signing_key: Ed25519PrivateKey
    rotated_key: Ed25519PrivateKey
    adversary_key: Ed25519PrivateKey
    input_paths: list[Path]
    model_path: Path
    model_binding: ModelBinding
    seed: int


# ---------------------------------------------------------------------------
# The clean baseline
# ---------------------------------------------------------------------------


def build_clean(
    out_dir: Path | str,
    *,
    seed: int = DEFAULT_SEED,
    record_count: int = 6,
    log_id: str = "lab-log-1",
) -> CleanBundle:
    """Generate artifacts, keys, a trust store and a clean signed log."""
    if record_count < MIN_LAB_RECORDS:
        raise ProvenanceError(
            f"the provenance lab needs at least {MIN_LAB_RECORDS} records; "
            f"{record_count} was requested. The structural scenarios address "
            "positions by index, and a shorter baseline would silently turn "
            "them into different attacks from the ones their ground truth "
            "describes."
        )
    root = Path(out_dir)
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    signing_key = lab_signing_key(seed, "signer-a")
    rotated_key = lab_signing_key(seed, "signer-b-rotated")
    adversary_key = lab_signing_key(seed, "adversary")

    # A "model artifact" here is just bytes. Module 3 binds Module 2's digests
    # and computes none of its own model forensics, so the lab needs a file with
    # stable content and nothing more. The integration test that binds a real
    # ONNX manifest lives in tests/integration/test_provenance_pipeline.py.
    model_path = artifacts / "model.bin"
    model_path.write_bytes(
        hashlib.sha256(f"model|{seed}".encode("utf-8")).digest() * 64
    )
    model_binding = _model_binding_for(model_path)

    input_paths: list[Path] = []
    for index in range(record_count):
        path = artifacts / f"input_{index:03d}.bin"
        path.write_bytes(
            hashlib.sha256(f"input|{seed}|{index}".encode("utf-8")).digest() * 16
        )
        input_paths.append(path)

    key_id, public_hex = export_public_key(signing_key)
    rotated_id, rotated_hex = export_public_key(rotated_key)
    store = trust_key(
        TrustStore.empty(),
        public_key=public_hex,
        label="signer-a",
        purpose=KeyPurpose.INFERENCE_PROVENANCE,
        provenance="lab-provisioned out of band",
    )
    store = trust_key(
        store,
        public_key=rotated_hex,
        label="signer-b (rotation successor)",
        purpose=KeyPurpose.INFERENCE_PROVENANCE,
        provenance="lab-provisioned out of band",
    )

    provenance_log = ProvenanceLog.new(log_id)
    for index, path in enumerate(input_paths):
        _append_lab_record(
            provenance_log,
            signing_key,
            seed=seed,
            index=index,
            input_path=path,
            model_binding=model_binding,
        )

    anchor = build_anchor(
        provenance_log.entries, note="lab anchor, taken out of band"
    )
    provenance_log.save(root / "log.jsonl")
    store.save(root / "trust_store.json")
    (root / "anchor.json").write_text(anchor.model_dump_json(indent=2), encoding="utf-8")
    log.info("clean provenance baseline: %d records -> %s", len(provenance_log), root)

    return CleanBundle(
        root=root,
        log=provenance_log,
        trust_store=store,
        anchor=anchor,
        signing_key=signing_key,
        rotated_key=rotated_key,
        adversary_key=adversary_key,
        input_paths=input_paths,
        model_path=model_path,
        model_binding=model_binding,
        seed=seed,
    )


def _model_binding_for(path: Path) -> ModelBinding:
    from ..core.hashing import sha256_file

    digest = sha256_file(path)
    return ModelBinding(
        model_id=f"M-{digest[:16]}",
        file_sha256=digest,
        graph_digest=hashlib.sha256(f"graph|{digest}".encode()).hexdigest(),
        parameter_digest=hashlib.sha256(f"params|{digest}".encode()).hexdigest(),
        parameter_count=12_345,
        model_format="onnx",
        # Deliberately a name the digests do not support: the lab keeps the
        # untrusted-metadata rule honest, exactly as the Module 2 substitution
        # scenario keeps the reference architecture name in its metadata.
        declared_name="wheel_defect_detector_v3",
        declared_version="3.1.0",
    )


def lab_preprocessing() -> Any:
    return bind_config(
        {
            "resize": [224, 224],
            "interpolation": "bilinear",
            "letterbox": True,
            "colour_conversion": "BGR_to_RGB",
            "channel_order": "CHW",
            "dtype": "float32",
            "mean": [0.485, 0.456, 0.406],
            "std": [0.229, 0.224, 0.225],
            "rotation_degrees": 0,
        }
    )


def lab_inference_config() -> Any:
    return bind_config(
        {
            "confidence_threshold": 0.25,
            "nms_iou_threshold": 0.45,
            "max_detections": 100,
            "top_k": 5,
            "postprocessing": "sigmoid",
        }
    )


def _append_lab_record(
    provenance_log: ProvenanceLog,
    key: Ed25519PrivateKey,
    *,
    seed: int,
    index: int,
    input_path: Path,
    model_binding: ModelBinding,
) -> SignedRecord:
    output = (
        classification_output(
            {"wheel_defect": 0.91 - index * 0.01, "clean": 0.09 + index * 0.01},
        )
        if index % 2 == 0
        else detection_output(
            [
                {"label": "wheel_defect", "score": 0.83, "box": (12.5, 30.0, 88.25, 140.75)},
                {"label": "coupling", "score": 0.41, "box": (150.0, 10.0, 210.5, 60.0)},
            ],
            labels=("wheel_defect", "coupling", "clean"),
        )
    )

    def factory(sequence_number: int, previous_record_digest: str | None):
        return create_provenance_record(
            # A locator relative to the artifacts directory, not an absolute
            # path: the locator is inside the signature, so an absolute one
            # would make a lab built in two directories differ byte for byte
            # and the reproducibility test could not be written.
            input_binding=bind_input(
                input_path,
                locator=f"artifacts/{input_path.name}",
                media_type="application/octet-stream",
            ),
            model_binding=model_binding,
            preprocessing=lab_preprocessing(),
            inference=lab_inference_config(),
            output=bind_output(output),
            log_id=provenance_log.log_id,
            sequence_number=sequence_number,
            previous_record_digest=previous_record_digest,
            execution=ExecutionMetadata(
                runtime="onnxruntime",
                runtime_version="1.x",
                adapter="onnx",
                adapter_version="1.0",
                access_mode="white_box",
                host_label="lab-host",
                device="cpu",
            ),
            timestamp=lab_timestamp(index),
            nonce=lab_nonce(seed, provenance_log.log_id, index),
            producer="lab-producer",
        )

    return provenance_log.append_signed(factory, key)


# ---------------------------------------------------------------------------
# Expectation helpers
# ---------------------------------------------------------------------------


def expected_from_clean(clean: CleanBundle) -> dict[str, Any]:
    """The analyst's independently held truth about the clean baseline."""
    return {
        "model_file_sha256": clean.model_binding.file_sha256,
        "model_graph_digest": clean.model_binding.graph_digest,
        "model_parameter_digest": clean.model_binding.parameter_digest,
        "model_id": clean.model_binding.model_id,
        "preprocessing_digest": lab_preprocessing().digest,
        "inference_digest": lab_inference_config().digest,
        # Deliberately no log_id and no input digest. A log id is an operator
        # label shared across a whole log, and the raw input digest differs per
        # record, so neither belongs in a single log-wide expectation. Input
        # binding against a real artifact is exercised directly in
        # tests/security/test_provenance_attacks.py.
        "source": "lab ground truth, held independently of the log",
    }


def _ground_truth(
    *,
    description: str,
    attack_classes: Sequence[str],
    per_record: dict[int, list[str]],
    chain_status: str,
    truncation_status: str,
    replay: dict[int, str] | None = None,
    malformed_lines: int = 0,
    expected_record_count: int,
    notes: Sequence[str] = (),
    anchor_supplied: bool = True,
    expectations_supplied: bool = True,
) -> dict[str, Any]:
    return {
        "lab_version": PROVENANCE_LAB_VERSION,
        "description": description,
        "attack_classes": list(attack_classes),
        "expected_record_count": expected_record_count,
        "expected_failures_by_position": {
            str(position): sorted(codes) for position, codes in sorted(per_record.items())
        },
        "expected_chain_status": chain_status,
        "expected_truncation_status": truncation_status,
        "expected_replay_by_position": {
            str(position): verdict for position, verdict in sorted((replay or {}).items())
        },
        "expected_malformed_lines": malformed_lines,
        "anchor_supplied": anchor_supplied,
        "expectations_supplied": expectations_supplied,
        "notes": list(notes),
    }


def _valid_everywhere(count: int) -> dict[int, list[str]]:
    return {position: [FailureCode.VALID.value] for position in range(count)}


def _successor_break(per_record: dict[int, list[str]], position: int, count: int) -> None:
    """Mark the link break that editing the entry at ``position`` causes.

    Exactly **one** link breaks, not all of them, and the difference matters
    enough to be encoded here rather than assumed.  Entry *n+1* stores the
    digest of entry *n* as it was when *n+1* was written, so editing *n*
    invalidates that one back-pointer.  Entry *n+2* stores the digest of *n+1*,
    which nobody touched, so it still matches.

    That localisation is a feature: the chain does not merely report "this log
    is broken", it reports *where*, and an analyst can read the position of the
    single break as the position of the edit.  A structural change that also
    shifts sequence numbers -- an insertion, a deletion -- is different, and
    those scenarios enumerate their breaks explicitly.
    """
    successor = position + 1
    if successor < count:
        per_record[successor] = sorted(
            set(per_record.get(successor, [])) - {FailureCode.VALID.value}
            | {FailureCode.CHAIN_BREAK.value}
        )


def _write_scenario(
    clean: CleanBundle,
    name: str,
    out_dir: Path,
    *,
    entries: Sequence[SignedRecord],
    store: TrustStore | None = None,
    anchor: LogAnchor | None = None,
    raw_lines: Sequence[str] | None = None,
    copy_artifacts: bool = False,
    artifact_mutation: Callable[[Path], None] | None = None,
    ground_truth: dict[str, Any],
    config: dict[str, Any],
    attack_classes: Sequence[str],
) -> ProvenanceScenario:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "log.jsonl"

    if raw_lines is not None:
        log_path.write_text("".join(line + "\n" for line in raw_lines), encoding="utf-8")
    else:
        log_path.write_text(
            "".join(
                canonical_json(entry.entry_payload()).decode("utf-8") + "\n"
                for entry in entries
            ),
            encoding="utf-8",
        )

    store_path = out_dir / "trust_store.json"
    (store or clean.trust_store).save(store_path)

    anchor_path: Path | None = None
    if anchor is not None:
        anchor_path = out_dir / "anchor.json"
        anchor_path.write_text(anchor.model_dump_json(indent=2), encoding="utf-8")

    artifacts_dir: Path | None = None
    if copy_artifacts:
        artifacts_dir = out_dir / "artifacts"
        if artifacts_dir.exists():
            shutil.rmtree(artifacts_dir)
        shutil.copytree(clean.root / "artifacts", artifacts_dir)
        if artifact_mutation is not None:
            artifact_mutation(artifacts_dir)

    scenario = ProvenanceScenario(
        name=name,
        out_dir=out_dir,
        log_path=log_path,
        trust_store_path=store_path,
        anchor_path=anchor_path,
        artifacts_dir=artifacts_dir,
        attack_classes=list(attack_classes),
        ground_truth=ground_truth,
        config={"scenario": name, "seed": clean.seed, "lab_version": PROVENANCE_LAB_VERSION,
                **config},
    )
    scenario.write()
    return scenario


def _resign(record: Any, key: Ed25519PrivateKey) -> SignedRecord:
    """Re-derive the record id for mutated content, then sign.

    Used by scenarios that model an adversary who *has* a signing key.  Without
    the id refresh the record would also fail ``record_id_matches_content``, and
    the scenario would be testing two things at once — which would make it
    impossible to tell which check caught the attack.
    """
    refreshed = record.model_copy(update={"record_id": "PR-0000000000000000"})
    refreshed = refreshed.model_copy(update={"record_id": refreshed.expected_record_id()})
    return sign_record(refreshed, key)


def _mutate_signed_in_place(entry: SignedRecord, **record_updates: Any) -> SignedRecord:
    """Alter a record's content while keeping its original signature.

    This is the *unprivileged* adversary: they can edit the log file but cannot
    sign.  The expected outcome is ``INVALID_SIGNATURE``, and usually
    ``SELF_INCONSISTENT_RECORD`` too, since the record id no longer matches.
    """
    return entry.model_copy(
        update={"record": entry.record.model_copy(update=record_updates)}
    )


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def scenario_clean(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    count = len(clean.log.entries)
    return _write_scenario(
        clean, "clean", out_dir,
        entries=clean.log.entries,
        anchor=clean.anchor,
        copy_artifacts=True,
        attack_classes=[CLEAN],
        ground_truth=_ground_truth(
            description="An untampered signed log from a trusted key, with a "
            "matching anchor. Present so that false positives are measurable: a "
            "lab containing only attacks measures nothing.",
            attack_classes=[CLEAN],
            per_record=_valid_everywhere(count),
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
        ),
        config={"mutation": "none"},
    )


def scenario_modified_input_digest(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """Unprivileged edit of the bound input digest."""
    entries = list(clean.log.entries)
    target = entries[2]
    entries[2] = _mutate_signed_in_place(
        target,
        input=target.record.input.model_copy(
            update={"raw_input_digest": "f" * 64}
        ),
    )
    per_record = _valid_everywhere(len(entries))
    per_record[2] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
    })
    _successor_break(per_record, 2, len(entries))
    return _write_scenario(
        clean, "modified_input_digest", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="The raw input digest in record 2 was changed by someone "
            "without a signing key.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
            notes=[
                "The anchor still matches, and that is correct rather than a "
                "miss: an anchor attests the head and the count, and neither "
                "changed. The interior edit is the chain's job, and the chain "
                "catches it. The two mechanisms cover different things and the "
                "report keeps them as separate fields for that reason.",
                "No per-record input expectation is supplied in the lab, so this "
                "record is caught by its broken signature alone -- which is the "
                "realistic case for an adversary without a key.",
            ],
        ),
        config={"mutation": "input.raw_input_digest", "position": 2},
    )


def scenario_modified_model_digest(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """Privileged edit: an adversary with a signing key swaps the model digest.

    The most instructive scenario in the lab.  The signature verifies, the
    record is internally perfect, and the attack is caught only because the key
    is not in the trust store *and* the bound model digest does not match the
    model the analyst assured.
    """
    entries = list(clean.log.entries)
    target = entries[1].record
    mutated = target.model_copy(
        update={
            "model": target.model.model_copy(
                update={"file_sha256": "b" * 64, "model_id": "M-bbbbbbbbbbbbbbbb"}
            )
        }
    )
    entries[1] = _resign(mutated, clean.adversary_key)
    per_record = _valid_everywhere(len(entries))
    per_record[1] = sorted({
        FailureCode.MODEL_MISMATCH.value,
        FailureCode.UNKNOWN_KEY.value,
    })
    _successor_break(per_record, 1, len(entries))
    return _write_scenario(
        clean, "modified_model_digest", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering", "provenance_key_trust"],
        ground_truth=_ground_truth(
            description="An adversary holding their own signing key rewrote the "
            "bound model digest and re-signed. The signature verifies; the key "
            "is unknown and the model digest does not match what the analyst "
            "holds.",
            attack_classes=["inference_tampering", "provenance_key_trust"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
            notes=[
                "Signature validity alone would have passed this record. The "
                "trust store and the independent expectation are what catch it.",
                "Re-signing also refreshes the record id, so record_id_matches_"
                "content passes. A privileged adversary leaves no self-"
                "inconsistency; only external facts contradict them.",
            ],
        ),
        config={"mutation": "model.file_sha256", "position": 1, "resigned_with": "adversary"},
    )


def scenario_modified_model_artifact(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """The log is untouched; the model file on disk was swapped underneath it."""
    def mutate(artifacts: Path) -> None:
        (artifacts / "model.bin").write_bytes(b"\x00" * 2048)

    count = len(clean.log.entries)
    return _write_scenario(
        clean, "modified_model_artifact", out_dir,
        entries=clean.log.entries, anchor=clean.anchor,
        copy_artifacts=True, artifact_mutation=mutate,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="Every record is genuine and the chain is intact, but the "
            "model artifact on disk has been replaced. Re-deriving the "
            "expectation from the artifact now contradicts every record.",
            attack_classes=["inference_tampering"],
            per_record={
                position: [FailureCode.MODEL_MISMATCH.value] for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
            notes=[
                "This scenario must be evaluated with the expectation re-derived "
                "from artifacts/model.bin, not from the clean baseline. It is the "
                "case where the cryptography is flawless and the deployment is "
                "not.",
            ],
        ),
        config={"mutation": "artifacts/model.bin", "expectation_source": "scenario artifacts"},
    )


def _privileged_field_scenario(
    clean: CleanBundle,
    out_dir: Path,
    *,
    name: str,
    position: int,
    updates: Callable[[Any], dict[str, Any]],
    failures: list[str],
    description: str,
    attack_classes: Sequence[str],
    mutation: str,
) -> ProvenanceScenario:
    """An adversary with a key edits one bound field and re-signs."""
    entries = list(clean.log.entries)
    mutated = entries[position].record.model_copy(update=updates(entries[position].record))
    entries[position] = _resign(mutated, clean.adversary_key)
    per_record = _valid_everywhere(len(entries))
    per_record[position] = sorted(set(failures))
    _successor_break(per_record, position, len(entries))
    return _write_scenario(
        clean, name, out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=attack_classes,
        ground_truth=_ground_truth(
            description=description,
            attack_classes=attack_classes,
            per_record=per_record,
            # Editing the head would change the head digest; editing the
            # interior does not, so the anchor still holds and the chain is
            # what catches the edit.
            chain_status="BROKEN" if position < len(entries) - 1 else "INTACT",
            truncation_status=(
                "VERIFIED_COMPLETE" if position < len(entries) - 1
                else "TRUNCATION_DETECTED"
            ),
            expected_record_count=len(entries),
        ),
        config={"mutation": mutation, "position": position, "resigned_with": "adversary"},
    )


def scenario_modified_preprocessing(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    replacement = bind_config(
        {
            "resize": [320, 320],
            "interpolation": "nearest",
            "letterbox": False,
            "colour_conversion": "none",
            "channel_order": "HWC",
            "dtype": "uint8",
            "mean": [0.0, 0.0, 0.0],
            "std": [1.0, 1.0, 1.0],
            "rotation_degrees": 90,
        }
    )
    return _privileged_field_scenario(
        clean, out_dir,
        name="modified_preprocessing_config",
        position=3,
        updates=lambda record: {"preprocessing": replacement},
        failures=[
            FailureCode.CONFIGURATION_MISMATCH.value,
            FailureCode.UNKNOWN_KEY.value,
        ],
        description="Preprocessing was rewritten and the record re-signed with an "
        "adversary key. The same model and the same image under different "
        "preprocessing is a different inference.",
        attack_classes=["inference_tampering", "provenance_key_trust"],
        mutation="preprocessing",
    )


def scenario_modified_inference_config(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    replacement = bind_config(
        {
            "confidence_threshold": 0.01,
            "nms_iou_threshold": 0.95,
            "max_detections": 10_000,
            "top_k": 1,
            "postprocessing": "none",
        }
    )
    return _privileged_field_scenario(
        clean, out_dir,
        name="modified_inference_config",
        position=3,
        updates=lambda record: {"inference": replacement},
        failures=[
            FailureCode.CONFIGURATION_MISMATCH.value,
            FailureCode.UNKNOWN_KEY.value,
        ],
        description="Inference thresholds were rewritten and the record re-signed. "
        "Dropping the confidence threshold to 0.01 turns the same model into a "
        "different detector.",
        attack_classes=["inference_tampering", "provenance_key_trust"],
        mutation="inference",
    )


def scenario_modified_output(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """Unprivileged edit of the bound output digest alone.

    Leaves the inline output in place, so the record contradicts itself and is
    caught by self-consistency even before the signature check.
    """
    entries = list(clean.log.entries)
    target = entries[4]
    entries[4] = _mutate_signed_in_place(
        target, output=target.record.output.model_copy(update={"digest": "c" * 64})
    )
    per_record = _valid_everywhere(len(entries))
    per_record[4] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.OUTPUT_MISMATCH.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
    })
    _successor_break(per_record, 4, len(entries))
    return _write_scenario(
        clean, "modified_output", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="The bound output digest was changed without touching the "
            "inline output. Three independent checks catch it: the signature, "
            "the record's self-consistency, and the expectation.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "output.digest", "position": 4},
    )


def scenario_modified_timestamp(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries[2] = _mutate_signed_in_place(entries[2], timestamp="2019-01-01T00:00:00Z")
    per_record = _valid_everywhere(len(entries))
    per_record[2] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
    })
    _successor_break(per_record, 2, len(entries))
    return _write_scenario(
        clean, "modified_timestamp", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="A timestamp was backdated in the log. The timestamp is "
            "inside the signature, so the edit is detected -- which is the "
            "strongest claim available: signing a clock binds the claim, not the "
            "time.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "timestamp", "position": 2},
    )


def scenario_modified_nonce(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries[1] = _mutate_signed_in_place(entries[1], nonce="0" * 32)
    per_record = _valid_everywhere(len(entries))
    per_record[1] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
    })
    _successor_break(per_record, 1, len(entries))
    return _write_scenario(
        clean, "modified_nonce", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="A nonce was replaced in the log.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "nonce", "position": 1},
    )


def scenario_modified_sequence(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    target = entries[3]
    entries[3] = _mutate_signed_in_place(
        target,
        sequence=target.record.sequence.model_copy(update={"sequence_number": 99}),
    )
    per_record = _valid_everywhere(len(entries))
    # Two independent breaks at this position: the sequence rule fires on the
    # record itself, and the successor's back-pointer fires on the edit.
    per_record[3] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
        FailureCode.CHAIN_BREAK.value,
    })
    _successor_break(per_record, 3, len(entries))
    return _write_scenario(
        clean, "modified_sequence", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering"],
        ground_truth=_ground_truth(
            description="A sequence number was rewritten. Linkage and the "
            "sequence rule fail independently, which is what turns 'link 3 is "
            "wrong' into 'the position was altered'.",
            attack_classes=["record_reordering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "sequence.sequence_number", "position": 3},
    )


def scenario_modified_previous_digest(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    target = entries[2]
    entries[2] = _mutate_signed_in_place(
        target,
        sequence=target.record.sequence.model_copy(
            update={"previous_record_digest": "d" * 64}
        ),
    )
    per_record = _valid_everywhere(len(entries))
    per_record[2] = sorted({
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
        FailureCode.CHAIN_BREAK.value,
    })
    _successor_break(per_record, 2, len(entries))
    return _write_scenario(
        clean, "modified_previous_digest", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering"],
        ground_truth=_ground_truth(
            description="A back-pointer was rewritten to break the link to its "
            "predecessor.",
            attack_classes=["record_reordering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "sequence.previous_record_digest", "position": 2},
    )


def scenario_deleted_record(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = [e for index, e in enumerate(clean.log.entries) if index != 2]
    per_record = _valid_everywhere(len(entries))
    # A deletion shifts every later record's position, so the sequence rule
    # fires on all of them even though only the first has a broken back-pointer.
    # That is the diagnosis the sequence numbers exist to provide: one link
    # failure plus a run of off-by-one sequences reads as "an entry was removed
    # here", which a linkage-only chain could not say.
    for position in range(2, len(entries)):
        per_record[position] = [FailureCode.CHAIN_BREAK.value]
    return _write_scenario(
        clean, "deleted_record", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering"],
        ground_truth=_ground_truth(
            description="A middle record was removed. Every record that remains is "
            "individually valid; only the chain reveals the gap.",
            attack_classes=["record_reordering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="ANCHOR_MISMATCH",
            expected_record_count=len(entries),
            notes=[
                "This is the case that justifies the chain existing at all: "
                "record-by-record verification alone reports a clean log.",
            ],
        ),
        config={"mutation": "delete", "position": 2},
    )


def scenario_inserted_record(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """A well-formed, adversary-signed record spliced into the middle."""
    entries = list(clean.log.entries)
    template = entries[0].record
    forged = template.model_copy(
        update={
            "record_id": "PR-0000000000000000",
            "nonce": lab_nonce(clean.seed, clean.log.log_id, 900),
            "timestamp": lab_timestamp(30),
            "sequence": template.sequence.model_copy(
                update={
                    "sequence_number": 3,
                    "previous_record_digest": entries[2].entry_digest(),
                }
            ),
        }
    )
    inserted = _resign(forged, clean.adversary_key)
    entries.insert(3, inserted)
    per_record = _valid_everywhere(len(entries))
    # The forged entry's own link is intact -- it was built with a correct
    # back-pointer -- so only the trust store catches it. Everything after it is
    # displaced by one position, so the sequence rule fires on all of them.
    per_record[3] = [FailureCode.UNKNOWN_KEY.value]
    for later in range(4, len(entries)):
        per_record[later] = [FailureCode.CHAIN_BREAK.value]
    # The displaced original now claims the sequence slot the forgery took, so
    # the replay database reports a fork. Two unrelated mechanisms -- the chain
    # and the replay database -- independently flag the same insertion, which is
    # worth having: neither depends on the other being correct.
    per_record[4] = sorted(set(per_record[4]) | {FailureCode.REPLAY.value})
    return _write_scenario(
        clean, "inserted_record", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering", "provenance_key_trust"],
        ground_truth=_ground_truth(
            description="A forged record was spliced in after position 2, with a "
            "correct back-pointer. Its own link is therefore intact; the entries "
            "after it are not, because their back-pointers still name the "
            "pre-insertion predecessor.",
            attack_classes=["record_reordering", "provenance_key_trust"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="ANCHOR_MISMATCH",
            replay={3: "DUPLICATE_SUBJECT", 4: "SEQUENCE_COLLISION"},
            expected_record_count=len(entries),
            notes=[
                "The forged record reuses record 0's input, model and "
                "configuration, so the replay database reports DUPLICATE_SUBJECT "
                "for it -- an observation, not a failure, because processing the "
                "same image twice is normal.",
                "The displaced original at position 4 claims the sequence slot "
                "the forgery took, which the replay database reports as a fork.",
            ],
        ),
        config={"mutation": "insert", "position": 3, "signed_with": "adversary"},
    )


def scenario_reordered_records(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries[2], entries[3] = entries[3], entries[2]
    per_record = _valid_everywhere(len(entries))
    # A swap of positions 2 and 3 breaks three links, not two: 2 and 3 each
    # hold the wrong back-pointer and sequence number, and 4 breaks as well
    # because its back-pointer names the record that is now at position 2.
    # Position 5 is untouched -- the damage is bounded by the swap's extent,
    # which is what makes the break positions readable as a diagnosis.
    for position in (2, 3, 4):
        per_record[position] = [FailureCode.CHAIN_BREAK.value]
    return _write_scenario(
        clean, "reordered_records", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering"],
        ground_truth=_ground_truth(
            description="Two adjacent records were swapped. Every signature still "
            "verifies; back-pointers follow content, not position, so the swap "
            "is visible.",
            attack_classes=["record_reordering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
            notes=[
                "The head and the entry count are unchanged, so the anchor still "
                "holds. Reordering is the chain's job, not the anchor's.",
            ],
        ),
        config={"mutation": "swap", "positions": [2, 3]},
    )


def scenario_duplicated_record(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries.insert(3, entries[2])
    per_record = _valid_everywhere(len(entries))
    # The duplicate occupies position 3: its back-pointer names position 1's
    # digest, its sequence repeats, and the replay database has already seen it.
    per_record[3] = sorted({FailureCode.CHAIN_BREAK.value, FailureCode.REPLAY.value})
    # Everything after the duplicate is displaced by one, so the sequence rule
    # fires on all of it.
    for later in range(4, len(entries)):
        per_record[later] = [FailureCode.CHAIN_BREAK.value]
    return _write_scenario(
        clean, "duplicated_record", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["record_reordering", "inference_replay"],
        ground_truth=_ground_truth(
            description="A record was duplicated in place. Two independent "
            "mechanisms fire: the chain (repeated sequence, wrong back-pointer) "
            "and the replay database (identical entry digest).",
            attack_classes=["record_reordering", "inference_replay"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="ANCHOR_MISMATCH",
            replay={3: "REPLAY_EXACT"},
            expected_record_count=len(entries),
        ),
        config={"mutation": "duplicate", "position": 2},
    )


def scenario_unknown_key(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """A whole log signed by a key nobody trusts.  Every signature verifies."""
    provenance_log = ProvenanceLog.new(clean.log.log_id)
    for index, path in enumerate(clean.input_paths):
        _append_lab_record(
            provenance_log, clean.adversary_key,
            seed=clean.seed, index=index, input_path=path,
            model_binding=clean.model_binding,
        )
    count = len(provenance_log.entries)
    return _write_scenario(
        clean, "unknown_key", out_dir,
        entries=provenance_log.entries,
        anchor=build_anchor(provenance_log.entries),
        copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="An entirely self-consistent log, perfectly chained, "
            "every signature valid -- signed by a key the operator has never "
            "authorised. This is what 'cryptographically valid' is worth on its "
            "own.",
            attack_classes=["provenance_key_trust"],
            per_record={
                position: [FailureCode.UNKNOWN_KEY.value] for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
        ),
        config={"mutation": "signed_by_untrusted_key"},
    )


def scenario_revoked_key(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    key_id, _ = export_public_key(clean.signing_key)
    store = revoke_key(
        clean.trust_store, key_id,
        reason="signing host suspected compromised on 2026-03-05",
        revoked_at="2026-03-05T00:00:00Z",
    )
    count = len(clean.log.entries)
    return _write_scenario(
        clean, "revoked_key", out_dir,
        entries=clean.log.entries, store=store, anchor=clean.anchor,
        copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="The log is untouched, but its signing key has since been "
            "revoked. Revocation is absolute; whether the records claim to "
            "predate it is reported as a separate, self-asserted fact.",
            attack_classes=["provenance_key_trust"],
            per_record={
                position: [FailureCode.REVOKED_KEY.value] for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
            notes=[
                "Every record's timestamp precedes the revocation, and the "
                "verification says so -- as a claim by the record, not a fact.",
            ],
        ),
        config={"mutation": "revoke_signing_key", "revoked_at": "2026-03-05T00:00:00Z"},
    )


def scenario_malformed_record(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    lines = [
        canonical_json(entry.entry_payload()).decode("utf-8")
        for entry in clean.log.entries
    ]
    lines.insert(3, '{"record": {"schema_version": "1.0", "oops": true}')
    per_record = _valid_everywhere(len(clean.log.entries))
    return _write_scenario(
        clean, "malformed_record", out_dir,
        entries=clean.log.entries, raw_lines=lines,
        anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="A line of the log is not parseable JSON. The loader keeps "
            "going: aborting would let one byte hide every finding in the rest of "
            "the log.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            malformed_lines=1,
            expected_record_count=len(clean.log.entries),
            notes=[
                "The parseable records still verify and still chain, because the "
                "malformed line was never part of the chain. The report carries "
                "the malformed line as its own finding.",
            ],
        ),
        config={"mutation": "insert_unparseable_line", "line": 4},
    )


def scenario_schema_version_mismatch(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries[1] = _mutate_signed_in_place(entries[1], schema_version="9.9")
    per_record = _valid_everywhere(len(entries))
    per_record[1] = sorted({
        FailureCode.UNSUPPORTED_SCHEMA.value,
        FailureCode.INVALID_SIGNATURE.value,
        FailureCode.SELF_INCONSISTENT_RECORD.value,
    })
    _successor_break(per_record, 1, len(entries))
    return _write_scenario(
        clean, "schema_version_mismatch", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["inference_tampering"],
        ground_truth=_ground_truth(
            description="A record claims a schema version this build does not "
            "implement. The verifier refuses rather than guessing what the "
            "fields mean.",
            attack_classes=["inference_tampering"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
        ),
        config={"mutation": "schema_version", "position": 1, "value": "9.9"},
    )


def scenario_key_rotation(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """Half the log signed by the old key, half by its successor.  Clean."""
    provenance_log = ProvenanceLog.new(clean.log.log_id)
    split = len(clean.input_paths) // 2
    for index, path in enumerate(clean.input_paths):
        _append_lab_record(
            provenance_log,
            clean.signing_key if index < split else clean.rotated_key,
            seed=clean.seed, index=index, input_path=path,
            model_binding=clean.model_binding,
        )
    count = len(provenance_log.entries)
    return _write_scenario(
        clean, "key_rotation", out_dir,
        entries=provenance_log.entries,
        anchor=build_anchor(provenance_log.entries),
        copy_artifacts=True,
        attack_classes=[CLEAN],
        ground_truth=_ground_truth(
            description="The signing key was rotated mid-log. Both keys are "
            "trusted, so the whole log verifies: rotation is an ordinary state, "
            "not an outage.",
            attack_classes=[CLEAN],
            per_record=_valid_everywhere(count),
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
        ),
        config={"mutation": "rotate_key_at", "split": split},
    )


def scenario_truncated_log(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = clean.log.entries[:3]
    return _write_scenario(
        clean, "truncated_log", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["chain_truncation"],
        ground_truth=_ground_truth(
            description="The last three entries were removed. The remaining chain "
            "is internally perfect -- every record valid, every link intact -- "
            "and only the anchor reveals the loss.",
            attack_classes=["chain_truncation"],
            per_record=_valid_everywhere(len(entries)),
            chain_status="INTACT",
            truncation_status="TRUNCATION_DETECTED",
            expected_record_count=len(entries),
            notes=[
                "Evaluated WITHOUT the anchor, this scenario is indistinguishable "
                "from a clean three-record log, and the verifier says so: "
                "truncation_status NOT_DETECTABLE, never clean.",
            ],
        ),
        config={"mutation": "truncate_tail", "removed": 3},
    )


def scenario_front_truncated_log(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = clean.log.entries[2:]
    # Every remaining record is displaced by two, so the sequence rule fires on
    # all of them; the genesis rule fires additionally on the first.
    per_record = {
        position: [FailureCode.CHAIN_BREAK.value] for position in range(len(entries))
    }
    return _write_scenario(
        clean, "front_truncated_log", out_dir,
        entries=entries, copy_artifacts=True,
        attack_classes=["chain_truncation"],
        ground_truth=_ground_truth(
            description="The first two entries were removed. Unlike tail "
            "truncation this IS self-detectable: genesis must carry a null "
            "back-pointer and sequence 0.",
            attack_classes=["chain_truncation"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="FRONT_TRUNCATION_DETECTED",
            expected_record_count=len(entries),
            anchor_supplied=False,
        ),
        config={"mutation": "truncate_front", "removed": 2},
    )


def scenario_missing_signature(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    entries = list(clean.log.entries)
    entries[2] = SignedRecord(record=entries[2].record, signature=None)
    per_record = _valid_everywhere(len(entries))
    per_record[2] = [FailureCode.MISSING_SIGNATURE.value]
    _successor_break(per_record, 2, len(entries))
    return _write_scenario(
        clean, "missing_signature", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="A signature was stripped. The record's content is "
            "unchanged, so nothing it asserts is contradicted -- but it now "
            "attributes itself to no one, and the chain notices because the "
            "chained digest covers the signature envelope.",
            attack_classes=["provenance_key_trust"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
            notes=[
                "This is why entry_digest covers the signature and not only the "
                "payload: a payload-only chain would report itself intact here.",
            ],
        ),
        config={"mutation": "strip_signature", "position": 2},
    )


def scenario_replay_exact(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """The same signed record, re-presented in a second log.

    Case A of the brief's replay semantics: cryptographically valid, and a
    replay if the verifier has seen it before.  The evaluation harness runs the
    clean log through the replay database first, so this log's records are all
    second presentations.
    """
    entries = clean.log.entries[:2]
    count = len(entries)
    return _write_scenario(
        clean, "replay_exact", out_dir,
        entries=entries, copy_artifacts=True,
        attack_classes=["inference_replay"],
        ground_truth=_ground_truth(
            description="Two genuine records re-presented after the original log "
            "was already observed. Every signature verifies and every binding "
            "holds; they are replays because they have been seen before.",
            attack_classes=["inference_replay"],
            per_record={
                position: [FailureCode.REPLAY.value] for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="NOT_DETECTABLE",
            replay={position: "REPLAY_EXACT" for position in range(count)},
            expected_record_count=count,
            anchor_supplied=False,
            notes=[
                "Requires the replay database to have observed the clean log "
                "first. Evaluated with a fresh database these records are "
                "FIRST_OBSERVATION and valid, which is correct and is the "
                "limitation the report states.",
            ],
        ),
        config={"mutation": "replay", "prime_with": "clean", "records": count},
    )


def scenario_legitimate_reprocess(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """Case B: the same images processed again, properly.  NOT a replay.

    The false-positive guard for the replay detector, and the reason
    ``DUPLICATE_SUBJECT`` exists as a distinct verdict.
    """
    provenance_log = ProvenanceLog.new("lab-log-2")
    for index, path in enumerate(clean.input_paths[:3]):
        _append_lab_record(
            provenance_log, clean.signing_key,
            seed=clean.seed + 1, index=index, input_path=path,
            model_binding=clean.model_binding,
        )
    count = len(provenance_log.entries)
    return _write_scenario(
        clean, "legitimate_reprocess", out_dir,
        entries=provenance_log.entries,
        anchor=build_anchor(provenance_log.entries),
        copy_artifacts=True,
        attack_classes=[CLEAN],
        ground_truth=_ground_truth(
            description="The same inputs, the same model and the same "
            "configuration, processed again into a new log with fresh nonces and "
            "a fresh sequence. This is NOT a replay and must not be reported as "
            "one.",
            attack_classes=[CLEAN],
            per_record=_valid_everywhere(count),
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            replay={position: "DUPLICATE_SUBJECT" for position in range(count)},
            expected_record_count=count,
            notes=[
                "Requires the replay database to have observed the clean log "
                "first; that is exactly what makes the DUPLICATE_SUBJECT verdict "
                "reachable and the distinction testable.",
            ],
        ),
        config={"mutation": "reprocess", "log_id": "lab-log-2"},
    )


def scenario_stale_key_window(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """A key trusted only for a window that ends before the log was written."""
    key_id, public_hex = export_public_key(clean.signing_key)
    rotated_id, rotated_hex = export_public_key(clean.rotated_key)
    store = trust_key(
        TrustStore.empty(),
        public_key=public_hex,
        label="signer-a (expired)",
        valid_from="2025-01-01T00:00:00Z",
        valid_until="2026-02-01T00:00:00Z",
        provenance="lab-provisioned out of band",
    )
    store = trust_key(
        store, public_key=rotated_hex, label="signer-b",
        provenance="lab-provisioned out of band",
    )
    count = len(clean.log.entries)
    return _write_scenario(
        clean, "expired_key_window", out_dir,
        entries=clean.log.entries, store=store, anchor=clean.anchor,
        copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="The signing key's trusted window ended a month before "
            "the log's timestamps. Under the at_record_timestamp policy the "
            "records fall outside it.",
            attack_classes=["provenance_key_trust"],
            per_record={
                position: [FailureCode.KEY_EXPIRED.value] for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
            notes=[
                "The window is evaluated against the record's own clock, which a "
                "key holder controls. The verification records which policy it "
                "used and that the moment is self-asserted.",
            ],
        ),
        config={"mutation": "expired_key_window", "valid_until": "2026-02-01T00:00:00Z"},
    )


def scenario_wrong_key_purpose(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    key_id, public_hex = export_public_key(clean.signing_key)
    store = trust_key(
        TrustStore.empty(), public_key=public_hex, label="anchor-only key",
        purpose=KeyPurpose.LOG_ANCHOR,
        provenance="lab-provisioned out of band",
    )
    count = len(clean.log.entries)
    return _write_scenario(
        clean, "wrong_key_purpose", out_dir,
        entries=clean.log.entries, store=store, anchor=clean.anchor,
        copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="The signing key is trusted only to attest that a log is "
            "complete, not to sign inference records. Letting a log's producer "
            "mint its own completeness attestation would remove the only thing "
            "that makes truncation detectable.",
            attack_classes=["provenance_key_trust"],
            per_record={
                position: [FailureCode.KEY_PURPOSE_MISMATCH.value]
                for position in range(count)
            },
            chain_status="INTACT",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=count,
        ),
        config={"mutation": "key_purpose", "purpose": "log_anchor"},
    )


def scenario_key_id_forgery(clean: CleanBundle, out_dir: Path) -> ProvenanceScenario:
    """An envelope that names a trusted key but carries the adversary's."""
    entries = list(clean.log.entries)
    adversary_signed = _resign(entries[2].record, clean.adversary_key)
    trusted_key_id, _ = export_public_key(clean.signing_key)
    assert adversary_signed.signature is not None
    entries[2] = adversary_signed.model_copy(
        update={
            "signature": adversary_signed.signature.model_copy(
                update={"key_id": trusted_key_id}
            )
        }
    )
    per_record = _valid_everywhere(len(entries))
    per_record[2] = sorted({
        FailureCode.MALFORMED_SIGNATURE.value,
        FailureCode.UNKNOWN_KEY.value,
    })
    _successor_break(per_record, 2, len(entries))
    return _write_scenario(
        clean, "key_id_forgery", out_dir,
        entries=entries, anchor=clean.anchor, copy_artifacts=True,
        attack_classes=["provenance_key_trust"],
        ground_truth=_ground_truth(
            description="The envelope declares a trusted key_id while carrying the "
            "adversary's public key. Verifying against the carried key and "
            "reporting the named one would attribute the record to a key that "
            "did not sign it, so the envelope is rejected as malformed before "
            "any verification is attempted.",
            attack_classes=["provenance_key_trust"],
            per_record=per_record,
            chain_status="BROKEN",
            truncation_status="VERIFIED_COMPLETE",
            expected_record_count=len(entries),
            notes=[
                "key_known and key_trusted report NOT_APPLICABLE rather than "
                "resolving the declared id: reporting the named key's status for "
                "a record it did not sign is exactly the confusion this forgery "
                "is attempting.",
            ],
        ),
        config={"mutation": "key_id_substitution", "position": 2},
    )


#: Every scenario, by name.  Order is the order they are built and evaluated.
SCENARIOS: dict[str, Callable[[CleanBundle, Path], ProvenanceScenario]] = {
    "clean": scenario_clean,
    "modified_input_digest": scenario_modified_input_digest,
    "modified_model_digest": scenario_modified_model_digest,
    "modified_model_artifact": scenario_modified_model_artifact,
    "modified_preprocessing_config": scenario_modified_preprocessing,
    "modified_inference_config": scenario_modified_inference_config,
    "modified_output": scenario_modified_output,
    "modified_timestamp": scenario_modified_timestamp,
    "modified_nonce": scenario_modified_nonce,
    "modified_sequence": scenario_modified_sequence,
    "modified_previous_digest": scenario_modified_previous_digest,
    "deleted_record": scenario_deleted_record,
    "inserted_record": scenario_inserted_record,
    "reordered_records": scenario_reordered_records,
    "duplicated_record": scenario_duplicated_record,
    "unknown_key": scenario_unknown_key,
    "revoked_key": scenario_revoked_key,
    "malformed_record": scenario_malformed_record,
    "schema_version_mismatch": scenario_schema_version_mismatch,
    "key_rotation": scenario_key_rotation,
    "truncated_log": scenario_truncated_log,
    "front_truncated_log": scenario_front_truncated_log,
    "missing_signature": scenario_missing_signature,
    "replay_exact": scenario_replay_exact,
    "legitimate_reprocess": scenario_legitimate_reprocess,
    "expired_key_window": scenario_stale_key_window,
    "wrong_key_purpose": scenario_wrong_key_purpose,
    "key_id_forgery": scenario_key_id_forgery,
}


def build_lab(
    lab_dir: Path | str,
    *,
    seed: int = DEFAULT_SEED,
    record_count: int = 6,
    scenarios: Sequence[str] | None = None,
) -> tuple[CleanBundle, list[ProvenanceScenario]]:
    """Build the clean baseline and every requested scenario."""
    root = Path(lab_dir)
    root.mkdir(parents=True, exist_ok=True)
    clean = build_clean(root / "_clean", seed=seed, record_count=record_count)

    names = list(scenarios) if scenarios else list(SCENARIOS)
    unknown = [name for name in names if name not in SCENARIOS]
    if unknown:
        raise ProvenanceError(
            f"unknown provenance scenario(s): {', '.join(unknown)}; available: "
            f"{', '.join(sorted(SCENARIOS))}"
        )

    built: list[ProvenanceScenario] = []
    for name in names:
        scenario = SCENARIOS[name](clean, root / name)
        built.append(scenario)
        log.info("provenance scenario %-30s -> %s", name, scenario.out_dir)

    (root / "lab_manifest.json").write_text(
        json.dumps(
            {
                "lab_version": PROVENANCE_LAB_VERSION,
                "seed": seed,
                "record_count": record_count,
                "scenarios": [s.name for s in built],
                "expected_source": expected_from_clean(clean),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return clean, built


__all__ = [
    "PROVENANCE_LAB_VERSION", "DEFAULT_SEED", "SCENARIOS", "CleanBundle",
    "ProvenanceScenario", "build_clean", "build_lab", "expected_from_clean",
    "lab_signing_key", "lab_nonce", "lab_timestamp",
]
