"""Module 3 — inference provenance and cryptographic integrity.

What this module establishes, and what it deliberately does not
---------------------------------------------------------------
It establishes the **cryptographic relationship** between an input, a model, a
preprocessing configuration, an inference configuration, an output, execution
metadata, a position in a sequence, and a signing key.  When that relationship
holds, nobody altered the account of the inference.  When it breaks, the break
is a deterministic fact with a named cause.

It says nothing about whether the model is sound, whether the input was
in-distribution, or whether the output is correct.  Those are Modules 1, 2 and 4,
and this module never mixes its verdicts with theirs.  A cryptographically
perfect record of a backdoored model is entirely possible, as is an invalid
record of a clean one, and the assurance system has to be able to say both.

Layout
------
``output``     canonical inference-output representation and its digest
``binding``    input, model, configuration and output bindings
``record``     the signed record schema (1.0), its two digests, the envelope
``keys``       offline Ed25519 key generation, storage and fingerprints
``trust``      the local trust store, rotation, revocation, validity policy
``signing``    sign and verify, with the three failure modes kept apart
``replay``     the replay database and what it can and cannot detect
``chain``      the append-only hash-linked log and the anchor that bounds it
``log``        the JSONL store and its deliberately tolerant loader
``verify``     record verification: structured evidence, never a boolean
``findings``   deterministic verification facts as Module 1 ``Finding`` objects
"""

from .binding import (
    ConfigBinding,
    ExecutionMetadata,
    InputBinding,
    ModelBinding,
    OutputBinding,
    bind_config,
    bind_input,
    bind_input_bytes,
    bind_model_manifest,
    bind_output,
    normalized_tensor_digest,
)
from .chain import (
    ChainStatus,
    ChainVerification,
    LinkStatus,
    LogAnchor,
    TruncationStatus,
    build_anchor,
    verify_chain,
)
from .keys import (
    KeyPair,
    export_public_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_fingerprint,
    read_public_key_file,
)
from .log import MalformedEntry, ProvenanceLog
from .output import (
    CanonicalOutput,
    OutputTask,
    classification_output,
    detection_output,
    embedding_output,
    keypoint_output,
    mask_digest,
    raw_output,
    segmentation_output,
)
from .record import (
    PROVENANCE_SCHEMA_VERSION,
    SUPPORTED_SCHEMA_VERSIONS,
    ProvenanceRecord,
    SequenceBinding,
    SignatureEnvelope,
    SignedRecord,
    create_provenance_record,
    new_nonce,
)
from .replay import (
    ReplayDatabase,
    ReplayResult,
    ReplayVerdict,
    detect_replay,
)
from .signing import SignatureCheck, SignatureOutcome, sign_record, verify_signature
from .trust import (
    KeyPurpose,
    KeyStatus,
    TrustedKey,
    TrustStore,
    ValidityPolicy,
    revoke_key,
    trust_key,
    untrust_key,
)
from .verify import (
    CheckOutcome,
    ExpectedBinding,
    FailureCode,
    RecordVerification,
    VerificationCheck,
    verify_record,
)

__all__ = [
    "PROVENANCE_SCHEMA_VERSION", "SUPPORTED_SCHEMA_VERSIONS",
    # record
    "ProvenanceRecord", "SignedRecord", "SignatureEnvelope", "SequenceBinding",
    "create_provenance_record", "new_nonce",
    # bindings
    "InputBinding", "ModelBinding", "ConfigBinding", "OutputBinding",
    "ExecutionMetadata", "bind_input", "bind_input_bytes", "bind_config",
    "bind_output", "bind_model_manifest", "normalized_tensor_digest",
    # output
    "CanonicalOutput", "OutputTask", "classification_output", "detection_output",
    "segmentation_output", "keypoint_output", "embedding_output", "raw_output",
    "mask_digest",
    # keys and trust
    "KeyPair", "generate_keypair", "load_private_key", "load_public_key",
    "public_key_fingerprint", "export_public_key", "read_public_key_file",
    "TrustStore", "TrustedKey", "KeyStatus", "KeyPurpose", "ValidityPolicy",
    "trust_key", "revoke_key", "untrust_key",
    # signing
    "sign_record", "verify_signature", "SignatureCheck", "SignatureOutcome",
    # verification
    "verify_record", "RecordVerification", "VerificationCheck", "CheckOutcome",
    "FailureCode", "ExpectedBinding",
    # chain
    "verify_chain", "ChainVerification", "ChainStatus", "LinkStatus",
    "TruncationStatus", "LogAnchor", "build_anchor",
    # replay
    "ReplayDatabase", "ReplayResult", "ReplayVerdict", "detect_replay",
    # log
    "ProvenanceLog", "MalformedEntry",
]
