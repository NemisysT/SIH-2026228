# Cryptographic model

What this system uses, why, and — the part that matters more — what each
primitive does and does not buy.

## 1. Primitives

| Primitive | Where | Why this one |
|---|---|---|
| **SHA-256** | Every identity and integrity decision, Modules 1–3 | The only digest in the codebase. MD5 and SHA-1 appear nowhere, including as "convenience" keys, because a convenience key becomes an identity eventually |
| **Ed25519** (RFC 8032) | Provenance record signatures | Deterministic signatures, fixed 64-byte output, 32-byte public key, no parameter choices to get wrong, constant-time reference implementation in a library already vendored |
| **PKCS#8 + PBKDF2/AES** | Private keys at rest | `cryptography`'s `BestAvailableEncryption`; not our choice to make and not ours to implement |
| **`secrets` / OS CSPRNG** | Nonces | `getrandom(2)` / `/dev/urandom`. No network, no seeding, no userspace PRNG to get wrong |
| **Canonical JSON** | Everything that is hashed or signed | RFC 8785's key-ordering, whitespace and UTF-8 rules, deliberately diverging on numbers (§3) |

**Nothing is invented.** The only cryptographic code in this repository is calls
into `hashlib`, `secrets` and `cryptography`. A test asserts that no other crypto
library is imported anywhere under `provenance/`, and that no certificate,
key-server, OCSP, CRL or RFC 3161 timestamp API appears in the shipped source.

### Why Ed25519 and not the alternatives

**Not ECDSA.** ECDSA needs a fresh random nonce per signature, and reuse or bias
in that nonce leaks the private key outright — a failure mode that has taken
real keys in the field. Ed25519's signatures are deterministic, so there is no
such nonce. The same property gives a second, practical benefit: two
independently produced logs over the same inputs are byte-identical down to the
signature, which is what lets the attack lab be *regenerated and diffed* rather
than merely re-run.

**Not RSA.** A 3072-bit RSA signature is 384 bytes against Ed25519's 64, and its
public key is 400+ bytes against 32. At one signature per inference that is a
sixfold increase in log size for no security gain at this level.

**Not a MAC.** An HMAC would authenticate a record to anyone who can *verify* it
— which means anyone who can verify it can also forge it. Non-repudiation
requires asymmetry.

**Not a Merkle tree, yet.** ADR-009 listed one as a possible addition "if
justified by volume". It is not, and it has not been added. A Merkle tree buys
efficient *inclusion proofs* — proving one record is in a log without shipping
the log — which matters when a verifier holds a root and a prover holds the
data. In this deployment the analyst holds the whole log and verifies it in 8.8
ms per 200 entries. Adding a tree would add code and a second set of invariants
to get wrong, in exchange for solving a problem nobody has. If a deployment ever
needs to prove membership to a party that does not hold the log, that is the
point to add it.

## 2. Hash usage

| Digest | Over | Answers |
|---|---|---|
| `file_sha256` (M1) | Image bytes on disk | Is this the same artifact? |
| `pixel_sha256` (M1) | Decoded pixels + shape + mode | Is this the same content? |
| `file_sha256` (M2) | Model bytes | Is this the same artifact? |
| `graph_digest` (M2) | Topology, shapes, dtypes — not weights | Is this the same architecture? |
| `parameter_digest` (M2) | Quantised weight values | Are these the same weights? |
| `raw_input_digest` (M3) | Input bytes | Which artifact was fed in? |
| `normalized_input_digest` (M3) | Quantised preprocessed tensor + shape | Which tensor reached the model? |
| `output_digest` (M3) | Canonical output bytes | What did it produce? |
| `preprocessing` / `inference` digest (M3) | Canonical configuration | Under what settings? |
| `record_digest` (M3) | Record payload minus its id | Which record is this? |
| `entry_digest` (M3) | Payload **and** signature | What does the chain link? |
| `key_id` (M3) | Raw 32-byte public key | Which key? |

Truncated digests (`short()`) are labels and appear only in identifiers and
display. **Every integrity comparison uses all 64 hex characters.**

## 3. Canonicalisation, and the float decision

Anything hashed or signed must have exactly one byte representation on every
machine and Python version. `core/canonical.py` guarantees UTF-8 without BOM,
keys sorted by Unicode code point, no insignificant whitespace, `NaN`/`Infinity`
rejected, integers confined to the IEEE-754 safe range, and only
`dict`/`list`/`tuple`/`str`/`int`/`bool`/`None` accepted — anything else is an
error rather than a silent `str()`.

**Floats are rejected on the digest path** (ADR-004). RFC 8785 specifies number
canonicalisation via ECMAScript `Number::toString`, which is implementable but
subtle, and Module 3 signs these structures — every subtlety would have become a
signature-verification bug. Real-valued quantities are quantised onto a fixed
decimal grid and carried as integers, with the number of places recorded inside
the signed structure so the grid is part of what was signed.

The cost is stated: two scores closer together than 10⁻⁶ are indistinguishable
to the digest. That is far finer than any meaningful difference in a confidence
value and far coarser than float32 epsilon, and it is asserted as a test rather
than left as a claim.

## 4. What a signature establishes

A valid Ed25519 signature over a record's canonical bytes establishes:

> the holder of the private key matching **the public key in this envelope**
> produced exactly these bytes.

It establishes nothing else. In particular it does **not** establish that the
key is authorised, because the public key travels inside the record and anyone
can generate a keypair. That is a deliberate trade (see
[`provenance.md`](provenance.md) §5): carrying the key is what lets a verifier
distinguish *invalid signature* from *valid signature by an unknown key*, and
the price is that validity without authority means nothing at all.

Authority comes from the trust store, which is an administrative record of
operator decisions, and from nowhere else.

## 5. Private-key handling — the host-trust assumption

**This software cannot protect a private key from a compromised host.** It is a
Python process reading a file. An adversary with code execution as the signing
user can read that file, or simply call this module and ask it to sign. No
amount of file permissions or passphrase handling changes that, and pretending
otherwise would be the most dangerous claim in this document.

What is actually provided:

| | Operational | Development / demo |
|---|---|---|
| Storage | PKCS#8 PEM, `BestAvailableEncryption` with an operator passphrase | Unencrypted PKCS#8 PEM |
| Opt-in | Default | **Required**: `generate_keypair(..., allow_unencrypted=True)`, or `--allow-unencrypted` on the CLI |
| Permissions | `0600`, created with `os.open` at that mode rather than chmod-ed after — the window between write and chmod is enough | Same |
| Recorded | `private_key_encrypted` on the public half, so a reviewer can see which kind of key signed a log | Same |
| Warning | A key loaded with group- or world-readable permissions logs a warning | Same |

The refusal to write an unencrypted key without an explicit flag is the point of
the design: an unencrypted operational key should be a decision someone made,
not a default they inherited. It mirrors Module 2's
`allow_unsafe_deserialisation`.

**What is deliberately absent**: key escrow, key derivation from passwords,
hardware token integration, and any form of remote key management. The first
three are real features a production deployment would want; none is implemented
and none is claimed. An HSM or a smartcard is the correct answer to the
host-trust problem above, and integrating one is a deployment decision this
build does not pre-empt.

### The lab's seed-derived keys

The attack lab derives its signing keys from a published seed so the lab is
byte-reproducible. A key derived from a published seed is a key every reader of
the source already has. The function is named to make that obvious, it is
confined to `attack_lab/provenance_attacks.py`, and a test in
`tests/security/test_offline.py` asserts that `from_private_bytes` appears in no
other shipped module.

## 6. Offline guarantees

Everything runs air-gapped. There is no:

- certificate authority, certificate chain, or certificate download
- OCSP responder or CRL fetch
- key server or key directory
- remote timestamp authority (RFC 3161)
- online verification service
- blockchain network, consensus protocol or peer discovery
- telemetry of any kind

Asserted two independent ways, as in Modules 1 and 2: **dynamically**, by
running key generation, signing, verification, chain verification, replay
detection and the whole lab with `socket.socket` replaced by something that
raises; and **statically**, by scanning the shipped source for network imports,
for weight-download APIs, for URL literals, and — added for Module 3 — for
certificate, key-server, OCSP, CRL and timestamp-authority APIs.

## 7. Threats the cryptography does not address

| Threat | Why cryptography does not help |
|---|---|
| A compromised signing host | It can sign anything it likes, correctly |
| A producer signing a record for an inference it never ran | The record would be perfectly valid. Detecting this needs trusted execution |
| A trust store populated from the same channel as the records | The signatures would verify against keys the adversary chose |
| Tail truncation without an anchor | A truncated chain is internally perfect |
| A rolled-back replay database | Every record becomes first-seen again |
| A wrong-but-well-formed model | Cryptography binds identity, not quality — that is Module 2's job |
| SHA-256 collision or Ed25519 forgery | Assumed hard. If either falls, every claim here falls with it |

The last row is the standing assumption; the others are the interesting ones,
and each has a named mitigation or a named gap in
[`threat-model.md`](threat-model.md) §7.
