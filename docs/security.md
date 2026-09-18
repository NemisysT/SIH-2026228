# Security design

## Cryptographic policy

| Rule | Where enforced |
|---|---|
| SHA-256 is the only digest used for identity or integrity | `core/hashing.py`; `HASH_ALGORITHM` recorded in every manifest |
| **MD5 and SHA-1 appear nowhere**, including for "convenience" keys | A convenience key becomes an identity eventually; there are none to promote |
| No invented cryptography | Only `hashlib` and (from Module 3) `cryptography`'s Ed25519 |
| Canonical serialisation before hashing | `core/canonical.py` |
| Digest-bearing structures are float-free | `canonical_json` raises on `float` by default (ADR-004) |
| Truncated digests are labels, never proofs | `short()` is used for display and finding IDs only; every integrity comparison uses the full 64 hex characters |
| A path is never an identity | Contributor attribution precedence is explicit and recorded; path-pattern attribution is opt-in and off by default |
| Untrusted timestamps are never trusted silently | Module 1 records no contributor-supplied time as authoritative; `observed_at` is the analyst machine's own clock, and is excluded from every digest |

## Canonical serialisation

Anything hashed — and, from Module 3, signed — must have exactly one byte
representation on every machine and Python version. `canonical_json` guarantees:

- UTF-8, no BOM, no escaping of non-ASCII
- object keys sorted by Unicode code point
- no insignificant whitespace (`,` / `:` separators)
- `NaN` / `Infinity` always rejected
- integers outside the IEEE-754 safe range rejected
- only `dict` / `list` / `tuple` / `str` / `int` / `bool` / `None` accepted —
  anything else is an error rather than a silent `str()`

**Floats are rejected on the digest path.** RFC 8785 number canonicalisation is
implementable but subtle, and every subtlety becomes a signature-verification
bug once Module 3 signs these structures. Configuration and reports, which
legitimately contain thresholds and scores, are hashed through `digest_safe()`,
which rewrites floats as fixed-unit integers. Sixteen tests in
`tests/unit/test_canonical.py` pin this behaviour.

## Two digests per image, and why

| Digest | Answers | Defeated by |
|---|---|---|
| `file_sha256` — over bytes on disk | "Is this the same *artifact*?" | any re-encode, metadata strip, container change |
| `pixel_sha256` — over decoded RGB pixels, with shape/dtype/mode bound in | "Is this the same *content*?" | any pixel change |

An adversary who knows only byte hashing is used will re-encode. The file digest
then reports nothing while the training set is just as skewed. Content digests
close that gap deterministically, with no threshold to argue about. Tested with
an explicit evasion attempt.

## Input handling

The dataset root is untrusted input and is treated as such:

- **Path traversal.** A COCO `file_name` that escapes the dataset root is kept
  verbatim rather than resolved, so it surfaces as a `missing_image_file`
  finding. The adapter never follows it. Tested.
- **Decompression bombs.** Pillow's guard is retained with a raised ceiling;
  a `DecompressionBombError` becomes an `unreadable_image` finding.
- **Truncated and corrupt images.** Full decode is forced (`Image.open` is lazy
  and a truncated file only fails on decode). Failure becomes a finding, and the
  file digest is still recorded — we know exactly which bytes failed.
- **Malformed annotations.** Never raise; they become `IngestIssue` values,
  because a malformed annotation is itself a supported threat and must reach the
  analyst as evidence.
- **Unbounded work.** Above `near_duplicate.max_pairwise_samples` the
  near-duplicate detector **refuses and reports `NOT_ASSESSED`** rather than
  silently subsampling. A partial scan reported as a full one is the quiet
  coverage gap this system exists to prevent.
- **Unknown configuration keys are rejected** (`extra="forbid"`). A
  silently-ignored threshold is a threshold the analyst believes is active.

## The air gap

| Property | Status |
|---|---|
| Network access at runtime | **None.** No HTTP client is imported by any runtime path. |
| Cloud inference / external API | None. No OpenAI, Anthropic, or any hosted service. |
| Pretrained weight downloads | **None.** The default feature space needs no weights. The optional CNN backend requires a locally vendored file, records its SHA-256 in the report, and raises `DetectorUnavailable` with a message that explicitly states weights are never downloaded. Tested. |
| Remote database | None. No database at all; artifacts are files. |
| Authentication service | None. |
| Telemetry | None. |

Installation requires a package index. Runtime does not. See
`docs/deployment.md`.

## Conservative-by-default policy decisions

Each of these makes the tool *less* likely to act, on purpose:

1. **Uncalibrated evidence cannot quarantine.** Rule
   `D-110-severe-but-uncalibrated` downgrades to `REVIEW`. Quarantine is
   expensive and reversing it costs credibility.
2. **An unassessed class never drives an irreversible action.** Rule
   `D-000-not-assessed` returns `REVIEW`, not `QUARANTINE` — an open question is
   neither a clean result nor grounds for action.
3. **Calibrated confidence is a lower bound**, not a point estimate (Wilson 95%).
4. **Statistical confidence is capped at 0.99.** A p-value of 1e-40 means the
   null model is wrong, which is not the same claim as certainty.
5. **OOD severity is capped at MEDIUM.** "Different from the reference" is never,
   on that evidence alone, a high-severity security claim.
6. **Contributor severity never exceeds the worst underlying sample severity.**
   Aggregation concentrates evidence; it does not manufacture a worse threat.
7. **Contributor confidence is the minimum** of the statistical confidence and
   the mean confidence of its children, so multiplicity cannot launder weak
   evidence into a confident verdict. Tested.
8. **Overall assessment is a worst-case roll-up, never an average.** One
   confident HIGH finding among a thousand clean samples is the case that
   matters, and any mean would bury it.

## Known security limitations

- Until Module 3, manifests are unsigned. A manifest stored *alongside* the
  dataset could be replaced wholesale by an adversary with write access —
  manifest self-tampering is detected, but wholesale replacement with a
  self-consistent forgery is not. **Store baseline manifests separately from the
  dataset.**
- Contributor attribution rests on untrusted metadata (see
  `docs/threat-model.md` §4).
- The tool trusts its own configuration file. Protect it with filesystem
  permissions.
- No sandboxing of image decoding. A Pillow/libjpeg vulnerability would be
  reachable from a malicious image. Mitigation for a hostile deployment: run
  scans as an unprivileged user in a container or VM with no network.
