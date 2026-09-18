"""The append-only, cryptographically linked audit log.

This is **not a blockchain**, and ADR-009 records why that was a deliberate
architectural decision rather than an omission: a distributed ledger buys
Byzantine agreement among mutually distrusting writers, and an air-gapped single
analyst authority has one writer, no network to gossip over, and no second party
whose disagreement about ordering needs resolving.  What it needs is
tamper-evidence, and a hash chain provides that with no consensus layer.

Construction
------------
Entry *n* binds ``previous_record_digest = entry_digest(entry n-1)``, where
``entry_digest`` covers the record payload **and** its signature envelope (see
:meth:`cvtrust.provenance.record.SignedRecord.entry_digest`).  Entry 0 binds
``None`` and carries ``sequence_number = 0``.

Two independent mechanisms, and the difference matters
------------------------------------------------------
**Linkage** is cryptographic: altering any entry changes its ``entry_digest``,
so the successor's back-pointer no longer matches, and every subsequent link is
also unverifiable.  Forging past a break requires re-signing every later entry,
which requires the private key.

**Sequence numbers** are semantic: they must start at 0 and increase by exactly
one.  They add nothing to the cryptography, but they turn "link 7 does not
match" into "an entry was deleted between 6 and 8", which is the difference
between an alarm and a diagnosis.

What this detects, precisely
----------------------------
=====================  ==================================================
Modify an entry        **Detected.** Its digest changes; the next link fails.
Delete a middle entry  **Detected.** Link and sequence both break.
Insert an entry        **Detected.** The inserted entry's back-pointer cannot
                       match, and sequence numbers collide or skip.
Reorder entries        **Detected.** Back-pointers follow content, not position.
Duplicate an entry     **Detected.** Sequence repeats; replay DB also fires.
Replace a signature    **Detected.** ``entry_digest`` covers the signature.
=====================  ==================================================

What this does **not** detect without external help
---------------------------------------------------
**Truncation.**  Removing entries from the end of a log leaves a chain that is
internally perfect.  So does deleting the whole log.  No self-contained
structure can detect its own absence — the shortened chain is exactly what a
shorter honest run would have produced.

The offline remedy is an **anchor**: the analyst records the head
``entry_digest`` and the entry count out of band, signed with a key whose
purpose is ``log_anchor``.  Verification against a held anchor detects
truncation, and verification without one reports truncation as
``NOT_DETECTABLE`` — never as clean.  An anchor is only as good as the
independence of where it is kept; an anchor stored inside the log directory
protects against nothing, which is why the CLI writes it to a separate path and
says so.

Front truncation (removing entries from the start) is detected by the genesis
check: a log whose first entry has a non-null back-pointer, or a non-zero
sequence number, is missing its beginning.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..core.evidence import utc_now_iso
from ..core.hashing import sha256_canonical
from .record import GENESIS_SEQUENCE, SignedRecord

CHAIN_SCHEMA_VERSION = "1.0"
ANCHOR_SCHEMA_VERSION = "1.0"


class LinkStatus(str, Enum):
    GENESIS = "GENESIS"
    LINKED = "LINKED"
    BROKEN = "BROKEN"
    #: The entry claims a predecessor but none exists at that position.
    ORPHANED = "ORPHANED"


class ChainStatus(str, Enum):
    INTACT = "INTACT"
    BROKEN = "BROKEN"
    EMPTY = "EMPTY"


class TruncationStatus(str, Enum):
    """Completeness of a log relative to an anchor.

    The vocabulary is deliberately finer than "truncated / not truncated",
    because three of these states call for different actions and lumping them
    together produces false alarms on the most ordinary operation there is:
    appending a record to a log you anchored yesterday.
    """

    #: Head and entry count both match the anchor.
    VERIFIED_COMPLETE = "VERIFIED_COMPLETE"
    #: Entries are missing from the end, or the anchored log is not this one.
    TRUNCATION_DETECTED = "TRUNCATION_DETECTED"
    #: The anchored head is present but *interior*: the log has grown past the
    #: anchor. **Not an attack** -- this is what an appended log looks like, and
    #: reporting it as truncation would make the mechanism unusable. Everything
    #: up to the anchored head is attested; entries after it are outside the
    #: anchor's scope and their removal would be undetectable. Re-anchor.
    ANCHOR_STALE = "ANCHOR_STALE"
    #: The anchored head *is* the current head, but the entry counts disagree:
    #: entries were added or removed before it. Not truncation -- the tail is
    #: where the anchor says it is -- and the chain localises what happened.
    ANCHOR_MISMATCH = "ANCHOR_MISMATCH"
    #: No anchor. Tail truncation is structurally undetectable, and this says so.
    NOT_DETECTABLE = "NOT_DETECTABLE"
    #: The log is missing its beginning, which *is* self-detectable.
    FRONT_TRUNCATION_DETECTED = "FRONT_TRUNCATION_DETECTED"


class LinkResult(BaseModel):
    """The verification of one entry's position in the chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    position: int
    record_id: str
    entry_digest: str
    sequence_number: int
    expected_previous_digest: str | None
    declared_previous_digest: str | None
    link_status: LinkStatus
    sequence_expected: int
    sequence_valid: bool
    detail: str

    @property
    def ok(self) -> bool:
        return (
            self.link_status in (LinkStatus.GENESIS, LinkStatus.LINKED)
            and self.sequence_valid
        )


class LogAnchor(BaseModel):
    """An out-of-band attestation of a log's head.  The truncation remedy.

    Small on purpose: it holds only what is needed to answer "is the log I am
    holding the whole log", so an analyst can keep it somewhere the log's
    producer cannot reach — printed, on separate media, in a different
    enclave.  Its signature, when present, should be made with a key whose
    purpose is ``log_anchor`` rather than the inference signing key; otherwise
    whoever can write records can also mint the attestation that they are
    complete.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = ANCHOR_SCHEMA_VERSION
    log_id: str = Field(min_length=1)
    head_entry_digest: str = Field(min_length=64, max_length=64)
    entry_count: int = Field(ge=0)
    head_sequence_number: int = Field(ge=0)
    anchored_at: str = Field(default_factory=utc_now_iso)
    note: str | None = None

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def digest(self) -> str:
        return sha256_canonical(self.canonical_payload())


class SignedAnchor(BaseModel):
    """An anchor with a detached signature, for an anchor kept on shared media."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    anchor: LogAnchor
    signature: dict[str, Any] | None = None


class ChainVerification(BaseModel):
    """The structured result of verifying a chain."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = CHAIN_SCHEMA_VERSION
    log_id: str | None
    status: ChainStatus
    entry_count: int
    head_entry_digest: str | None
    links: tuple[LinkResult, ...]
    first_break_position: int | None
    truncation_status: TruncationStatus
    truncation_detail: str
    anchor_supplied: bool
    mixed_log_ids: tuple[str, ...] = ()
    detail: str = ""

    @property
    def intact(self) -> bool:
        return self.status is ChainStatus.INTACT

    def broken_positions(self) -> tuple[int, ...]:
        return tuple(link.position for link in self.links if not link.ok)

    def anchor_is_satisfied(self) -> bool:
        """Does the anchor raise no objection?

        ``ANCHOR_STALE`` counts as satisfied: a log that has grown past its
        anchor is the ordinary result of appending to it, and everything the
        anchor covers is intact. What it does *not* mean is that the newer
        entries are attested, which is why the status is reported rather than
        being collapsed into VERIFIED_COMPLETE.
        """
        return self.truncation_status in (
            TruncationStatus.VERIFIED_COMPLETE,
            TruncationStatus.ANCHOR_STALE,
        )

    def guarantees(self) -> dict[str, str]:
        """What this result does and does not establish.  Printed in the report.

        A verification that reports only a boolean invites the reader to supply
        their own idea of what it covered, and that idea is always broader than
        the truth.
        """
        return {
            "modification": "DETECTED — an altered entry changes its digest and "
            "breaks the following link",
            "deletion": "DETECTED — link and sequence both break at the gap",
            "insertion": "DETECTED — an inserted entry cannot carry a matching "
            "back-pointer",
            "reordering": "DETECTED — back-pointers follow content, not position",
            "duplication": "DETECTED — the sequence number repeats",
            "signature_substitution": "DETECTED — the chained digest covers the "
            "signature envelope, not only the payload",
            "front_truncation": "DETECTED — genesis must have a null back-pointer "
            "and sequence 0",
            "tail_truncation": (
                "DETECTED against the supplied anchor"
                if self.anchor_supplied
                else "NOT DETECTABLE — no anchor was supplied. A truncated chain "
                "is internally perfect; detecting it needs a head digest held "
                "outside the log"
            ),
            "authenticity": "NOT ESTABLISHED HERE — the chain shows the log has "
            "not been restructured. Whether each entry was signed by a trusted "
            "key is a separate check",
        }


def entry_digests(entries: Sequence[SignedRecord]) -> list[str]:
    return [entry.entry_digest() for entry in entries]


def verify_chain(
    entries: Sequence[SignedRecord],
    *,
    anchor: LogAnchor | None = None,
) -> ChainVerification:
    """Verify linkage, sequence and (given an anchor) completeness.

    Every entry is checked.  Verification does not stop at the first break,
    because the position of the *second* break is what distinguishes a single
    edited record from a wholesale rewrite, and an analyst needs both.
    """
    if not entries:
        return ChainVerification(
            log_id=None,
            status=ChainStatus.EMPTY,
            entry_count=0,
            head_entry_digest=None,
            links=(),
            first_break_position=None,
            truncation_status=(
                TruncationStatus.TRUNCATION_DETECTED
                if anchor is not None and anchor.entry_count > 0
                else TruncationStatus.NOT_DETECTABLE
            ),
            truncation_detail=(
                f"the log is empty but the anchor attests {anchor.entry_count} "
                "entry(ies): the log has been removed or replaced"
                if anchor is not None and anchor.entry_count > 0
                else "the log is empty and no anchor was supplied; an empty log "
                "and a deleted log are indistinguishable without one"
            ),
            anchor_supplied=anchor is not None,
            detail="no entries",
        )

    digests = entry_digests(entries)
    log_ids = sorted({entry.record.sequence.log_id for entry in entries})
    links: list[LinkResult] = []
    first_break: int | None = None

    for position, entry in enumerate(entries):
        record = entry.record
        declared = record.sequence.previous_record_digest
        expected = digests[position - 1] if position > 0 else None
        sequence_expected = GENESIS_SEQUENCE + position
        sequence_valid = record.sequence.sequence_number == sequence_expected

        if position == 0:
            if declared is None:
                status = LinkStatus.GENESIS
                detail = "genesis entry: no predecessor, as required"
            else:
                status = LinkStatus.ORPHANED
                detail = (
                    "the first entry declares a predecessor that is not in this "
                    "log: entries are missing from the front, or this is a "
                    "fragment of a longer log"
                )
        elif declared is None:
            status = LinkStatus.BROKEN
            detail = (
                "a non-genesis entry declares no predecessor, so it is not "
                "linked to anything before it"
            )
        elif declared == expected:
            status = LinkStatus.LINKED
            detail = "back-pointer matches the preceding entry's digest"
        else:
            status = LinkStatus.BROKEN
            detail = (
                f"back-pointer {declared[:16]}… does not match the preceding "
                f"entry's digest {(expected or '')[:16]}…: the preceding entry was "
                "modified, or an entry was inserted, deleted or reordered here"
            )

        if not sequence_valid:
            detail += (
                f"; sequence number is {record.sequence.sequence_number} where "
                f"{sequence_expected} was expected"
            )

        link = LinkResult(
            position=position,
            record_id=record.record_id,
            entry_digest=digests[position],
            sequence_number=record.sequence.sequence_number,
            expected_previous_digest=expected,
            declared_previous_digest=declared,
            link_status=status,
            sequence_expected=sequence_expected,
            sequence_valid=sequence_valid,
            detail=detail,
        )
        links.append(link)
        if not link.ok and first_break is None:
            first_break = position

    head_digest = digests[-1]
    front_truncated = links[0].link_status is LinkStatus.ORPHANED or (
        links[0].sequence_number != GENESIS_SEQUENCE
    )

    truncation_status, truncation_detail = _assess_truncation(
        entries=entries,
        digests=digests,
        anchor=anchor,
        front_truncated=front_truncated,
    )

    intact = all(link.ok for link in links)
    return ChainVerification(
        log_id=log_ids[0] if len(log_ids) == 1 else None,
        status=ChainStatus.INTACT if intact else ChainStatus.BROKEN,
        entry_count=len(entries),
        head_entry_digest=head_digest,
        links=tuple(links),
        first_break_position=first_break,
        truncation_status=truncation_status,
        truncation_detail=truncation_detail,
        anchor_supplied=anchor is not None,
        mixed_log_ids=tuple(log_ids) if len(log_ids) > 1 else (),
        detail=(
            "every entry links to its predecessor and sequence numbers are "
            "contiguous from genesis"
            if intact
            else f"chain integrity fails from position {first_break}"
        ),
    )


def _assess_truncation(
    *,
    entries: Sequence[SignedRecord],
    digests: Sequence[str],
    anchor: LogAnchor | None,
    front_truncated: bool,
) -> tuple[TruncationStatus, str]:
    if front_truncated:
        return (
            TruncationStatus.FRONT_TRUNCATION_DETECTED,
            "the log does not begin at genesis: its first entry either declares "
            "a predecessor or carries a non-zero sequence number, so entries "
            "have been removed from the front",
        )
    if anchor is None:
        return (
            TruncationStatus.NOT_DETECTABLE,
            "no anchor was supplied. A chain truncated at the end is internally "
            "perfect and cannot be distinguished from a shorter honest log; "
            "detecting it requires a head digest recorded out of band",
        )

    head = digests[-1]
    if anchor.head_entry_digest == head and anchor.entry_count == len(entries):
        return (
            TruncationStatus.VERIFIED_COMPLETE,
            f"the log head matches the anchor taken at {anchor.anchored_at} and "
            f"the entry count agrees ({len(entries)})",
        )
    if anchor.head_entry_digest in set(digests):
        position = list(digests).index(anchor.head_entry_digest)
        if position < len(entries) - 1:
            return (
                TruncationStatus.ANCHOR_STALE,
                f"the anchored head is at position {position} of {len(entries)} "
                f"entries, so the log has grown past this anchor. Nothing has "
                f"been truncated: entries 0-{position} are attested complete, and "
                f"the {len(entries) - 1 - position} entry(ies) after them are "
                "outside this anchor's scope, so their removal would not be "
                "detectable. Take a fresh anchor",
            )
        return (
            TruncationStatus.ANCHOR_MISMATCH,
            "the anchored head is the current head, so the log ends where the "
            f"anchor says, but the entry counts disagree ({anchor.entry_count} "
            f"anchored, {len(entries)} present): entries were "
            + ("removed" if len(entries) < anchor.entry_count else "inserted")
            + " before the head. The chain result localises where",
        )
    if len(entries) < anchor.entry_count:
        return (
            TruncationStatus.TRUNCATION_DETECTED,
            f"the anchor attests {anchor.entry_count} entry(ies) and only "
            f"{len(entries)} are present: entries have been removed from the end",
        )
    return (
        TruncationStatus.TRUNCATION_DETECTED,
        f"the anchored head digest {anchor.head_entry_digest[:16]}… appears "
        "nowhere in this log: the log is not the one that was anchored",
    )


def build_anchor(
    entries: Sequence[SignedRecord], *, note: str | None = None
) -> LogAnchor:
    """Take an anchor over a log's current head.

    The anchor is only worth something if it is stored where the log's producer
    cannot reach it; this function does not and cannot enforce that, so the CLI
    writes it to an explicitly separate path and the documentation says why.
    """
    if not entries:
        raise ValueError("cannot anchor an empty log")
    head = entries[-1]
    return LogAnchor(
        log_id=head.record.sequence.log_id,
        head_entry_digest=head.entry_digest(),
        entry_count=len(entries),
        head_sequence_number=head.record.sequence.sequence_number,
        note=note,
    )


__all__ = [
    "CHAIN_SCHEMA_VERSION", "LinkStatus", "ChainStatus", "TruncationStatus",
    "LinkResult", "LogAnchor", "SignedAnchor", "ChainVerification",
    "verify_chain", "build_anchor", "entry_digests",
]
