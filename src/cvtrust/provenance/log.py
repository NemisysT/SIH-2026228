"""The on-disk provenance log, and the writer that appends to it.

Format: JSON Lines.  One signed record per line, canonical JSON, newline
terminated.  Chosen over a single JSON array for one reason that matters here:
appending to a JSONL file is a single ``write`` of new bytes and never rewrites
what is already on disk, so a crash mid-append truncates the tail rather than
corrupting the history.  A truncated tail is exactly the failure the anchor
mechanism is designed to surface (see :mod:`cvtrust.provenance.chain`).

Reading is deliberately tolerant in a narrow way: a line that is not valid JSON,
or that does not validate against the schema, does **not** abort the load.  It
becomes a :class:`MalformedEntry` holding the raw line and the parse error, is
counted, and is reported as ``MALFORMED_RECORD``.  Aborting would mean one bad
line hides every finding in the rest of the log, which is a denial of
verification an adversary could trigger with a single byte.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.canonical import canonical_json
from ..core.errors import ProvenanceError
from ..core.logging import get_logger
from .record import GENESIS_SEQUENCE, ProvenanceRecord, SignedRecord
from .signing import sign_record

log = get_logger("provenance.log")

LOG_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class MalformedEntry:
    """A line that could not be parsed into a record.

    Kept rather than dropped: "line 4 of this log is not a record" is a finding,
    and a loader that silently skipped it would turn a tampered log into a
    shorter clean one.
    """

    line_number: int
    raw: str
    error: str


@dataclass
class ProvenanceLog:
    """An ordered sequence of signed records, plus whatever would not parse."""

    log_id: str
    entries: list[SignedRecord] = field(default_factory=list)
    malformed: list[MalformedEntry] = field(default_factory=list)
    path: Path | None = None

    # -- construction ------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str, *, log_id: str | None = None) -> "ProvenanceLog":
        file_path = Path(path)
        if not file_path.is_file():
            raise ProvenanceError(f"provenance log not found: {file_path}")
        entries: list[SignedRecord] = []
        malformed: list[MalformedEntry] = []
        for line_number, line in enumerate(
            file_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                malformed.append(
                    MalformedEntry(line_number, line[:2000], f"not valid JSON: {exc}")
                )
                continue
            try:
                entries.append(SignedRecord.model_validate(payload))
            except Exception as exc:
                malformed.append(
                    MalformedEntry(
                        line_number,
                        line[:2000],
                        f"does not validate against provenance schema "
                        f"{'1.0'}: {_first_error(exc)}",
                    )
                )
        resolved = log_id or (
            entries[0].record.sequence.log_id if entries else file_path.stem
        )
        return cls(log_id=resolved, entries=entries, malformed=malformed, path=file_path)

    @classmethod
    def new(cls, log_id: str, path: Path | str | None = None) -> "ProvenanceLog":
        return cls(log_id=log_id, path=Path(path) if path else None)

    # -- state -------------------------------------------------------------

    @property
    def head(self) -> SignedRecord | None:
        return self.entries[-1] if self.entries else None

    def head_digest(self) -> str | None:
        head = self.head
        return head.entry_digest() if head else None

    def next_sequence(self) -> int:
        return (
            self.entries[-1].record.sequence.sequence_number + 1
            if self.entries
            else GENESIS_SEQUENCE
        )

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[SignedRecord]:
        return iter(self.entries)

    def records(self) -> list[ProvenanceRecord]:
        return [entry.record for entry in self.entries]

    # -- append ------------------------------------------------------------

    def append(self, entry: SignedRecord) -> "ProvenanceLog":
        """Append an already-built entry, checking it belongs where it claims.

        The checks here are *constructor-side* sanity, not verification: they
        stop this process from writing a log that is broken on its own terms.
        They are no substitute for :func:`cvtrust.provenance.chain.verify_chain`,
        which is what runs against a log this process did not write.
        """
        expected_sequence = self.next_sequence()
        if entry.record.sequence.sequence_number != expected_sequence:
            raise ProvenanceError(
                f"cannot append: record claims sequence "
                f"{entry.record.sequence.sequence_number}, this log's next is "
                f"{expected_sequence}"
            )
        expected_previous = self.head_digest()
        if entry.record.sequence.previous_record_digest != expected_previous:
            raise ProvenanceError(
                "cannot append: record's previous_record_digest does not match "
                "this log's head"
            )
        if entry.record.sequence.log_id != self.log_id:
            raise ProvenanceError(
                f"cannot append: record belongs to log "
                f"{entry.record.sequence.log_id!r}, not {self.log_id!r}"
            )
        self.entries.append(entry)
        return self

    def append_signed(
        self,
        record_factory: Any,
        private_key: Ed25519PrivateKey,
        **kwargs: Any,
    ) -> SignedRecord:
        """Build the next record via ``record_factory``, sign it, append it.

        ``record_factory`` receives ``sequence_number`` and
        ``previous_record_digest`` so the caller never has to compute the chain
        position itself — which is the one place an honest producer would
        otherwise get the chain wrong.
        """
        record = record_factory(
            sequence_number=self.next_sequence(),
            previous_record_digest=self.head_digest(),
            **kwargs,
        )
        entry = sign_record(record, private_key)
        self.append(entry)
        return entry

    # -- persistence -------------------------------------------------------

    def serialise(self) -> str:
        return "".join(
            canonical_json(entry.entry_payload()).decode("utf-8") + "\n"
            for entry in self.entries
        )

    def save(self, path: Path | str | None = None) -> Path:
        target = Path(path) if path else self.path
        if target is None:
            raise ProvenanceError("no path supplied and this log has none")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.serialise(), encoding="utf-8")
        self.path = target
        return target

    def append_to_file(self, entry: SignedRecord, path: Path | str | None = None) -> Path:
        """Append one entry's bytes to the file without rewriting the rest."""
        target = Path(path) if path else self.path
        if target is None:
            raise ProvenanceError("no path supplied and this log has none")
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(canonical_json(entry.entry_payload()).decode("utf-8") + "\n")
        self.path = target
        return target

    def stats(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "entries": len(self.entries),
            "malformed_lines": len(self.malformed),
            "head_entry_digest": self.head_digest(),
            "head_sequence": (
                self.entries[-1].record.sequence.sequence_number if self.entries else None
            ),
            "signed_entries": sum(1 for e in self.entries if e.is_signed()),
            "bytes_on_disk": (
                self.path.stat().st_size if self.path and self.path.is_file() else None
            ),
        }


def load_entries(paths: Sequence[Path | str]) -> ProvenanceLog:
    """Load and concatenate several log files in the order given.

    Used by the attack lab, where a scenario may split a log across files. The
    chain verifier sees the concatenation, which is the point: splicing two logs
    together is one of the things it has to detect.
    """
    combined: list[SignedRecord] = []
    malformed: list[MalformedEntry] = []
    log_id: str | None = None
    for path in paths:
        part = ProvenanceLog.load(path)
        combined.extend(part.entries)
        malformed.extend(part.malformed)
        log_id = log_id or part.log_id
    return ProvenanceLog(log_id=log_id or "unknown", entries=combined, malformed=malformed)


def _first_error(exc: Exception) -> str:
    """Condense a pydantic ValidationError into one readable clause."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            items = errors()
        except Exception:  # pragma: no cover - defensive
            return str(exc)[:300]
        if items:
            first = items[0]
            location = ".".join(str(p) for p in first.get("loc", ()))
            return f"{location or '<root>'}: {first.get('msg', 'invalid')}"
    return str(exc)[:300]


__all__ = [
    "LOG_SCHEMA_VERSION", "MalformedEntry", "ProvenanceLog", "load_entries",
]
