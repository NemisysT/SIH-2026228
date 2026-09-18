"""Replay detection, and an explicit statement of what it cannot do.

The claim this module refuses to make
-------------------------------------
A valid signature does **not** establish that an inference happened exactly
once.  A signed record is a static artifact: anyone who can read one can present
it again, and it will verify again, because verifying is all a signature does.
Detecting a second presentation requires *memory* — a record of what has already
been seen — and memory is state the verifier must keep and protect.

Three detectable conditions, kept separate
------------------------------------------
``REPLAY_EXACT``
    The same ``entry_digest`` has been observed before.  Byte-identical signed
    record, presented twice.  Deterministic given the database.

``NONCE_REUSE``
    A *different* record reuses a nonce this database has already seen from the
    same signing key.  A well-behaved producer draws a fresh 128-bit nonce per
    record, so reuse is either a broken producer or a forger splicing fields out
    of an old record into a new one.

``SEQUENCE_COLLISION``
    A different record claims a ``(log_id, sequence_number)`` slot the database
    has already recorded.  This is a forked log: two distinct records asserting
    the same position.

And one condition that is deliberately **not** replay
-----------------------------------------------------
``DUPLICATE_SUBJECT``: the same input, model and configuration, with a fresh
nonce, a fresh sequence number and a distinct signature.  That is the same image
legitimately processed twice, which every real pipeline does, and calling it a
replay would make the detector useless within a day.  It is reported at INFO as
an observation, never as a failure, and the distinction is tested directly
(``tests/security/test_provenance_replay.py``).

Limitations, stated rather than implied
---------------------------------------
* **The database is the trust anchor.**  Delete it and every record becomes
  first-seen again.  It must be protected at least as well as the log it
  guards; an adversary with write access to it can erase a replay.
* **It is local.**  Two verifiers with separate databases will each accept a
  replay the other would catch.  There is no shared state, by design — a shared
  ledger is the thing ADR-009 declined.
* **Retention bounds detection.**  A pruned database cannot detect the replay of
  a record older than its window.  ``prune_before`` therefore records what it
  removed and the verification report carries the window, so a negative result
  is never read as stronger than the retention allows.
* **First observation is indistinguishable from the original.**  A verifier that
  sees a replayed record *before* the genuine one records the replay as
  original.  Ordering of presentation is not something a local database can
  establish.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict, Field

from ..core.errors import ProvenanceError
from ..core.evidence import utc_now_iso
from ..core.logging import get_logger
from .record import SignedRecord

log = get_logger("provenance.replay")

REPLAY_DB_SCHEMA_VERSION = "1.0"


class ReplayVerdict(str, Enum):
    FIRST_OBSERVATION = "FIRST_OBSERVATION"
    REPLAY_EXACT = "REPLAY_EXACT"
    NONCE_REUSE = "NONCE_REUSE"
    SEQUENCE_COLLISION = "SEQUENCE_COLLISION"
    #: Not a failure. The same inference subject, legitimately re-processed.
    DUPLICATE_SUBJECT = "DUPLICATE_SUBJECT"
    #: No database was supplied, so the question was not asked.
    NOT_CHECKED = "NOT_CHECKED"


#: Verdicts that constitute a replay.  ``DUPLICATE_SUBJECT`` is deliberately
#: absent, and this tuple is the single place that distinction is encoded.
REPLAY_VERDICTS: tuple[ReplayVerdict, ...] = (
    ReplayVerdict.REPLAY_EXACT,
    ReplayVerdict.NONCE_REUSE,
    ReplayVerdict.SEQUENCE_COLLISION,
)


@dataclass(frozen=True)
class ReplayResult:
    """What the database had to say about one record."""

    verdict: ReplayVerdict
    detail: str
    observation: dict[str, Any]

    @property
    def is_replay(self) -> bool:
        return self.verdict in REPLAY_VERDICTS


class ObservationEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_digest: str
    record_id: str
    log_id: str
    sequence_number: int
    nonce: str
    key_id: str | None
    subject_key: str
    record_timestamp: str
    first_seen_at: str


class ReplayDatabase(BaseModel):
    """A local, append-mostly record of what this verifier has already seen."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = REPLAY_DB_SCHEMA_VERSION
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    retention_note: str = (
        "A negative replay result is bounded by this database's retention: a "
        "record older than the earliest observation below cannot be shown not "
        "to have been seen before."
    )
    observations: tuple[ObservationEntry, ...] = ()

    # -- indices, rebuilt on demand ---------------------------------------

    def _by_digest(self) -> dict[str, ObservationEntry]:
        return {o.entry_digest: o for o in self.observations}

    def _by_nonce(self) -> dict[tuple[str | None, str], ObservationEntry]:
        return {(o.key_id, o.nonce): o for o in self.observations}

    def _by_slot(self) -> dict[tuple[str, int], ObservationEntry]:
        return {(o.log_id, o.sequence_number): o for o in self.observations}

    def _by_subject(self) -> dict[str, list[ObservationEntry]]:
        index: dict[str, list[ObservationEntry]] = {}
        for observation in self.observations:
            index.setdefault(observation.subject_key, []).append(observation)
        return index

    # -- the question -----------------------------------------------------

    def check(self, signed: SignedRecord) -> ReplayResult:
        """Classify a record against what has been seen.  Does not record it.

        Checks run in order of decreasing certainty, and the *first* match is
        returned because these conditions are not independent: an exact replay
        also reuses its own nonce and its own slot, and reporting three failures
        for one event would misstate how much evidence there is.
        """
        entry_digest = signed.entry_digest()
        record = signed.record
        key_id = signed.signature.key_id if signed.signature else None

        prior = self._by_digest().get(entry_digest)
        if prior is not None:
            return ReplayResult(
                verdict=ReplayVerdict.REPLAY_EXACT,
                detail=(
                    # The *when* lives in the observation below, not in this
                    # sentence: it is the verifier's own clock, so quoting it
                    # here would make two otherwise identical reports differ.
                    "this exact signed record was already observed by this "
                    "database; it is byte-identical, so this is a "
                    "re-presentation of an existing record, not a new inference"
                ),
                observation={
                    "entry_digest": entry_digest,
                    "record_id": record.record_id,
                    "first_seen_at": prior.first_seen_at,
                    "first_seen_log_id": prior.log_id,
                    "first_seen_sequence": prior.sequence_number,
                },
            )

        nonce_prior = self._by_nonce().get((key_id, record.nonce))
        if nonce_prior is not None:
            return ReplayResult(
                verdict=ReplayVerdict.NONCE_REUSE,
                detail=(
                    f"nonce {record.nonce[:16]}… was already used by record "
                    f"{nonce_prior.record_id} from the same signing key, in a "
                    "record with different content; a conforming producer draws "
                    "a fresh nonce per record"
                ),
                observation={
                    "nonce": record.nonce,
                    "key_id": key_id,
                    "this_record_id": record.record_id,
                    "prior_record_id": nonce_prior.record_id,
                    "prior_entry_digest": nonce_prior.entry_digest,
                    "first_seen_at": nonce_prior.first_seen_at,
                },
            )

        slot_prior = self._by_slot().get(
            (record.sequence.log_id, record.sequence.sequence_number)
        )
        if slot_prior is not None:
            return ReplayResult(
                verdict=ReplayVerdict.SEQUENCE_COLLISION,
                detail=(
                    f"sequence {record.sequence.sequence_number} of log "
                    f"{record.sequence.log_id!r} is already occupied by record "
                    f"{slot_prior.record_id}; two distinct records claim the same "
                    "position, which is a forked log"
                ),
                observation={
                    "log_id": record.sequence.log_id,
                    "sequence_number": record.sequence.sequence_number,
                    "this_record_id": record.record_id,
                    "this_entry_digest": entry_digest,
                    "prior_record_id": slot_prior.record_id,
                    "prior_entry_digest": slot_prior.entry_digest,
                },
            )

        subject_prior = self._by_subject().get(record.subject_key(), [])
        if subject_prior:
            return ReplayResult(
                verdict=ReplayVerdict.DUPLICATE_SUBJECT,
                detail=(
                    f"the same input, model and configuration were recorded "
                    f"{len(subject_prior)} time(s) before, with different nonces "
                    "and sequence numbers. This is NOT a replay: it is the same "
                    "inference subject processed again, which is normal"
                ),
                observation={
                    "subject_key": record.subject_key(),
                    "prior_record_ids": [o.record_id for o in subject_prior],
                    "prior_count": len(subject_prior),
                    "raw_input_digest": record.input.raw_input_digest,
                    "model_file_sha256": record.model.file_sha256,
                    "is_replay": False,
                },
            )

        return ReplayResult(
            verdict=ReplayVerdict.FIRST_OBSERVATION,
            detail=(
                "this record has not been seen before by this database, within "
                f"its {len(self.observations)}-observation retention"
            ),
            observation={
                "entry_digest": entry_digest,
                "observations_held": len(self.observations),
                "earliest_observation": self.earliest_observation(),
            },
        )

    def record(self, signed: SignedRecord, *, seen_at: str | None = None) -> "ReplayDatabase":
        """Return a database with this record observed.

        Re-observing an already-present ``entry_digest`` is a no-op rather than
        an error: a verifier that re-runs over the same log must not corrupt its
        own history, and the *detection* already happened in :meth:`check`.
        """
        entry_digest = signed.entry_digest()
        if entry_digest in self._by_digest():
            return self
        record = signed.record
        entry = ObservationEntry(
            entry_digest=entry_digest,
            record_id=record.record_id,
            log_id=record.sequence.log_id,
            sequence_number=record.sequence.sequence_number,
            nonce=record.nonce,
            key_id=signed.signature.key_id if signed.signature else None,
            subject_key=record.subject_key(),
            record_timestamp=record.timestamp,
            first_seen_at=seen_at or utc_now_iso(),
        )
        return self.model_copy(
            update={
                "observations": self.observations + (entry,),
                "updated_at": seen_at or utc_now_iso(),
            }
        )

    def check_and_record(
        self, signed: SignedRecord, *, seen_at: str | None = None
    ) -> tuple[ReplayResult, "ReplayDatabase"]:
        result = self.check(signed)
        return result, self.record(signed, seen_at=seen_at)

    # -- housekeeping ------------------------------------------------------

    def earliest_observation(self) -> str | None:
        return min((o.first_seen_at for o in self.observations), default=None)

    def prune_before(self, moment: str) -> tuple["ReplayDatabase", int]:
        """Drop observations first seen before ``moment``.

        Returns the pruned database and how many entries went, because a
        verification report that does not say how much memory was discarded
        cannot be read as evidence of anything.
        """
        kept = tuple(o for o in self.observations if o.first_seen_at >= moment)
        removed = len(self.observations) - len(kept)
        if removed:
            log.info("pruned %d replay observation(s) first seen before %s", removed, moment)
        return (
            self.model_copy(update={"observations": kept, "updated_at": utc_now_iso()}),
            removed,
        )

    def stats(self) -> dict[str, Any]:
        return {
            "observations": len(self.observations),
            "distinct_logs": len({o.log_id for o in self.observations}),
            "distinct_keys": len({o.key_id for o in self.observations if o.key_id}),
            "distinct_subjects": len({o.subject_key for o in self.observations}),
            "earliest_observation": self.earliest_observation(),
        }

    def __iter__(self) -> Iterator[ObservationEntry]:  # type: ignore[override]
        return iter(self.observations)

    def __len__(self) -> int:
        return len(self.observations)

    # -- persistence -------------------------------------------------------

    @classmethod
    def empty(cls) -> "ReplayDatabase":
        return cls()

    @classmethod
    def load(cls, path: Path | str) -> "ReplayDatabase":
        file_path = Path(path)
        if not file_path.is_file():
            raise ProvenanceError(f"replay database not found: {file_path}")
        try:
            return cls.model_validate(json.loads(file_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise ProvenanceError(
                f"replay database {file_path} is not JSON: {exc}"
            ) from exc
        except Exception as exc:
            raise ProvenanceError(
                f"replay database {file_path} is malformed: {exc}"
            ) from exc

    @classmethod
    def load_or_empty(cls, path: Path | str | None) -> "ReplayDatabase":
        if path is None:
            return cls.empty()
        file_path = Path(path)
        return cls.load(file_path) if file_path.is_file() else cls.empty()

    def save(self, path: Path | str) -> Path:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return file_path


def detect_replay(signed: SignedRecord, database: ReplayDatabase | None) -> ReplayResult:
    """Classify a record against a database, or report that nothing was asked.

    An absent database yields ``NOT_CHECKED``, never ``FIRST_OBSERVATION``.
    Reporting "not seen before" when nothing was consulted would be the same
    class of error as reporting an unrun detector as clean.
    """
    if database is None:
        return ReplayResult(
            verdict=ReplayVerdict.NOT_CHECKED,
            detail=(
                "no replay database was supplied, so replay was not assessed. A "
                "valid signature does not establish that an inference happened "
                "once; that requires a record of what has been seen."
            ),
            observation={"database_supplied": False},
        )
    return database.check(signed)


__all__ = [
    "REPLAY_DB_SCHEMA_VERSION", "ReplayVerdict", "REPLAY_VERDICTS", "ReplayResult",
    "ObservationEntry", "ReplayDatabase", "detect_replay",
]
