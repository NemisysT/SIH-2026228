"""Cost of the provenance machinery, measured rather than assumed.

The module brief asks for record creation, signing, verification, chain
verification, storage overhead and replay-database overhead, and asks that
nothing be optimised prematurely.  Nothing here is: the numbers exist so that a
deployment can tell whether signing every inference is affordable, and so that a
future change that makes it ten times slower is visible rather than discovered
in the field.

One measurement deserves its caveat up front.  Chain verification is linear in
the number of entries and re-hashes every entry, so a log that grows without
bound takes proportionally longer to verify.  That is inherent to a hash chain
and is the price of the tamper-evidence; the mitigation, if a deployment ever
needs one, is to anchor and rotate logs rather than to verify less.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..core.canonical import canonical_json
from ..core.config import Config
from ..core.evidence import utc_now_iso
from .binding import ModelBinding, bind_config, bind_input_bytes, bind_output
from .chain import build_anchor, verify_chain
from .keys import generate_keypair
from .log import ProvenanceLog
from .output import classification_output, detection_output
from .record import create_provenance_record
from .replay import ReplayDatabase
from .signing import sign_record, verify_signature
from .trust import TrustStore, trust_key
from .verify import verify_record

BENCHMARK_SCHEMA_VERSION = "1.0"


class Timing(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: str
    count: int
    total_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    per_second: float
    note: str = ""


class BenchmarkResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = BENCHMARK_SCHEMA_VERSION
    measured_at: str = Field(default_factory=utc_now_iso)
    record_count: int
    timings: tuple[Timing, ...]
    storage: dict[str, Any]
    environment: dict[str, str]
    caveats: tuple[str, ...] = (
        "Measured on the host that ran the command, single-threaded, with no "
        "warm-up discarded beyond the first record. Treat these as orders of "
        "magnitude, not as a specification.",
        "Chain verification is O(n) in the number of entries and re-hashes each "
        "one. A log that grows without bound verifies proportionally more "
        "slowly; that is inherent to the construction.",
        "Record size is dominated by the inline canonical output. A detection "
        "output with many boxes produces a larger record than a classification.",
    )

    def timing(self, operation: str) -> Timing | None:
        for item in self.timings:
            if item.operation == operation:
                return item
        return None


def _summarise(operation: str, samples: list[float], note: str = "") -> Timing:
    ordered = sorted(samples)
    total = sum(samples)
    mean = total / len(samples)
    index = max(0, int(round(0.95 * (len(ordered) - 1))))
    return Timing(
        operation=operation,
        count=len(samples),
        total_ms=round(total * 1000, 3),
        mean_ms=round(mean * 1000, 4),
        median_ms=round(statistics.median(ordered) * 1000, 4),
        p95_ms=round(ordered[index] * 1000, 4),
        per_second=round(1.0 / mean, 1) if mean > 0 else 0.0,
        note=note,
    )


def run_benchmark(
    *, record_count: int = 200, config: Config | None = None
) -> BenchmarkResult:
    """Build, sign and verify ``record_count`` representative records."""
    import platform
    import sys

    cfg = config or Config()
    key, info = generate_keypair()
    store = trust_key(TrustStore.empty(), public_key=info.public_key_hex, label="bench")

    model_binding = ModelBinding(
        model_id="M-benchmark", file_sha256="a" * 64, graph_digest="b" * 64,
        parameter_digest="c" * 64, parameter_count=11_000_000, model_format="onnx",
    )
    preprocessing = bind_config(
        {"resize": [640, 640], "mean": [0.485, 0.456, 0.406],
         "std": [0.229, 0.224, 0.225], "letterbox": True, "dtype": "float32"}
    )
    inference = bind_config(
        {"confidence_threshold": 0.25, "nms_iou_threshold": 0.45, "max_detections": 100}
    )

    # A representative mix: half classification, half detection with five boxes.
    outputs = [
        bind_output(
            classification_output({"defect": 0.91, "clean": 0.09})
            if index % 2 == 0
            else detection_output(
                [
                    {"label": "defect", "score": 0.9 - n * 0.1,
                     "box": (10.0 * n, 20.0 * n, 40.0 * n + 30, 60.0 * n + 30)}
                    for n in range(5)
                ],
                labels=("defect", "clean"),
            )
        )
        for index in range(record_count)
    ]

    create_samples: list[float] = []
    sign_samples: list[float] = []
    records = []
    provenance_log = ProvenanceLog.new("benchmark")

    for index in range(record_count):
        input_binding = bind_input_bytes(f"benchmark-input-{index}".encode())
        start = time.perf_counter()
        record = create_provenance_record(
            input_binding=input_binding,
            model_binding=model_binding,
            preprocessing=preprocessing,
            inference=inference,
            output=outputs[index],
            log_id="benchmark",
            sequence_number=index,
            previous_record_digest=provenance_log.head_digest(),
        )
        create_samples.append(time.perf_counter() - start)

        start = time.perf_counter()
        entry = sign_record(record, key)
        sign_samples.append(time.perf_counter() - start)

        provenance_log.append(entry)
        records.append(entry)

    signature_samples: list[float] = []
    for entry in records:
        start = time.perf_counter()
        verify_signature(entry)
        signature_samples.append(time.perf_counter() - start)

    chain = verify_chain(provenance_log.entries, anchor=build_anchor(provenance_log.entries))

    verify_samples: list[float] = []
    database = ReplayDatabase.empty()
    for position, entry in enumerate(records):
        start = time.perf_counter()
        verify_record(
            entry, trust_store=store, replay_database=database,
            chain_result=chain, position=position,
        )
        verify_samples.append(time.perf_counter() - start)
        database = database.record(entry)

    chain_samples: list[float] = []
    for _ in range(5):
        start = time.perf_counter()
        verify_chain(provenance_log.entries, anchor=build_anchor(provenance_log.entries))
        chain_samples.append(time.perf_counter() - start)

    replay_samples: list[float] = []
    for entry in records[: min(50, len(records))]:
        start = time.perf_counter()
        database.check(entry)
        replay_samples.append(time.perf_counter() - start)

    serialised = provenance_log.serialise().encode("utf-8")
    replay_bytes = len(database.model_dump_json().encode("utf-8"))
    record_bytes = [len(canonical_json(e.entry_payload())) for e in records]

    return BenchmarkResult(
        record_count=record_count,
        timings=(
            _summarise("record_creation", create_samples,
                       "canonicalise every binding and derive the content-addressed id"),
            _summarise("signing", sign_samples, "Ed25519 over the record's canonical bytes"),
            _summarise("signature_verification", signature_samples,
                       "signature check alone, without trust or binding checks"),
            _summarise("record_verification", verify_samples,
                       "the full check set: schema, self-consistency, signature, "
                       "trust, expectations, replay and chain position"),
            _summarise("chain_verification_full_log", chain_samples,
                       f"whole {record_count}-entry chain, O(n) and re-hashing every entry"),
            _summarise("replay_lookup", replay_samples,
                       f"one lookup against a {len(database)}-observation database"),
        ),
        storage={
            "log_bytes": len(serialised),
            "mean_record_bytes": round(sum(record_bytes) / len(record_bytes), 1),
            "min_record_bytes": min(record_bytes),
            "max_record_bytes": max(record_bytes),
            "replay_database_bytes": replay_bytes,
            "replay_bytes_per_observation": round(replay_bytes / max(1, len(database)), 1),
            "note": "Record size is dominated by the inline canonical output; the "
            "detection records here carry five boxes each.",
        },
        environment={
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "config_hash": cfg.config_hash()[:16],
        },
    )


def render_benchmark(result: BenchmarkResult) -> None:
    """Console rendering of a benchmark result."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()
    table = Table(box=None, pad_edge=False)
    table.add_column("operation", style="bold", width=30)
    table.add_column("mean", justify="right", width=11)
    table.add_column("median", justify="right", width=11)
    table.add_column("p95", justify="right", width=11)
    table.add_column("per second", justify="right", width=12)

    for timing in result.timings:
        table.add_row(
            timing.operation,
            f"{timing.mean_ms:.3f} ms",
            f"{timing.median_ms:.3f} ms",
            f"{timing.p95_ms:.3f} ms",
            f"{timing.per_second:,.0f}",
        )
    console.print(
        Panel(table, title=f"Provenance performance — {result.record_count} records",
              border_style="blue")
    )

    storage = Table(box=None, show_header=False, pad_edge=False)
    storage.add_column(style="bold", width=30)
    storage.add_column()
    storage.add_row("Log on disk", f"{result.storage['log_bytes']:,} bytes")
    storage.add_row("Mean record", f"{result.storage['mean_record_bytes']:,.0f} bytes")
    storage.add_row(
        "Record range",
        f"{result.storage['min_record_bytes']:,}–{result.storage['max_record_bytes']:,} bytes",
    )
    storage.add_row("Replay database", f"{result.storage['replay_database_bytes']:,} bytes")
    storage.add_row(
        "Per observation", f"{result.storage['replay_bytes_per_observation']:,.0f} bytes"
    )
    console.print(Panel(storage, title="Storage overhead", border_style="dim"))
    console.print(
        Panel(
            Text("\n".join(f"• {c}" for c in result.caveats), style="dim"),
            title="Caveats",
            border_style="dim",
        )
    )


__all__ = ["BENCHMARK_SCHEMA_VERSION", "Timing", "BenchmarkResult", "run_benchmark",
           "render_benchmark"]
