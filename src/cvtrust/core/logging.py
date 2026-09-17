"""Logging setup.

Two sinks, deliberately separate:

* a human sink on stderr, for the operator running the CLI;
* the report itself, which is the machine-readable record.

Log lines are *not* evidence.  Anything that must survive into an audit or into
an analyst decision goes into a :class:`~cvtrust.core.evidence.Finding` or into
the run context, never into a log line only.
"""

from __future__ import annotations

import logging
import sys
from typing import Literal

_CONFIGURED = False
LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)-28s %(message)s"
DATE_FORMAT = "%H:%M:%S"


def configure_logging(
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO",
    *,
    rich_output: bool = True,
) -> None:
    global _CONFIGURED
    root = logging.getLogger("cvtrust")
    root.setLevel(level)
    root.handlers.clear()

    handler: logging.Handler
    if rich_output:
        try:
            from rich.logging import RichHandler

            handler = RichHandler(
                rich_tracebacks=True, show_path=False, log_time_format="[%H:%M:%S]"
            )
            handler.setFormatter(logging.Formatter("%(name)-24s %(message)s"))
        except ImportError:  # pragma: no cover - rich is a core dependency
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(f"cvtrust.{name}")
