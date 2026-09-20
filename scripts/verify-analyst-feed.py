#!/usr/bin/env python3
"""Fail if the analyst feed is anything less than every scenario, run for real.

`cvtrust analyst export` exits 1 when it writes a feed in which some scenario
had no upstream lab to run against. At the CLI that is correct behaviour — the
engine reports missing evidence rather than inventing it, and the frontend
renders NOT_RUN with the reason. In a production image it is not acceptable:
a container that shipped with, say, no model lab would present a dashboard
whose Module 2 column is empty for reasons that have nothing to do with the
data being assessed. So the image build calls this, and stops.

Usage:  verify-analyst-feed.py <feed-dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    index = Path(argv[1]) / "index.json"
    if not index.is_file():
        print(f"no feed at {index}", file=sys.stderr)
        return 1

    catalogue = json.loads(index.read_text(encoding="utf-8"))
    rows = catalogue["scenarios"]
    missing = [row["name"] for row in rows if row["status"] != "RUN"]

    print(
        f"analyst feed: {len(rows) - len(missing)}/{len(rows)} scenarios ran · "
        f"engine {catalogue['software_version']} · "
        f"config {catalogue['config_hash'][:12]} · "
        f"generated {catalogue['generated_at']}"
    )
    for row in rows:
        observed = row["observed_disposition"] or "NOT_RUN"
        expected = row["expected_disposition"]
        note = "" if observed == expected else f"   (lab expected {expected})"
        print(f"  {row['name']:34s} {observed:13s}{note}")

    if missing:
        print(
            "\nfeed incomplete — these scenarios had no upstream lab to run "
            "against: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
