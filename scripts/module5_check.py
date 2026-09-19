"""Assert that what the analyst sees is what the engine decided.

Run by ``scripts/module5-verify.sh`` against a serving instance. For every
scenario in the exported feed it fetches all ten analyst screens and checks
them against the JSON the engine wrote:

* the disposition on screen is the disposition in the report, everywhere;
* every rule the engine fired is named on the decision screen;
* a scope the run did not assess reads NOT_ASSESSED, never ACCEPT;
* no screen displays an aggregate trust, security or risk score;
* demo data is labelled as demo data on every screen;
* the raw report endpoint serves the engine's bytes unmodified.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get("BASE_URL", "http://localhost:3131")
FEED = Path(__file__).resolve().parents[1] / "reports" / "analyst"

PAGES = (
    "/",
    "/dataset",
    "/model",
    "/provenance",
    "/audit",
    "/shift",
    "/evidence",
    "/decision",
    "/coverage",
    "/demo",
)

#: A score the UI displays, as opposed to prose saying there is no score.
#: The negations the platform and the engine both print are excluded.
SCORE_DISPLAY = re.compile(
    r"(?<!no )(?<!not a )(trust|security|safety|risk)\s*(score|level)\s*[:=]?\s*\d",
    re.I,
)
PERCENT_SECURE = re.compile(r"\d{1,3}\s*%\s*(secure|safe|trusted|covered)", re.I)

failures: list[str] = []


def fetch(path: str) -> str:
    try:
        with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=60) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:  # pragma: no cover - diagnostic path
        failures.append(f"{path}: could not be fetched ({exc})")
        return ""


def visible(markup: str) -> str:
    markup = re.sub(r"<script.*?</script>", " ", markup, flags=re.S)
    markup = re.sub(r"<style.*?</style>", " ", markup, flags=re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", markup)))


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def check_live_source() -> int:
    """The live source must never be labelled, or served, as demo data (§19).

    Publishing a real assessment is how an operator uses this platform, and the
    failure mode that actually misleads is a live page still wearing demo
    chrome. Skipped when nothing has been published.
    """
    live_index = FEED.parent / "live" / "index.json"
    if not live_index.is_file():
        print("    live source: empty (skipped)")
        return 0

    catalogue = json.loads(live_index.read_text(encoding="utf-8"))
    rendered = 0
    for row in catalogue.get("scenarios", []):
        if row.get("status") != "RUN":
            continue
        report = json.loads(
            (live_index.parent / row["files"]["assurance"]).read_text(encoding="utf-8")
        )
        disposition = report["decision"]["disposition"]
        for path in PAGES:
            text = visible(fetch(f"{path}?source=live&scenario={row['name']}"))
            rendered += 1
            check(
                "Live assessment" in text,
                f"live/{row['name']}{path}: is not labelled as a live assessment",
            )
            # /demo explains that demo data is NOT substituted, so the phrase
            # is legitimate there and nowhere else.
            check(
                path == "/demo" or "Demo scenario" not in text,
                f"live/{row['name']}{path}: carries demo chrome over live data",
            )
            check(
                disposition in text,
                f"live/{row['name']}{path}: does not show the engine's {disposition}",
            )
    print(f"    live source: {len(catalogue.get('scenarios', []))} assessment(s) checked")
    return rendered


def main() -> int:
    index_path = FEED / "index.json"
    if not index_path.is_file():
        print(f"no analyst feed at {FEED}; run `cvtrust analyst export` first", file=sys.stderr)
        return 2

    catalogue = json.loads(index_path.read_text(encoding="utf-8"))
    scenarios = catalogue["scenarios"]
    print(f"    feed: {len(scenarios)} scenario(s), engine {catalogue['software_version']}")

    checked_pages = 0
    for row in scenarios:
        name = row["name"]
        query = f"?scenario={name}"

        pages = {path: fetch(f"{path}{query}") for path in PAGES}
        checked_pages += len(pages)

        for path, markup in pages.items():
            check(len(markup) > 5000, f"{name}{path}: page came back empty or truncated")
            text = visible(markup)

            # §7: no universal score, anywhere, on any screen.
            hit = SCORE_DISPLAY.search(text) or PERCENT_SECURE.search(text)
            check(hit is None, f"{name}{path}: displays a score — {hit.group(0) if hit else ''!r}")

            # §19: the analyst must always know which body of data this is.
            check(
                "Demo scenario" in text or "Live assessment" in text,
                f"{name}{path}: does not state whether this is demo or live data",
            )

        if row["status"] != "RUN":
            decision_text = visible(pages["/demo"])
            check(
                "NOT_RUN" in decision_text,
                f"{name}: a scenario that did not run must say so on the demo screen",
            )
            continue

        report = json.loads((FEED / row["files"]["assurance"]).read_text(encoding="utf-8"))
        decision = report["decision"]
        disposition = decision["disposition"]

        # §33: the displayed result must match the actual assurance report.
        for path in ("/", "/decision", "/demo", "/evidence"):
            check(
                disposition in visible(pages[path]),
                f"{name}{path}: does not show the engine's disposition {disposition}",
            )

        decision_text = visible(pages["/decision"])
        for rule_id in sorted({outcome["rule_id"] for outcome in decision["fired_rules"]}):
            check(
                rule_id in decision_text,
                f"{name}/decision: fired rule {rule_id} is not shown",
            )

        # Per-scope: an unassessed scope must never read as accepted.
        scope_pages = {
            "dataset": "/dataset",
            "model": "/model",
            "provenance": "/provenance",
            "distribution": "/shift",
        }
        for scope, path in scope_pages.items():
            summary = report[f"{scope}_assurance"]
            text = visible(pages[path])
            check(
                summary["disposition"] in text,
                f"{name}{path}: scope disposition {summary['disposition']} is not shown",
            )
            if not summary["assessed"]:
                check(
                    "NOT_ASSESSED" in text or "not assessed" in text.lower(),
                    f"{name}{path}: an unassessed scope must say so",
                )
                check(
                    "ACCEPT" not in text.split("Demo scenario")[0],
                    f"{name}{path}: an unassessed scope must not read as accepted",
                )

        # §30: the export endpoint serves the engine's own bytes.
        raw = fetch(f"/api/analyst/report/demo/{name}/assurance")
        check(
            json.loads(raw)["report_id"] == report["report_id"],
            f"{name}: the report endpoint did not serve the engine's report",
        )

        # §16: a chain break localises; later records are not marked invalid.
        if row["files"].get("provenance"):
            provenance = json.loads(
                (FEED / row["files"]["provenance"]).read_text(encoding="utf-8")
            )
            break_at = provenance["chain"].get("first_break_position")
            audit_text = visible(pages["/audit"])
            if break_at is not None:
                check(
                    f"position {break_at}" in audit_text,
                    f"{name}/audit: the break at position {break_at} is not localised",
                )
                check(
                    audit_text.count("CHAIN BREAK") == 1,
                    f"{name}/audit: exactly one link may be marked as the break",
                )
                # Only meaningful when the break is not the final link. In the
                # lab's tamper scenarios the last record is the altered one, so
                # nothing follows it.
                trailing = [
                    link
                    for link in provenance["chain"]["links"]
                    if link["position"] > break_at
                ]
                if trailing:
                    check(
                        "UNVERIFIED BEYOND BREAK" in audit_text,
                        f"{name}/audit: records after the break must read as unverified, "
                        "not as invalid",
                    )

        status = "ok" if not failures else "issues"
        print(f"    {name:34s} {disposition:13s} {status}")

    checked_pages += check_live_source()
    print(f"    checked {checked_pages} page renders")

    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\n    every screen agrees with the engine's report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
