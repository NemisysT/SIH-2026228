"""Module 5 must not acquire a network dependency (brief §21).

The SIH target environment has no cloud, no external API and no telemetry, and
the frontend is the easiest place for one to creep in: a font from a CDN, an
analytics package, an image left on the origin the design reference was
deployed to. These tests fail the build if any of those come back.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[2] / "web"

#: URLs that are documentation inside vendored library code or standards
#: namespaces, never fetched at run time.
ALLOWED = re.compile(
    r"^https?://(?:"
    r"www\.w3\.org|localhost|127\.0\.0\.1|"
    r"json-schema\.org|ui\.shadcn\.com"
    r")"
)

SOURCE_GLOBS = ("app/**/*.ts", "app/**/*.tsx", "app/**/*.css",
                "components/**/*.tsx", "lib/**/*.ts")


def _sources() -> list[Path]:
    files: list[Path] = []
    for pattern in SOURCE_GLOBS:
        files.extend(WEB.glob(pattern))
    return files


def test_no_source_file_references_a_remote_origin() -> None:
    offenders: list[str] = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        # Ignore prose in block comments: the comments explain why the remote
        # origins were removed, and naming them is the point.
        code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        code = re.sub(r"^\s*//.*$", "", code, flags=re.M)
        code = re.sub(r"^\s*\*.*$", "", code, flags=re.M)
        for match in re.finditer(r"https?://[^\s\"'`)]+", code):
            if not ALLOWED.match(match.group(0)):
                offenders.append(f"{path.relative_to(WEB)}: {match.group(0)}")
    assert not offenders, "the frontend must not reference a remote origin:\n" + "\n".join(offenders)


def test_the_vercel_blob_assets_were_replaced_with_the_supplied_files() -> None:
    """The design reference loaded eight assets from a hosted blob store."""
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        assert "hebbkx1anhila5yf" not in text, (
            f"{path.relative_to(WEB)} still points at the reference deployment's blob store"
        )


def test_every_referenced_local_asset_exists() -> None:
    missing: list[str] = []
    for path in _sources():
        for match in re.finditer(r'"(/(?:images|video|fonts)/[^"]+)"', path.read_text("utf-8")):
            asset = WEB / "public" / match.group(1).lstrip("/")
            if not asset.is_file():
                missing.append(f"{path.relative_to(WEB)} -> {match.group(1)}")
    assert not missing, "referenced assets are absent from public/:\n" + "\n".join(missing)


def test_fonts_are_self_hosted_rather_than_fetched_at_build_time() -> None:
    """next/font/google fetches from fonts.gstatic.com when the app is built."""
    for path in _sources():
        if path.suffix == ".css":
            continue
        assert "next/font" not in path.read_text(encoding="utf-8"), (
            f"{path.relative_to(WEB)} uses next/font, which needs the network at build time"
        )

    fonts_css = (WEB / "app" / "fonts.css").read_text(encoding="utf-8")
    for family in ("Instrument Sans", "Instrument Serif", "JetBrains Mono"):
        assert family in fonts_css, f"{family} is no longer declared locally"
    for name in (
        "instrument-sans-latin.woff2",
        "instrument-serif-latin.woff2",
        "jetbrains-mono-latin.woff2",
    ):
        assert (WEB / "public" / "fonts" / name).is_file(), f"{name} is missing from public/fonts"


def test_no_analytics_or_telemetry_dependency() -> None:
    manifest = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    dependencies = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    for name in dependencies:
        assert not re.search(r"analytics|telemetry|sentry|datadog|segment", name, re.I), (
            f"{name} is a telemetry dependency and the target environment allows none"
        )
    # web/.env is Git-ignored, so it is a local file ./setup.sh writes from the
    # checked-in web/.env.example. Both must turn Next's build telemetry off;
    # comments and commented-out settings in them are not a reason to fail.
    for name in (".env.example", ".env"):
        path = WEB / name
        assert path.is_file(), f"web/{name} is missing — run ./setup.sh from the repository root"
        settings = dict(
            line.split("=", 1)
            for line in (raw.strip() for raw in path.read_text(encoding="utf-8").splitlines())
            if line and not line.startswith("#") and "=" in line
        )
        assert settings.get("NEXT_TELEMETRY_DISABLED") == "1", (
            f"web/{name} must set NEXT_TELEMETRY_DISABLED=1; the target environment allows no telemetry"
        )
        for key, value in settings.items():
            assert not value.startswith(("http://", "https://")), (
                f"web/{name} points {key} at a URL; the platform reads paths on disk, never a service"
            )


def test_the_platform_reads_reports_from_disk_not_from_a_service() -> None:
    source = (WEB / "lib" / "analyst" / "source.ts").read_text(encoding="utf-8")
    assert "node:fs/promises" in source
    for forbidden in ("fetch(", "axios", "XMLHttpRequest", "WebSocket"):
        assert forbidden not in source, (
            f"the data source reached for {forbidden}; it must read the filesystem"
        )


REFERENCE = Path(os.environ.get(
    "CVTRUST_DESIGN_REFERENCE",
    "/Users/mervinmandanna/Downloads/SIH Web design reference",
))

#: Sections reused from the reference, with the reference file to compare to.
REUSED_SECTIONS = {
    "components/landing/hero-section.tsx": "components/landing/hero-section.tsx",
    "components/landing/features-section.tsx": "components/landing/features-section.tsx",
    "components/landing/infrastructure-section.tsx": "components/landing/infrastructure-section.tsx",
    "components/landing/metrics-section.tsx": "components/landing/metrics-section.tsx",
    "components/landing/pricing-section.tsx": "components/landing/pricing-section.tsx",
    "components/platform/navigation.tsx": "components/landing/navigation.tsx",
}


def _breakpoints(text: str) -> set[str]:
    return {prefix for prefix in ("sm:", "md:", "lg:", "xl:") if prefix in text}


#: The one place the platform's responsive behaviour intentionally differs from
#: the reference's, with the reason. The reference bar held five links, a text
#: link and a pill and collapsed to a full-screen menu at `md` (768px). The
#: platform's bar holds seven routes plus the same two actions, which do not
#: fit at 768px, so it collapses at `lg` (1024px) instead. Everything else
#: about the bar — the scroll pill, the hover underline, the overlay and its
#: staggered reveal — is unchanged. Any OTHER divergence fails the test below.
DOCUMENTED_BREAKPOINT_DEVIATIONS = {
    "components/platform/navigation.tsx": {"md:"},
}


@pytest.mark.parametrize("component,reference", sorted(REUSED_SECTIONS.items()))
@pytest.mark.skipif(not REFERENCE.is_dir(), reason="the design reference is not mounted")
def test_reused_sections_keep_the_reference_breakpoints(component: str, reference: str) -> None:
    """§26: the reference's responsive behaviour must survive the transformation."""
    ours = _breakpoints((WEB / component).read_text(encoding="utf-8"))
    theirs = _breakpoints((REFERENCE / reference).read_text(encoding="utf-8"))
    allowed = DOCUMENTED_BREAKPOINT_DEVIATIONS.get(component, set())
    missing = theirs - ours - allowed
    assert not missing, (
        f"{component} dropped the reference's {sorted(missing)} breakpoint(s) with no "
        "recorded reason"
    )
    if allowed:
        # A deviation that has quietly been fixed should stop being excused.
        assert allowed & theirs, (
            f"{component} records a deviation from {sorted(allowed)} that the reference "
            "does not actually use"
        )


@pytest.mark.parametrize(
    "component",
    [
        "components/platform/page-header.tsx",
        "components/platform/primitives.tsx",
        "components/platform/finding-card.tsx",
        "components/platform/evidence-explorer.tsx",
    ],
)
def test_platform_components_are_responsive(component: str) -> None:
    text = (WEB / component).read_text(encoding="utf-8")
    assert len(_breakpoints(text)) >= 2, (
        f"{component} must adapt across desktop, laptop and tablet widths"
    )


def test_wide_tables_scroll_rather_than_overflow_the_page() -> None:
    """A forensic table has more columns than a tablet is wide.

    The reference has no table this wide, so there is no reference behaviour to
    preserve; the platform contains the table in its own scroll region so the
    page itself never scrolls sideways.
    """
    text = (WEB / "components" / "platform" / "data-table.tsx").read_text(encoding="utf-8")
    assert "overflow-x-auto" in text
    assert "min-w-[" in text, "the table needs a minimum width for its scroll region to work"
