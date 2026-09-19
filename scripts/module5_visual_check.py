"""Visual-fidelity check against the supplied design reference (brief §34).

The reference is the authoritative source for the frontend's visual system, so
"did we keep it?" needs an answer that is not a matter of opinion. This script
answers it structurally: for each reused section it extracts the Tailwind class
strings, the inline styles, the keyframe names and the design tokens from the
reference file and from the transformed file, and reports what carried over.

Content classes are expected to differ — the sections now carry SIH26228 data,
and a card that lists four scopes is not the card that listed three plans. What
must not differ is the visual vocabulary: the plates, the spacing scale, the
type ramp, the borders, the accent colour, the transitions and the animations.
So the check is run over the *visual* subset of classes, and prints the exact
tokens that went missing for review rather than only a number.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path("/Users/mervinmandanna/Downloads/SIH Web design reference")
WEB = ROOT / "web"

#: reference file -> transformed file
PAIRS = {
    "components/landing/hero-section.tsx": "components/landing/hero-section.tsx",
    "components/landing/features-section.tsx": "components/landing/features-section.tsx",
    "components/landing/how-it-works-section.tsx": "components/landing/how-it-works-section.tsx",
    "components/landing/infrastructure-section.tsx": "components/landing/infrastructure-section.tsx",
    "components/landing/metrics-section.tsx": "components/landing/metrics-section.tsx",
    "components/landing/integrations-section.tsx": "components/landing/integrations-section.tsx",
    "components/landing/security-section.tsx": "components/landing/security-section.tsx",
    "components/landing/developers-section.tsx": "components/landing/developers-section.tsx",
    "components/landing/testimonials-section.tsx": "components/landing/testimonials-section.tsx",
    "components/landing/pricing-section.tsx": "components/landing/pricing-section.tsx",
    "components/landing/cta-section.tsx": "components/landing/cta-section.tsx",
    "components/landing/ascii-scene.tsx": "components/landing/ascii-scene.tsx",
    "components/landing/navigation.tsx": "components/platform/navigation.tsx",
    "components/landing/footer-section.tsx": "components/platform/footer.tsx",
}

#: The classes that carry the design: layout rails, spacing, type ramp, colour,
#: borders, radii, shadows, transitions, animation. Utility classes that only
#: describe content flow (grid-cols-N, line-clamp) are excluded, because the
#: content genuinely changed.
VISUAL = re.compile(
    r"^(?:"
    r"max-w-\[|min-h-\[|px-|py-|pt-|pb-|mt-|mb-|gap-|p-\d|"
    r"text-\[|text-(?:xs|sm|base|lg|xl|\d?xl)|font-(?:display|mono|sans|medium)|"
    r"leading-|tracking-|"
    r"bg-(?:black|background|foreground|white|card|muted)|"
    r"border(?:-|$)|rounded-|shadow-|opacity-|blur-|backdrop-|"
    r"duration-|delay-|transition|animate-|ease-|"
    r"absolute|relative|fixed|sticky|inset-|"
    r"hover:|group-hover:|lg:|md:|xl:|sm:"
    r")"
)

#: Design tokens that must survive verbatim wherever the reference used them.
TOKENS = (
    "#eca8d6",                 # the accent
    "oklch(0.09_0.01_260)",    # the process-section plate
    "max-w-[1400px]",          # the content rail
    "px-6 lg:px-12",           # the rail's gutters
    "font-display",            # the serif display face
    "border-foreground/10",    # the hairline
    "bg-foreground/[0.02]",    # the panel fill
    "duration-500",            # the standard transition
    "clamp(2rem,6vw,7rem)",    # the hero type ramp
)


def classes(source: str) -> set[str]:
    found: set[str] = set()
    for match in re.finditer(r'className=(?:"([^"]*)"|\{`([^`]*)`\}|\{"([^"]*)"\})', source):
        blob = match.group(1) or match.group(2) or match.group(3) or ""
        blob = re.sub(r"\$\{[^}]*\}", " ", blob)
        found.update(token for token in blob.split() if token)
    return found


def visual_classes(source: str) -> set[str]:
    return {token for token in classes(source) if VISUAL.match(token)}


def keyframes(source: str) -> set[str]:
    return set(re.findall(r"@keyframes\s+([A-Za-z0-9_-]+)", source))


def main() -> int:
    failures: list[str] = []
    print(f"{'component':40s} {'kept':>6s} {'ref':>5s} {'%':>5s}  missing visual tokens")
    print("-" * 110)

    total_kept = total_ref = 0
    for ref_rel, web_rel in PAIRS.items():
        ref_path = REFERENCE / ref_rel
        web_path = WEB / web_rel
        if not ref_path.is_file():
            failures.append(f"reference file missing: {ref_rel}")
            continue
        if not web_path.is_file():
            failures.append(f"transformed file missing: {web_rel}")
            continue

        ref_source = ref_path.read_text(encoding="utf-8")
        web_source = web_path.read_text(encoding="utf-8")

        ref_visual = visual_classes(ref_source)
        web_visual = visual_classes(web_source)
        kept = ref_visual & web_visual
        missing = sorted(ref_visual - web_visual)

        total_kept += len(kept)
        total_ref += len(ref_visual)
        share = 100 * len(kept) / max(len(ref_visual), 1)

        shown = ", ".join(missing[:5]) + (f" (+{len(missing) - 5})" if len(missing) > 5 else "")
        print(
            f"{Path(web_rel).name:40s} {len(kept):6d} {len(ref_visual):5d} {share:4.0f}%  {shown}"
        )

        # A reused section that kept less than half the reference's visual
        # vocabulary has been rebuilt rather than reused.
        if share < 50:
            failures.append(
                f"{web_rel}: only {share:.0f}% of the reference's visual classes survived"
            )

        for name in keyframes(ref_source):
            if name not in web_source:
                failures.append(f"{web_rel}: reference animation '{name}' was dropped")

    print("-" * 110)
    print(f"{'TOTAL':40s} {total_kept:6d} {total_ref:5d} {100 * total_kept / max(total_ref, 1):4.0f}%")

    print("\nDesign tokens, across the whole frontend:")
    all_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(WEB.glob("{app,components,lib}/**/*.tsx"))
    )
    all_source += "\n".join(
        path.read_text(encoding="utf-8")
        for directory in ("app", "components", "lib")
        for path in sorted((WEB / directory).rglob("*.tsx"))
    )
    all_source += (WEB / "app" / "globals.css").read_text(encoding="utf-8")

    for token in TOKENS:
        occurrences = all_source.count(token)
        status = "ok" if occurrences else "MISSING"
        print(f"  {token:28s} {occurrences:4d} use(s)  {status}")
        if not occurrences:
            failures.append(f"design token '{token}' no longer appears anywhere")

    # The reference's theme must be untouched: same tokens, same values.
    ref_css = (REFERENCE / "app" / "globals.css").read_text(encoding="utf-8")
    web_css = (WEB / "app" / "globals.css").read_text(encoding="utf-8")
    ref_vars = dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", ref_css))
    web_vars = dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", web_css))
    changed = {
        name: (value, web_vars.get(name))
        for name, value in ref_vars.items()
        if web_vars.get(name) != value
    }
    print(f"\nTheme variables: {len(ref_vars)} in the reference, {len(changed)} changed")
    for name, (was, now) in sorted(changed.items()):
        print(f"  {name}: {was.strip()!r} -> {now!r}")
        failures.append(f"theme variable {name} was changed")

    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("\nThe reference's visual system is intact.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
