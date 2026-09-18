"""Systematic mislabelling detection.

Random label flipping and systematic mislabelling look identical at the level of
a single sample and are completely different threats.  A flip is noise; a
systematic mapping ("this contributor labels every *transport* as *vehicle*") is
a directed manipulation of what the model will learn, and it survives every
per-sample sanity check because each individual label is plausible.

The distinguishing structure is *concentration*: a contributor's suspected
labels pile up on one ordered pair ``(declared -> suggested)`` far more than the
rest of the cohort's do.  That is a testable claim:

* ``k`` = this contributor's units where the label detector suggested this exact
  pair;
* ``n`` = this contributor's analysed units;
* ``p0`` = the same pair's rate across **every other contributor**
  (leave-one-out, ADR-007 — a dominant malicious contributor must not be
  allowed to raise the baseline it is compared against);
* one-sided binomial test of ``H0: rate <= p0``, then Benjamini-Hochberg across
  every (contributor, pair) tested, because a dataset with many contributors and
  many classes runs hundreds of tests and would otherwise manufacture
  significance by multiplicity alone.

Confidence here is ``1 - q`` and its basis is ``STATISTICAL``: it is a statement
about the null model, and the evidence carries ``k``, ``n``, ``p0``, the rate
ratio and the q-value so the analyst can check the arithmetic.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.evidence import (
    STATISTICAL_CONFIDENCE_CAP,
    AssetRef,
    AssetType,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Severity,
)
from ..risk.statistics import benjamini_hochberg, binomial_greater_pvalue
from .base import AnalysisContext, DetectorOutput, FindingFactory, coverage_entry

ATTACK_CLASS = "systematic_mislabel"


class SystematicMislabelDetector:
    name = "systematic_mislabel"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)

    def run(self, ctx: AnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        cfg = ctx.config.systematic_mislabel

        units = ctx.shared.get("label_units")
        suggestions = ctx.shared.get("label_suggestions")
        if not units or suggestions is None:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason="the label-consistency detector did not run or produced "
                           "no analysable units, so no label suggestions exist to "
                           "test for directional structure",
                )
            )
            return out

        totals: dict[str, int] = defaultdict(int)
        contributor_of_key: dict[str, str] = {}
        for key, contributor, _ in units:
            totals[contributor] += 1
            contributor_of_key[key] = contributor

        # (contributor, declared, suggested) -> [keys]
        pair_members: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for key, (declared, suggested, _) in suggestions.items():
            contributor = contributor_of_key.get(key)
            if contributor is None or declared == suggested:
                continue
            pair_members[(contributor, declared, suggested)].append(key)

        eligible_contributors = {
            c for c, n in totals.items() if n >= cfg.min_contributor_samples
        }
        if not eligible_contributors:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version,
                    reason=f"no contributor has the required "
                           f"{cfg.min_contributor_samples} analysed units",
                )
            )
            out.stats = {"contributor_units": dict(sorted(totals.items()))}
            return out

        tests: list[dict] = []
        for (contributor, declared, suggested), members in sorted(pair_members.items()):
            if contributor not in eligible_contributors:
                continue
            k = len(members)
            if k < cfg.min_pair_count:
                continue
            n = totals[contributor]

            others_k = sum(
                len(v)
                for (c, d, s), v in pair_members.items()
                if c != contributor and d == declared and s == suggested
            )
            others_n = sum(n_ for c, n_ in totals.items() if c != contributor)
            # With a single contributor there is no cohort to compare against;
            # fall back to a conservative baseline derived from the pair's own
            # dataset-wide rate, and say so in the evidence.
            baseline_is_cohort = others_n > 0
            p0 = (others_k / others_n) if baseline_is_cohort else (k / max(n, 1)) * 0.5
            p_value = binomial_greater_pvalue(k, n, p0)
            tests.append(
                {
                    "contributor": contributor,
                    "declared": declared,
                    "suggested": suggested,
                    "k": k,
                    "n": n,
                    "others_k": others_k,
                    "others_n": others_n,
                    "p0": p0,
                    "p_value": p_value,
                    "members": members,
                    "baseline_is_cohort": baseline_is_cohort,
                }
            )

        if not tests:
            out.stats = {
                "tests": 0,
                "contributor_units": dict(sorted(totals.items())),
                "reason": "no (contributor, declared -> suggested) pair reached "
                          f"min_pair_count={cfg.min_pair_count}",
            }
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=("label suggestions from the label-consistency detector "
                                 "are informative about the true class",),
                    limitations=_LIMITATIONS,
                )
            )
            return out

        qvalues = benjamini_hochberg([t["p_value"] for t in tests])
        scores: dict[str, float] = {}

        for test, q in zip(tests, qvalues):
            test["q_value"] = q
            if q >= cfg.alpha:
                continue
            rate = test["k"] / test["n"]
            ratio = rate / test["p0"] if test["p0"] > 0 else float("inf")
            severity, rationale = _severity(test["k"], ratio, rate)
            confidence = min(1.0 - q, STATISTICAL_CONFIDENCE_CAP)

            for key in test["members"]:
                scores[key] = max(scores.get(key, 0.0), confidence)

            asset = AssetRef(type=AssetType.CONTRIBUTOR, id=test["contributor"])
            out.findings.append(
                factory.emit(
                    attack_class=ATTACK_CLASS,
                    asset=asset,
                    contributor=test["contributor"],
                    title=(
                        f"Contributor '{test['contributor']}' systematically labels "
                        f"'{test['suggested']}' content as '{test['declared']}' "
                        f"({test['k']} of {test['n']} units)"
                    ),
                    severity=severity,
                    confidence=confidence,
                    basis=ConfidenceBasis.STATISTICAL,
                    coverage=Coverage.SUPPORTED,
                    discriminator=(test["declared"], test["suggested"]),
                    evidence=[
                        EvidenceItem(
                            kind="directional_label_concentration",
                            statement=(
                                f"{test['k']} of this contributor's {test['n']} analysed "
                                f"units ({rate:.1%}) carry the declared label "
                                f"'{test['declared']}' while their neighbourhood suggests "
                                f"'{test['suggested']}'. Across the rest of the cohort the "
                                f"same directional pair occurs in {test['others_k']} of "
                                f"{test['others_n']} units ({test['p0']:.2%})."
                            ),
                            observation={
                                "contributor": test["contributor"],
                                "declared_label": test["declared"],
                                "suggested_label": test["suggested"],
                                "contributor_pair_count": test["k"],
                                "contributor_units": test["n"],
                                "contributor_rate": rate,
                                "cohort_pair_count": test["others_k"],
                                "cohort_units": test["others_n"],
                                "cohort_rate": test["p0"],
                                "rate_ratio": ratio,
                                "baseline": (
                                    "leave-one-out cohort"
                                    if test["baseline_is_cohort"]
                                    else "fallback (single contributor; no cohort available)"
                                ),
                            },
                            refs=tuple(test["members"][:50]),
                        ),
                        EvidenceItem(
                            kind="binomial_test",
                            statement=(
                                f"One-sided binomial test of H0: rate <= {test['p0']:.4f} "
                                f"gives p = {test['p_value']:.3e}; after Benjamini-Hochberg "
                                f"correction over {len(tests)} tests, q = {q:.3e} "
                                f"(alpha = {cfg.alpha})."
                            ),
                            observation={
                                "test": "binomial, alternative=greater",
                                "successes": test["k"],
                                "trials": test["n"],
                                "null_rate": test["p0"],
                                "p_value": test["p_value"],
                                "q_value": q,
                                "alpha": cfg.alpha,
                                "n_tests": len(tests),
                                "correction": "benjamini_hochberg",
                            },
                            refs=(),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "affected_units": test["k"],
                                "rate_ratio": ratio,
                                "contributor_rate": rate,
                            },
                            refs=(),
                        ),
                    ],
                    assumptions=(
                        "label suggestions from neighbourhood analysis are informative "
                        "about the true class",
                        "contributors are exchangeable under the null: absent "
                        "manipulation, they mislabel any given pair at comparable rates",
                    ),
                    limitations=_LIMITATIONS,
                )
            )

        out.scores[ATTACK_CLASS] = scores
        out.flagged[ATTACK_CLASS] = {key.split("#", 1)[0] for key in scores}
        out.stats = {
            "tests": len(tests),
            "significant": len(out.findings),
            "alpha": cfg.alpha,
            "contributor_units": dict(sorted(totals.items())),
            "top_tests": [
                {
                    k: v for k, v in sorted(t.items())
                    if k not in {"members"}
                }
                for t in sorted(tests, key=lambda t: t["p_value"])[:10]
            ],
        }
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=("contributor attribution is available and correct",),
                limitations=_LIMITATIONS,
            )
        )
        return out


_LIMITATIONS = (
    "inherits the label-consistency detector's feature-space dependence: if the "
    "suggested labels are wrong, the directional structure tested here is wrong",
    "a mapping applied uniformly by every contributor has no cohort baseline to "
    "stand out against and is not detectable by this test",
    "statistical significance is evidence of a non-random pattern, not proof of "
    "intent; an unfamiliar annotation guideline produces the same signature",
)


def _severity(count: int, ratio: float, rate: float) -> tuple[Severity, str]:
    if count >= 20 and (ratio >= 5 or rate >= 0.25):
        return (
            Severity.HIGH,
            f"{count} units follow one directional mapping at {_format_ratio(ratio)}; "
            "at this volume the mapping shapes what the model learns for the "
            "affected classes",
        )
    if count >= 8 and ratio >= 3:
        return (
            Severity.MEDIUM,
            f"{count} units follow one directional mapping at {_format_ratio(ratio)}",
        )
    return (
        Severity.LOW,
        "the directional pattern is statistically detectable but affects few units",
    )


def _format_ratio(ratio: float) -> str:
    """Render a rate ratio, including the unbounded case.

    A cohort rate of zero makes the ratio infinite, and "infx the cohort rate"
    is not a sentence.  The unbounded case is also the most interesting one, so
    it gets said properly.
    """
    import math

    if not math.isfinite(ratio):
        return "an unbounded multiple of the cohort rate (the rest of the cohort had none)"
    return f"{ratio:.1f}x the cohort rate"
