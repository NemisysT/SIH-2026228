"""Contributor / batch / source risk aggregation.

The problem statement is explicit that sample-level flags are not enough: where
contributor metadata exists, evidence must be aggregated to the contributor.
The question an analyst actually needs answered is not "how many of this
contributor's samples were flagged" — a contributor who supplied half the
dataset will always top that list — but **"is this contributor flagged at a
higher rate than the rest of the cohort, by more than chance?"**

So for each (contributor, attack class):

* ``k`` flagged samples out of ``n`` the contributor supplied;
* ``p0`` the same class's flag rate across every **other** contributor
  (leave-one-out, ADR-007: a contributor must not dilute the baseline it is
  measured against);
* a one-sided binomial test, then Benjamini-Hochberg across all
  (contributor, class) tests in the run.

Confidence is deliberately the **minimum** of the statistical confidence
(``1 - q``) and the mean confidence of the underlying sample findings.  A very
significant concentration of weak evidence is still weak evidence; taking the
minimum stops multiplicity from laundering low-quality detections into a
high-confidence contributor verdict.

Every contributor finding references the sample findings that produced it, so
the lineage from "contributor bravo: QUARANTINE" back to individual images is
one hop.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from ..core.evidence import (
    SEVERITY_ORDER,
    STATISTICAL_CONFIDENCE_CAP,
    AssetRef,
    AssetType,
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Finding,
    Severity,
)
from ..datasets.manifest import DatasetManifest
from .statistics import benjamini_hochberg, binomial_greater_pvalue

METHOD = "contributor_aggregation"
METHOD_VERSION = "1.0"

#: Attack classes whose findings are already contributor-level and must not be
#: re-aggregated into a rate (that would double-count the same evidence).
CONTRIBUTOR_LEVEL_CLASSES = frozenset({"systematic_mislabel"})


class ContributorAggregator:
    name = METHOD
    version = METHOD_VERSION

    def __init__(self, cfg, policy, unknown_label: str = "unknown") -> None:
        self.cfg = cfg
        self.policy = policy
        self.unknown_label = unknown_label

    def run(
        self,
        findings: Sequence[Finding],
        manifest: DatasetManifest,
        coverage_by_class: dict[str, Coverage],
    ) -> tuple[list[Finding], list[dict]]:
        totals: dict[str, int] = defaultdict(int)
        for record in manifest.samples:
            totals[record.contributor] += 1

        # contributor -> attack class -> {sample_id: [findings]}
        flagged: dict[str, dict[str, dict[str, list[Finding]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )
        for finding in findings:
            if finding.asset.type is not AssetType.SAMPLE:
                continue
            if finding.attack_class in CONTRIBUTOR_LEVEL_CLASSES:
                continue
            contributor = finding.contributor or self.unknown_label
            flagged[contributor][finding.attack_class][finding.asset.id].append(finding)

        attack_classes = sorted({c for cls in flagged.values() for c in cls})
        tests: list[dict] = []

        for attack_class in attack_classes:
            per_contributor = {
                contributor: set(flagged[contributor].get(attack_class, {}))
                for contributor in totals
            }
            for contributor, n in sorted(totals.items()):
                k = len(per_contributor.get(contributor, set()))
                if n < self.cfg.min_contributor_samples or k < self.cfg.min_flagged:
                    continue
                others_k = sum(
                    len(v) for c, v in per_contributor.items() if c != contributor
                )
                others_n = sum(n_ for c, n_ in totals.items() if c != contributor)
                has_cohort = others_n > 0
                p0 = (others_k / others_n) if has_cohort else 0.5
                tests.append(
                    {
                        "contributor": contributor,
                        "attack_class": attack_class,
                        "k": k,
                        "n": n,
                        "others_k": others_k,
                        "others_n": others_n,
                        "p0": p0,
                        "p_value": binomial_greater_pvalue(k, n, p0),
                        "has_cohort": has_cohort,
                        "findings": [
                            f
                            for group in flagged[contributor][attack_class].values()
                            for f in group
                        ],
                    }
                )

        qvalues = benjamini_hochberg([t["p_value"] for t in tests])
        out_findings: list[Finding] = []
        summary: list[dict] = []

        for test, q in zip(tests, qvalues):
            test["q_value"] = q
            rate = test["k"] / test["n"]
            ratio = rate / test["p0"] if test["p0"] > 0 else float("inf")
            child_findings: list[Finding] = test["findings"]
            mean_child_confidence = (
                sum(f.confidence for f in child_findings) / len(child_findings)
                if child_findings
                else 0.0
            )
            max_child_severity = max(
                (f.severity for f in child_findings), key=lambda s: SEVERITY_ORDER[s]
            ) if child_findings else Severity.INFO

            summary.append(
                {
                    "contributor": test["contributor"],
                    "attack_class": test["attack_class"],
                    "flagged": test["k"],
                    "samples": test["n"],
                    "rate": rate,
                    "cohort_rate": test["p0"],
                    "rate_ratio": ratio,
                    "p_value": test["p_value"],
                    "q_value": q,
                    "significant": bool(q < self.cfg.alpha),
                    "max_child_severity": max_child_severity.value,
                    "mean_child_confidence": mean_child_confidence,
                }
            )

            if q >= self.cfg.alpha:
                continue

            confidence = min(
                1.0 - q, mean_child_confidence, STATISTICAL_CONFIDENCE_CAP
            )
            severity, rationale = _severity(test["k"], ratio, rate, max_child_severity)
            coverage = coverage_by_class.get(test["attack_class"], Coverage.PARTIAL)
            decision = self.policy.decide(
                severity=severity,
                confidence=confidence,
                coverage=coverage,
                basis=ConfidenceBasis.STATISTICAL,
            )

            asset = AssetRef(type=AssetType.CONTRIBUTOR, id=test["contributor"])
            from ..core.evidence import make_finding_id, utc_now_iso

            out_findings.append(
                Finding(
                    finding_id=make_finding_id(
                        method=METHOD,
                        method_version=METHOD_VERSION,
                        attack_class=test["attack_class"],
                        asset=asset,
                        discriminator=("contributor_rate",),
                    ),
                    observed_at=utc_now_iso(),
                    asset=asset,
                    contributor=test["contributor"],
                    category=Category.DATA,
                    attack_class=test["attack_class"],
                    title=(
                        f"Contributor '{test['contributor']}' is over-represented in "
                        f"{test['attack_class'].replace('_', ' ')} findings: "
                        f"{test['k']}/{test['n']} samples ({rate:.1%}) vs "
                        f"{test['p0']:.1%} across the rest of the cohort"
                    ),
                    severity=severity,
                    confidence=round(float(confidence), 4),
                    confidence_basis=ConfidenceBasis.STATISTICAL,
                    evidence=(
                        EvidenceItem(
                            kind="contributor_rate_comparison",
                            statement=(
                                f"{test['k']} of {test['n']} samples from "
                                f"'{test['contributor']}' were flagged for "
                                f"{test['attack_class']} ({rate:.2%}). The rest of the "
                                f"cohort was flagged in {test['others_k']} of "
                                f"{test['others_n']} samples ({test['p0']:.2%}), a rate "
                                f"ratio of {ratio:.1f}x."
                            ),
                            observation={
                                "contributor": test["contributor"],
                                "attack_class": test["attack_class"],
                                "flagged": test["k"],
                                "samples": test["n"],
                                "rate": rate,
                                "cohort_flagged": test["others_k"],
                                "cohort_samples": test["others_n"],
                                "cohort_rate": test["p0"],
                                "rate_ratio": ratio,
                                "baseline": (
                                    "leave-one-out cohort" if test["has_cohort"]
                                    else "fallback: no other contributor exists"
                                ),
                            },
                            refs=tuple(
                                sorted({f.asset.id for f in child_findings})[:50]
                            ),
                        ),
                        EvidenceItem(
                            kind="binomial_test",
                            statement=(
                                f"One-sided binomial test of H0: rate <= {test['p0']:.4f} "
                                f"gives p = {test['p_value']:.3e}; q = {q:.3e} after "
                                f"Benjamini-Hochberg over {len(tests)} tests "
                                f"(alpha = {self.cfg.alpha})."
                            ),
                            observation={
                                "successes": test["k"],
                                "trials": test["n"],
                                "null_rate": test["p0"],
                                "p_value": test["p_value"],
                                "q_value": q,
                                "alpha": self.cfg.alpha,
                                "n_tests": len(tests),
                                "correction": "benjamini_hochberg",
                            },
                            refs=(),
                        ),
                        EvidenceItem(
                            kind="evidence_lineage",
                            statement=(
                                f"Derived from {len(child_findings)} sample-level "
                                f"finding(s) with mean confidence "
                                f"{mean_child_confidence:.3f} and maximum severity "
                                f"{max_child_severity.value}. Contributor confidence is "
                                "the minimum of that mean and the statistical "
                                "confidence, so weak evidence cannot be amplified by "
                                "repetition."
                            ),
                            observation={
                                "child_finding_ids": [f.finding_id for f in child_findings][:100],
                                "child_count": len(child_findings),
                                "mean_child_confidence": mean_child_confidence,
                                "statistical_confidence": 1.0 - q,
                                "max_child_severity": max_child_severity.value,
                            },
                            refs=tuple(f.finding_id for f in child_findings[:100]),
                        ),
                        EvidenceItem(
                            kind="severity_rationale",
                            statement=rationale,
                            observation={
                                "flagged": test["k"],
                                "rate_ratio": ratio,
                                "max_child_severity": max_child_severity.value,
                            },
                            refs=(),
                        ),
                    ),
                    method=METHOD,
                    method_version=METHOD_VERSION,
                    assumptions=(
                        "contributor attribution is correct; see the report's "
                        "attribution section for how it was resolved",
                        "absent manipulation, contributors are exchangeable and flag "
                        "at comparable rates for a given attack class",
                    ),
                    limitations=(
                        "inherits every limitation of the detectors that produced the "
                        "underlying sample findings",
                        "a contributor whose data is uniformly affected has no clean "
                        "portion to contrast against and may not stand out",
                        "over-representation is evidence of a different data-generating "
                        "process, not proof of intent",
                    ),
                    coverage=coverage,
                    disposition=decision.disposition,
                    disposition_rule=decision.rule_id,
                )
            )

        summary.sort(key=lambda s: (-s["rate_ratio"], s["contributor"], s["attack_class"]))
        return out_findings, summary


def _severity(
    count: int, ratio: float, rate: float, max_child: Severity
) -> tuple[Severity, str]:
    """Contributor severity never exceeds the worst underlying sample severity.

    Aggregation concentrates evidence; it does not create a worse threat than
    the evidence describes.
    """
    if count >= 15 and ratio >= 5:
        proposed = Severity.HIGH
        rationale = (
            f"{count} affected samples at {_format_ratio(ratio)}: a systematic "
            "difference in this contributor's data, not scattered noise"
        )
    elif count >= 5 and ratio >= 3:
        proposed = Severity.MEDIUM
        rationale = f"{count} affected samples at {_format_ratio(ratio)}"
    else:
        proposed = Severity.LOW
        rationale = (
            "statistically elevated but small in absolute terms; worth a look, "
            "not worth an action on its own"
        )
    if SEVERITY_ORDER[proposed] > SEVERITY_ORDER[max_child]:
        return (
            max_child,
            rationale
            + f"; capped at the maximum underlying sample severity ({max_child.value})",
        )
    return proposed, rationale


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
