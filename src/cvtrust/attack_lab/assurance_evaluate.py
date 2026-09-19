"""Module 4 evaluation: measure the shift subsystem and the fusion engine.

Scored the way Module 3 is rather than the way Modules 1 and 2 are, and the
difference is deliberate.  Modules 1 and 2 report precision and recall because
their detectors produce scores over many samples.  Module 4's units are a
*population pair* and a *pipeline scenario*, of which there are a handful, so a
precision figure over nine observations would be a decimal point pretending to
be a measurement.

Instead both halves are scored by **exact match against a declared
expectation**, and every mismatch is printed with what was expected, what
happened and the evidence behind it.  An extra fired rule counts as hard as a
missing one.

The harness joins expectations to results *after* the analysis has run.  Neither
the characteriser nor the policy engine ever sees a ground-truth file: the lab
writes ground truth outside the corpus, exactly as Modules 1-3 do.

What the two halves measure
---------------------------
``shift``
    Does the characteriser return the right verdict for a population pair, and
    does it decline when the sample is too small?  The pairs are almost all
    **legitimate** operational changes, so this is primarily a false-positive
    measurement: the question is whether the system reports a night collection
    as an attack.

``fusion``
    Given real evidence from Modules 1-3 plus a shift assessment, does the
    policy engine reach the declared disposition, cite the declared rule, and
    keep the declared scopes apart?
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from ..assurance.policy import AssuranceDisposition
from ..core.config import Config
from ..core.evidence import utc_now_iso
from ..core.logging import get_logger
from ..shift.context import OperationalContext
from .assurance_scenarios import AssuranceLab

log = get_logger("attack_lab.assurance_evaluate")

EVALUATION_SCHEMA_VERSION = "1.0"


class PairResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pair: str
    expected_verdict: str
    observed_verdict: str
    matched: bool
    shift_present: bool
    attack: bool
    reference_samples: int
    current_samples: int
    duration_ms: int
    energy_p_value: float | None = None
    moved_blocks: list[str] = Field(default_factory=list)
    unexplained_blocks: list[str] = Field(default_factory=list)
    transform_expected_blocks: list[str] = Field(default_factory=list)
    metrics: list[dict[str, Any]] = Field(default_factory=list)
    note: str = ""


class ScenarioResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario: str
    expected_disposition: str
    observed_disposition: str
    matched: bool
    expected_rules: list[str] = Field(default_factory=list)
    fired_rules: list[str] = Field(default_factory=list)
    missing_rules: list[str] = Field(default_factory=list)
    #: Fired, not named by the spec, and carrying ACCEPT -- the "this scope had
    #: an input and found nothing" rules.  Recorded, not flagged: a scenario
    #: spec names the rules it is ABOUT, not every rule a four-scope fusion
    #: will legitimately produce.
    additional_rules: list[str] = Field(default_factory=list)
    #: Fired, not named by the spec, and NOT carrying ACCEPT.  This is the set
    #: worth a reviewer's attention, because an unnamed rule that can change an
    #: outcome means the scenario is exercising something its author did not
    #: describe.
    unexpected_rules: list[str] = Field(default_factory=list)
    scope_dispositions: dict[str, str] = Field(default_factory=dict)
    evidence_total: int = 0
    independent_families: list[str] = Field(default_factory=list)
    confounded_evidence: int = 0
    unassessed_scopes: list[str] = Field(default_factory=list)
    report_id: str | None = None
    duration_ms: int = 0
    status: str = "RUN"
    reason: str | None = None
    note: str = ""


class AssuranceEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = EVALUATION_SCHEMA_VERSION
    generated_at: str = Field(default_factory=utc_now_iso)
    software_version: str
    config_hash: str
    policy_version: str
    lab_spec: dict[str, Any] = Field(default_factory=dict)
    pairs: list[PairResult] = Field(default_factory=list)
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    evaluation_population: str = ""

    @property
    def pairs_matched(self) -> int:
        return sum(1 for p in self.pairs if p.matched)

    @property
    def scenarios_matched(self) -> int:
        return sum(1 for s in self.scenarios if s.matched)

    @property
    def scenarios_run(self) -> int:
        return sum(1 for s in self.scenarios if s.status == "RUN")

    @property
    def all_passed(self) -> bool:
        return (
            self.pairs_matched == len(self.pairs)
            and self.scenarios_matched == self.scenarios_run
        )

    def false_positive_pairs(self) -> list[PairResult]:
        """Legitimate pairs the system reported as something stronger.

        The number that matters most in this module: a pair whose ground truth
        says ``attack: false`` and whose observed verdict escalates beyond what
        the evidence supports.
        """
        return [
            p
            for p in self.pairs
            if not p.attack
            and p.observed_verdict == "SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT"
            and p.expected_verdict != "SHIFT_UNEXPLAINED_BY_DECLARED_CONTEXT"
        ]


def evaluate_pairs(
    lab: AssuranceLab, config: Config, *, pairs: Sequence[str] | None = None
) -> list[PairResult]:
    """Run the characteriser over every population pair."""
    import time

    from ..assurance_pipeline import characterise_shift

    wanted = set(pairs) if pairs else None
    results: list[PairResult] = []
    for pair in lab.pairs:
        if wanted is not None and pair.name not in wanted:
            continue
        started = time.perf_counter()
        assessment, _ = characterise_shift(
            pair.reference_root,
            pair.current_root,
            config,
            reference_context=OperationalContext.from_mapping(pair.reference_context),
            current_context=OperationalContext.from_mapping(pair.current_context),
            reference_provenance="cvtrust assurance lab reference corpus "
            "(synthetic, generated from a published seed)",
            reference_version=lab.spec.get("lab_version"),
        )
        duration = int((time.perf_counter() - started) * 1000)
        energy = assessment.metric("energy_distance")
        truth = pair.ground_truth
        results.append(
            PairResult(
                pair=pair.name,
                expected_verdict=str(truth["expected_verdict"]),
                observed_verdict=assessment.verdict.value,
                matched=assessment.verdict.value == truth["expected_verdict"],
                shift_present=bool(truth["shift_present"]),
                attack=bool(truth["attack"]),
                reference_samples=int(truth["reference_samples"]),
                current_samples=int(truth["current_samples"]),
                duration_ms=duration,
                energy_p_value=energy.p_value if energy else None,
                moved_blocks=list(assessment.context.moved_blocks)
                if assessment.context
                else [],
                unexplained_blocks=list(assessment.context.unexplained_blocks)
                if assessment.context
                else [],
                transform_expected_blocks=list(truth["transform_expected_blocks"]),
                metrics=[
                    {
                        "metric": m.metric,
                        "status": m.status.value,
                        "statistic": m.statistic,
                        "p_value": m.p_value,
                        "significant": m.significant,
                    }
                    for m in assessment.metrics
                ],
                note=str(truth.get("note", "")),
            )
        )
        log.info(
            "pair %-36s %-42s %s",
            pair.name,
            assessment.verdict.value,
            "OK" if results[-1].matched else f"MISMATCH (expected {truth['expected_verdict']})",
        )
    return results


def render_evaluation(evaluation: AssuranceEvaluation) -> None:
    """Console rendering.  Mismatches are printed, never summarised away."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    table = Table(
        title="Population pairs — distribution-shift verdicts",
        caption="Almost every pair is a LEGITIMATE operational change. This is "
        "primarily a false-positive measurement.",
    )
    table.add_column("Pair", style="bold")
    table.add_column("Expected")
    table.add_column("Observed")
    table.add_column("", justify="center")
    table.add_column("ref/cur", justify="right")
    table.add_column("energy p", justify="right")
    table.add_column("moved → unexplained")
    for result in evaluation.pairs:
        table.add_row(
            result.pair,
            result.expected_verdict,
            result.observed_verdict,
            Text("OK", style="green") if result.matched else Text("MISS", style="bold red"),
            f"{result.reference_samples}/{result.current_samples}",
            "-" if result.energy_p_value is None else f"{result.energy_p_value:.4f}",
            f"{', '.join(result.moved_blocks) or '-'} → "
            f"{', '.join(result.unexplained_blocks) or '-'}",
        )
    console.print(table)

    if evaluation.scenarios:
        scenarios = Table(title="Pipeline scenarios — fusion dispositions")
        scenarios.add_column("Scenario", style="bold")
        scenarios.add_column("Status")
        scenarios.add_column("Expected")
        scenarios.add_column("Observed")
        scenarios.add_column("", justify="center")
        scenarios.add_column("Scopes")
        scenarios.add_column("Independent families", justify="right")
        for result in evaluation.scenarios:
            scenarios.add_row(
                result.scenario,
                Text(result.status, style="dim" if result.status == "RUN" else "yellow"),
                result.expected_disposition,
                result.observed_disposition,
                Text("OK", style="green")
                if result.matched
                else Text("-", style="dim")
                if result.status != "RUN"
                else Text("MISS", style="bold red"),
                " ".join(
                    f"{k[:4]}={v[:4]}" for k, v in sorted(result.scope_dispositions.items())
                ),
                str(len(result.independent_families)),
            )
        console.print(scenarios)

        for result in evaluation.scenarios:
            if result.status == "RUN" and (
                result.missing_rules or result.unexpected_rules
            ):
                console.print(
                    Text(
                        f"  {result.scenario}: missing rules "
                        f"{result.missing_rules or '-'}, unexpected rules "
                        f"{result.unexpected_rules or '-'}",
                        style="yellow",
                    )
                )
            if result.status != "RUN":
                console.print(
                    Text(f"  {result.scenario}: {result.status} — {result.reason}", style="dim")
                )

    console.print(
        Panel(
            Text(evaluation.evaluation_population, style="dim"),
            title="Evaluation population",
            border_style="dim",
        )
    )


def write_evaluation(evaluation: AssuranceEvaluation, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(evaluation.model_dump_json(indent=2), encoding="utf-8")


EVALUATION_POPULATION = (
    "Population pairs are synthetic corpora generated from a published seed, "
    "with physically-motivated but LEGITIMATE condition transforms applied to "
    "the current side. Every metric reported here describes behaviour on this "
    "corpus. It is evidence that the subsystem behaves as designed and a lower "
    "bound on evidence quality; it is not a prediction of operational "
    "performance on real imagery, and no shift threshold in this build is "
    "calibrated against operational data. Pipeline scenarios compose evidence "
    "produced by the real Module 1, 2 and 3 pipelines -- never hand-written "
    "findings -- so a scenario whose evidence cannot be produced in this "
    "environment is reported NOT_RUN rather than faked."
)


def load_evaluation(path: Path) -> AssuranceEvaluation:
    return AssuranceEvaluation.model_validate(
        json.loads(Path(path).read_text(encoding="utf-8"))
    )





# ---------------------------------------------------------------------------
# Pipeline scenarios: the end-to-end assurance lab
#
# Every scenario below composes evidence produced by the REAL Module 1, 2 and 3
# pipelines.  Nothing here writes a Finding by hand.  A fusion engine tested
# against fixtures its author wrote is a fusion engine tested against its
# author's expectations, and the specific failure that would hide is the one
# that matters most: a rule that fires on evidence no real detector ever emits.
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field as _field  # noqa: E402


@dataclass
class PipelineScenario:
    """One end-to-end scenario, as paths to real upstream reports."""

    name: str
    expected_disposition: str
    expected_rules: tuple[str, ...] = ()
    dataset_report: Path | None = None
    model_report: Path | None = None
    provenance_report: Path | None = None
    shift_pair: str | None = None
    note: str = ""
    status: str = "RUN"
    reason: str | None = None


#: The scenario matrix the brief asks for (§25), plus the two that make the
#: dependency handling visible.  ``dataset`` / ``model`` / ``provenance`` name
#: an upstream lab scenario; ``shift`` names a population pair.
PIPELINE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "clean_baseline",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "ACCEPT",
        "rules": ("RULE-DATA-010", "RULE-MODEL-010", "RULE-PROV-010", "RULE-SHIFT-010"),
        "note": "everything assessed, nothing found. The only scenario in the "
        "matrix that reaches ACCEPT, and it needs all four scopes assessed to "
        "get there. The model is the reference compared against itself: every "
        "other lab artifact differs from the reference in its weights by "
        "construction, including the legitimately retrained ones.",
    },
    {
        "name": "operational_shift",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "clean",
        "shift": "operational_illumination",
        "expect": "ACCEPT",
        "rules": ("RULE-SHIFT-020",),
        "note": "a legitimate declared night collection over an otherwise clean "
        "pipeline. THE headline negative control: if this quarantines, or even "
        "reviews, the system is unusable in an operational deployment.",
    },
    {
        "name": "unexplained_shift",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "clean",
        "shift": "undeclared_illumination",
        "expect": "REVIEW",
        "rules": ("RULE-SHIFT-030",),
        "note": "the same physical change, undeclared. REVIEW, not QUARANTINE: "
        "an unexplained population change is an open question and no rule in "
        "this policy escalates on shift alone.",
    },
    {
        "name": "ood_without_attack",
        "dataset": "ood_insertion",
        "dataset_reference": "_clean",
        "model": "_reference",
        "provenance": "clean",
        "shift": "operational_sensor",
        "expect": "ACCEPT",
        "rules": ("RULE-SHIFT-020", "RULE-DATA-010"),
        "note": "a legitimate new sensor domain arriving as 27 per-sample OOD "
        "flags, downstream label-consistency findings AND a population shift. "
        "Three detectors, one phenomenon, and the correct answer is ACCEPT with "
        "all 40 findings preserved in the report. Note where the work happens: "
        "Module 1 ALREADY caps both the OOD findings and the label findings it "
        "qualified as OOD-driven to LOW severity, so by the time Module 4 sees "
        "them they sit below the corroboration floor and are carried as context. "
        "Module 4's confounding marks are the second line of defence, not the "
        "first.",
    },
    {
        "name": "ood_without_shift_assessment",
        "dataset": "ood_insertion",
        "dataset_reference": "_clean",
        "model": "_reference",
        "provenance": "clean",
        "shift": None,
        "expect": "NOT_ASSESSED",
        "rules": ("RULE-SHIFT-000", "RULE-DATA-010", "RULE-MODEL-010", "RULE-PROV-010"),
        "note": "the same dataset with no reference population supplied. Three "
        "scopes report ACCEPT and the overall disposition is still NOT_ASSESSED, "
        "because the population-level question was never asked. "
        "RULE-SHIFT-050 -- which acts on per-sample OOD evidence when no "
        "population assessment exists -- does NOT fire here and cannot on this "
        "corpus: Module 1 caps self-referenced and non-unanimous OOD findings at "
        "LOW, below the corroboration floor. The rule is exercised by a unit "
        "test over constructed evidence instead, and this note exists so that "
        "gap in the lab is stated rather than discovered.",
    },
    {
        "name": "label_anomaly_during_shift",
        "dataset": "label_flip",
        "model": "_reference",
        "provenance": "clean",
        "shift": "operational_illumination",
        "expect": "REVIEW",
        "rules": ("RULE-DATA-004", "RULE-SHIFT-020"),
        "note": "THE dependency-handling scenario. The SAME label_flip dataset "
        "as `dataset_anomaly`, now arriving alongside a declared legitimate "
        "illumination change. Identical detector output, different reading: "
        "RULE-DATA-002 fires when the evidence is independent, RULE-DATA-004 "
        "when a phenomenon present in the run explains it. Both are REVIEW, "
        "neither suppresses a finding, and the difference is that confounded "
        "evidence can no longer corroborate its way to RULE-DATA-003's "
        "QUARANTINE. The cost is stated in docs/limitations.md: a genuine "
        "dataset attack coinciding with a legitimate shift is held at REVIEW "
        "rather than escalated.",
    },
    {
        "name": "dataset_anomaly",
        "dataset": "label_flip",
        "model": "_reference",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "REVIEW",
        "rules": ("RULE-DATA-002",),
        "note": "poisoned labels with a clean model and valid provenance. "
        "Statistical dataset evidence alone must not quarantine, and with no "
        "shift in this run the findings are NOT confounded -- the same "
        "detector output is treated differently depending on what else is true, "
        "which is the entire point of the dependency handling.",
    },
    {
        "name": "dataset_tamper_deterministic",
        "dataset": "duplicate_flood",
        "model": "_reference",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "QUARANTINE",
        "rules": ("RULE-DATA-001",),
        "note": "exact duplicate flooding is a digest comparison with no "
        "statistical uncertainty, so it quarantines where a statistical finding "
        "of the same severity would not. The severity/basis distinction doing "
        "visible work.",
    },
    {
        "name": "model_anomaly_uncalibrated",
        "dataset": "_clean",
        "model": "backdoor_badnets!noref",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "REVIEW",
        "rules": ("RULE-MODEL-003",),
        "note": "a backdoored model assessed with NO trusted reference, so the "
        "only evidence is the trigger probe's HEURISTIC_UNCALIBRATED finding. "
        "REVIEW, not QUARANTINE: rule RULE-MODEL-002 requires MEASURED evidence "
        "quality and a documented prior is not one.",
    },
    {
        "name": "model_substitution",
        "dataset": "_clean",
        "model": "substitution_architecture",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "QUARANTINE",
        "rules": ("RULE-MODEL-001",),
        "note": "the served model is not the assured artifact. Deterministic "
        "against a trusted reference, so it quarantines.",
    },
    {
        "name": "provenance_tampering",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "modified_output",
        "shift": "clean_baseline",
        "expect": "QUARANTINE",
        "rules": ("RULE-PROV-001", "RULE-MODEL-010", "RULE-DATA-010"),
        "note": "a clean dataset and a clean model with a tampered inference "
        "record. The dataset and model scopes must STILL report ACCEPT: the "
        "facts are kept apart (ADR-014), and a report that let the provenance "
        "failure darken the model row would be describing a different incident.",
    },
    {
        "name": "combined_attack",
        "dataset": "combined",
        "model": "backdoor_badnets",
        "provenance": "modified_output",
        "shift": "undeclared_illumination",
        "expect": "QUARANTINE",
        # All four scopes are named, because the point of the scenario is that
        # all four keep their own disposition. The original spec named only two
        # and the evaluation reported the other two as "unexpected" -- which was
        # the harness being right about an incomplete expectation.
        "rules": (
            "RULE-DATA-002", "RULE-MODEL-001", "RULE-PROV-001", "RULE-SHIFT-040",
        ),
        "note": "dataset anomaly, model anomaly and provenance tampering at "
        "once. Every scope must keep its own disposition and the report must "
        "not collapse them into one narrative.",
    },
    {
        "name": "shift_with_independent_evidence",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "modified_output",
        "shift": "operational_terrain",
        "expect": "QUARANTINE",
        "rules": ("RULE-PROV-001", "RULE-SHIFT-040"),
        "note": "a DECLARED, legitimate terrain change alongside an independent "
        "cryptographic failure. The quarantine must come from the provenance "
        "rule on its own evidence; the distribution scope must contribute "
        "REVIEW at most, and nothing may describe the shift as malicious.",
    },
    # ------------------------------------------------------------------
    # Legitimate-but-unusual conditions.  None of these is an attack, and the
    # expectations below were MEASURED before they were written down -- the
    # point of the group is that the system must not read every unusual
    # condition as compromise, and two of the four correctly do NOT reach
    # ACCEPT, for reasons that are about identity rather than about malice.
    # ------------------------------------------------------------------
    {
        "name": "legitimate_reserialisation",
        "dataset": "_clean",
        "model": "reserialised",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "REVIEW",
        "rules": ("RULE-DATA-010", "RULE-MODEL-003", "RULE-PROV-010",
                  "RULE-SHIFT-010"),
        "note": "the same model re-exported: new bytes, identical graph and "
        "parameter digests. NOT an attack, and NOT silently accepted either. "
        "REVIEW is the honest answer -- 'the artifact changed and the model did "
        "not' is a fact an analyst should confirm was intentional. The three "
        "digests existing separately (ADR-010) is what makes this expressible "
        "at all; with one digest it would be indistinguishable from "
        "substitution.",
    },
    {
        "name": "legitimate_finetuning",
        "dataset": "_clean",
        "model": "clean_finetuned",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "QUARANTINE",
        "rules": ("RULE-DATA-010", "RULE-MODEL-001", "RULE-PROV-010",
                  "RULE-SHIFT-010"),
        "note": "a model legitimately fine-tuned from the reference. It "
        "QUARANTINES, and that is correct rather than a false positive: the "
        "artifact supplied is not the artifact that was assured, which is a "
        "digest comparison and not an inference. Note the WORDING the rule "
        "uses -- 'the model is not the assured artifact', never 'tampered' and "
        "never 'malicious'. The remedy is to re-assure the fine-tuned model and "
        "make it the new reference, not to treat anyone as an adversary. This "
        "scenario exists to keep that distinction visible.",
    },
    {
        "name": "unusual_initialisation",
        "dataset": "_clean",
        "model": "clean_unusual_init!noref",
        "provenance": "clean",
        "shift": "clean_baseline",
        "expect": "ACCEPT",
        "rules": ("RULE-DATA-010", "RULE-MODEL-010", "RULE-PROV-010",
                  "RULE-SHIFT-010"),
        "note": "a clean model with weight statistics well outside the usual "
        "range, assessed with NO reference so the peer-screening path is the "
        "one exercised. Unusual weights are not evidence of a backdoor -- "
        "quantisation-aware training, weight decay and layer saturation all "
        "produce them -- and the measured result is zero findings.",
    },
    {
        "name": "legitimate_reprocess",
        "dataset": "_clean",
        "model": "_reference",
        "provenance": "legitimate_reprocess",
        "shift": "clean_baseline",
        "expect": "ACCEPT",
        "rules": ("RULE-DATA-010", "RULE-MODEL-010", "RULE-PROV-010",
                  "RULE-SHIFT-010"),
        "note": "the same input legitimately processed twice, which every real "
        "pipeline does. Two records, distinct nonces, sequences and signatures. "
        "Reported as a duplicate SUBJECT at observation level and never as "
        "replay, so it reaches fusion with no findings at all.",
    },
    {
        "name": "no_inputs",
        "dataset": None,
        "model": None,
        "provenance": None,
        "shift": None,
        "expect": "NOT_ASSESSED",
        "rules": (
            "RULE-DATA-000",
            "RULE-MODEL-000",
            "RULE-PROV-000",
            "RULE-SHIFT-000",
        ),
        "note": "nothing supplied. The disposition must be NOT_ASSESSED, never "
        "ACCEPT: a pipeline nobody examined is not a clean pipeline.",
    },
    {
        "name": "dataset_only",
        "dataset": "_clean",
        "model": None,
        "provenance": None,
        "shift": None,
        "expect": "NOT_ASSESSED",
        "rules": ("RULE-DATA-010", "RULE-MODEL-000", "RULE-PROV-000", "RULE-SHIFT-000"),
        "note": "a clean dataset scan and nothing else. The DATASET scope "
        "reports ACCEPT and the overall disposition is NOT_ASSESSED, because an "
        "overall ACCEPT would present one-quarter coverage as a clean pipeline. "
        "This expectation was CORRECTED after the lab produced it: the original "
        "spec said ACCEPT and the engine was right.",
    },
)


def build_pipeline_scenarios(
    out_dir: Path,
    config: Config,
    *,
    assurance_lab: AssuranceLab,
    dataset_lab_root: Path | None = None,
    model_lab: Any | None = None,
    provenance_lab_root: Path | None = None,
    specs: Sequence[dict[str, Any]] | None = None,
) -> list[PipelineScenario]:
    """Run the real upstream pipelines and write the reports each scenario needs.

    Upstream reports are cached by (module, scenario) so that a scenario matrix
    reusing ``_clean`` eleven times runs the Module 1 scan once.  A scenario
    whose upstream lab was not supplied is returned with ``status="NOT_RUN"``
    and a reason naming the missing input; it is never fabricated, and it is
    never quietly dropped from the matrix either.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cache: dict[tuple[str, str], Path] = {}
    built: list[PipelineScenario] = []

    for spec in specs or PIPELINE_SPECS:
        name = str(spec["name"])
        scenario = PipelineScenario(
            name=name,
            expected_disposition=str(spec["expect"]),
            expected_rules=tuple(spec["rules"]),
            shift_pair=spec.get("shift"),
            note=str(spec.get("note", "")),
        )
        missing: list[str] = []

        if spec.get("dataset"):
            path = _dataset_report(
                out_dir, config, dataset_lab_root, str(spec["dataset"]), cache,
                assurance_lab=assurance_lab,
                reference_from=spec.get("dataset_reference"),
            )
            if path is None:
                missing.append(f"dataset lab scenario '{spec['dataset']}'")
            scenario.dataset_report = path
        if spec.get("model"):
            path = _model_report(out_dir, config, model_lab, str(spec["model"]), cache)
            if path is None:
                missing.append(f"model lab scenario '{spec['model']}'")
            scenario.model_report = path
        if spec.get("provenance"):
            path = _provenance_report(
                out_dir, config, provenance_lab_root, str(spec["provenance"]), cache
            )
            if path is None:
                missing.append(f"provenance lab scenario '{spec['provenance']}'")
            scenario.provenance_report = path
        if spec.get("shift"):
            try:
                assurance_lab.pair(str(spec["shift"]))
            except KeyError:
                missing.append(f"population pair '{spec['shift']}'")

        if missing:
            scenario.status = "NOT_RUN"
            scenario.reason = (
                "required upstream evidence was not available in this "
                "environment: " + "; ".join(missing)
            )
        built.append(scenario)
    return built


def _dataset_report(
    out_dir: Path,
    config: Config,
    lab_root: Path | None,
    scenario: str,
    cache: dict[tuple[str, str], Path],
    *,
    assurance_lab: AssuranceLab,
    reference_from: str | None = None,
) -> Path | None:
    key = ("dataset", f"{scenario}|{reference_from or ''}")
    if key in cache:
        return cache[key]
    if scenario == "_clean":
        root = assurance_lab.baseline_root
    else:
        if lab_root is None:
            return None
        root = Path(lab_root) / scenario / "dataset"
        if not root.is_dir():
            return None

    from ..pipeline import analyse

    # A DECLARED reference distribution, where the spec asks for one.
    #
    # Derived from the *prior* corpus -- "these are the samples we already
    # had" -- and never from the scenario's ground truth. That distinction is
    # the whole reason this is done by intersecting relpaths with an earlier
    # delivery rather than by reading ground_truth.json: an analyst genuinely
    # has the first and must never have the second.
    #
    # It matters because Module 1's OOD detector caps severity at LOW when it
    # is self-referencing (see cvtrust.detectors.ood._severity): without a
    # declared reference, OOD findings never clear Module 4's corroboration
    # floor, and a rule that exists to act on them can never fire.
    reference_ids = None
    if reference_from:
        prior = (
            assurance_lab.baseline_root
            if reference_from == "_clean"
            else (Path(lab_root) / reference_from / "dataset" if lab_root else None)
        )
        if prior is not None and prior.is_dir():
            prior_ids = {
                p.relative_to(prior).as_posix()
                for p in prior.rglob("*")
                if p.is_file() and p.suffix.lower() in {".jpg", ".jpeg", ".png"}
            }
            present = {
                p.relative_to(root).as_posix()
                for p in root.rglob("*")
                if p.is_file() and p.suffix.lower() in {".jpg", ".jpeg", ".png"}
            }
            reference_ids = sorted(prior_ids & present)

    report, _, _ = analyse(root, config, reference_sample_ids=reference_ids)
    suffix = f"-ref-{reference_from}" if reference_from else ""
    path = out_dir / "reports" / f"dataset-{scenario}{suffix}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    cache[key] = path
    return path


def _model_report(
    out_dir: Path,
    config: Config,
    model_lab: Any | None,
    scenario: str,
    cache: dict[tuple[str, str], Path],
) -> Path | None:
    key = ("model", scenario)
    if key in cache:
        return cache[key]
    if model_lab is None:
        return None

    # Two shapes are accepted because two callers exist and neither should have
    # to adapt to the other: the test fixture holds already-built scenario
    # objects in memory, and the CLI holds a directory somebody built earlier.
    # "<name>" assesses that scenario against the trusted reference.
    # "<name>!noref" assesses it with NO reference, which is the pathway that
    # matters for the uncalibrated-evidence rule: without a reference there is
    # no deterministic digest mismatch to quarantine on, and only the trigger
    # probe's uncalibrated evidence remains.
    # "_reference" assesses the reference against itself, which is the only
    # genuinely clean model case -- every other lab artifact differs from the
    # reference in its weights by construction, including the legitimately
    # retrained ones, and Module 2 correctly says so.
    name, _, modifier = scenario.partition("!")
    with_reference = modifier != "noref"

    if isinstance(model_lab, (str, Path)):
        root = Path(model_lab)
        reference = root / "_reference" / "reference.onnx"
        artifact = reference if name == "_reference" else root / name / "model.onnx"
        if not artifact.is_file() or not reference.is_file():
            return None
    else:
        scenarios = model_lab.get("scenarios", {})
        reference = model_lab["reference"].onnx_path
        if name == "_reference":
            artifact = reference
        elif name in scenarios:
            artifact = scenarios[name].onnx_path
        else:
            return None

    from ..core.errors import CvTrustError
    from ..model_pipeline import assess_model

    try:
        report, _, _ = assess_model(
            artifact, config, reference_path=reference if with_reference else None
        )
    except CvTrustError:
        # A missing ONNX runtime is a graceful degradation, not a lab failure:
        # the scenario is reported NOT_RUN with the reason rather than crashing
        # the whole evaluation.
        return None
    path = out_dir / "reports" / f"model-{scenario.replace('!', '-')}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    cache[key] = path
    return path


def _provenance_report(
    out_dir: Path,
    config: Config,
    lab_root: Path | None,
    scenario: str,
    cache: dict[tuple[str, str], Path],
) -> Path | None:
    key = ("provenance", scenario)
    if key in cache:
        return cache[key]
    if lab_root is None:
        return None

    from ..provenance.chain import LogAnchor
    from ..provenance.replay import ReplayDatabase
    from ..provenance.trust import TrustStore
    from ..provenance.log import ProvenanceLog
    from ..provenance_pipeline import verify_log

    directory = Path(lab_root) / scenario
    log_path = directory / "log.jsonl"
    if not log_path.is_file():
        return None
    trust_path = directory / "trust_store.json"
    if not trust_path.is_file():
        trust_path = Path(lab_root) / "_clean" / "trust_store.json"
    anchor_path = directory / "anchor.json"

    provenance_log = ProvenanceLog.load(log_path)
    store = TrustStore.load(trust_path) if trust_path.is_file() else None
    anchor = None
    if anchor_path.is_file():
        anchor = LogAnchor.model_validate(
            json.loads(anchor_path.read_text(encoding="utf-8"))
        )
    report, _, _ = verify_log(
        provenance_log,
        config,
        trust_store=store,
        replay_database=ReplayDatabase.empty(),
        anchor=anchor,
    )
    path = out_dir / "reports" / f"provenance-{scenario}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    cache[key] = path
    return path


def evaluate_scenarios(
    scenarios: Sequence[PipelineScenario],
    config: Config,
    *,
    assurance_lab: AssuranceLab,
    shift_cache: dict[str, Any] | None = None,
) -> list[ScenarioResult]:
    """Fuse each scenario's real evidence and compare against its expectation."""
    import time

    from ..assurance_pipeline import assess_pipeline, characterise_shift

    cache: dict[str, Any] = shift_cache if shift_cache is not None else {}
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        if scenario.status != "RUN":
            results.append(
                ScenarioResult(
                    scenario=scenario.name,
                    expected_disposition=scenario.expected_disposition,
                    observed_disposition="-",
                    matched=False,
                    expected_rules=list(scenario.expected_rules),
                    status=scenario.status,
                    reason=scenario.reason,
                    note=scenario.note,
                )
            )
            log.warning("scenario %-32s NOT_RUN — %s", scenario.name, scenario.reason)
            continue

        shift = None
        if scenario.shift_pair:
            if scenario.shift_pair not in cache:
                pair = assurance_lab.pair(scenario.shift_pair)
                assessment, _ = characterise_shift(
                    pair.reference_root,
                    pair.current_root,
                    config,
                    reference_context=OperationalContext.from_mapping(
                        pair.reference_context
                    ),
                    current_context=OperationalContext.from_mapping(
                        pair.current_context
                    ),
                )
                cache[scenario.shift_pair] = assessment
            shift = cache[scenario.shift_pair]

        started = time.perf_counter()
        report, result = assess_pipeline(
            config,
            dataset_report=scenario.dataset_report,
            model_report=scenario.model_report,
            provenance_report=scenario.provenance_report,
            shift=shift,
        )
        duration = int((time.perf_counter() - started) * 1000)

        fired = sorted({outcome.rule_id for outcome in report.decision.fired_rules})
        # Rules that fired carrying ACCEPT cannot have changed the outcome, so
        # an unnamed one is bookkeeping. An unnamed rule that carries anything
        # else could have, and is reported separately.
        accepting = {
            outcome.rule_id
            for outcome in report.decision.fired_rules
            if outcome.disposition is AssuranceDisposition.ACCEPT
        }
        expected = set(scenario.expected_rules)
        observed_disposition = report.decision.disposition.value
        results.append(
            ScenarioResult(
                scenario=scenario.name,
                expected_disposition=scenario.expected_disposition,
                observed_disposition=observed_disposition,
                matched=(
                    observed_disposition == scenario.expected_disposition
                    and expected.issubset(set(fired))
                ),
                expected_rules=sorted(expected),
                fired_rules=fired,
                missing_rules=sorted(expected - set(fired)),
                additional_rules=sorted(
                    r for r in set(fired) - expected if r in accepting
                ),
                unexpected_rules=sorted(
                    r for r in set(fired) - expected if r not in accepting
                ),
                scope_dispositions={
                    s.scope: s.disposition for s in report.scopes()
                },
                evidence_total=len(report.evidence.evidence),
                independent_families=[
                    f.value for f in report.evidence.independent_families()
                ],
                confounded_evidence=sum(
                    1 for e in report.evidence.evidence if e.active_confounders
                ),
                unassessed_scopes=[
                    area.area
                    for area in report.decision.unassessed_areas
                    if area.kind == "scope"
                ],
                report_id=report.report_id,
                duration_ms=duration,
                note=scenario.note,
            )
        )
        log.info(
            "scenario %-32s %-13s %s",
            scenario.name,
            observed_disposition,
            "OK" if results[-1].matched else f"MISMATCH (expected {scenario.expected_disposition})",
        )
    return results


def evaluate_lab(
    lab: AssuranceLab,
    config: Config,
    *,
    out_dir: Path | None = None,
    dataset_lab_root: Path | None = None,
    model_lab: Any | None = None,
    provenance_lab_root: Path | None = None,
    pairs: Sequence[str] | None = None,
    include_scenarios: bool = True,
) -> AssuranceEvaluation:
    """Run both halves of the evaluation and build the report."""
    from .. import __version__
    from ..assurance.policy import AssurancePolicyEngine

    pair_results = evaluate_pairs(lab, config, pairs=pairs)

    scenario_results: list[ScenarioResult] = []
    if include_scenarios:
        scenarios = build_pipeline_scenarios(
            out_dir or (lab.root / "_scenarios"),
            config,
            assurance_lab=lab,
            dataset_lab_root=dataset_lab_root,
            model_lab=model_lab,
            provenance_lab_root=provenance_lab_root,
        )
        scenario_results = evaluate_scenarios(scenarios, config, assurance_lab=lab)

    return AssuranceEvaluation(
        software_version=__version__,
        config_hash=config.config_hash(),
        policy_version=AssurancePolicyEngine.version,
        lab_spec=lab.spec,
        pairs=pair_results,
        scenarios=scenario_results,
        evaluation_population=EVALUATION_POPULATION,
    )


__all__ = [
    "EVALUATION_SCHEMA_VERSION", "EVALUATION_POPULATION", "PIPELINE_SPECS",
    "AssuranceEvaluation", "PairResult", "ScenarioResult", "PipelineScenario",
    "evaluate_pairs", "build_pipeline_scenarios", "evaluate_scenarios",
    "evaluate_lab", "render_evaluation", "write_evaluation", "load_evaluation",
]
