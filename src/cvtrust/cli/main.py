"""Command-line interface.

Everything the platform does is reachable from here, offline, with no service to
start.  Commands are grouped by the object they act on:

``dataset``   scan, verify, manifest
``lab``       generate the synthetic corpus, run attacks, evaluate, calibrate
``demo``      the end-to-end judge-facing demonstration
``info``      what this build supports and what it does not
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from .. import __version__
from ..core.config import Config
from ..core.errors import CvTrustError
from ..core.logging import configure_logging

app = typer.Typer(
    name="cvtrust",
    help="Trustworthy Computer Vision Integrity Assurance (SIH26228) — "
    "offline dataset forensics, Module 1.",
    no_args_is_help=True,
    add_completion=False,
)
dataset_app = typer.Typer(help="Dataset ingestion, integrity and forensics.", no_args_is_help=True)
lab_app = typer.Typer(help="Synthetic attack laboratory and evaluation.", no_args_is_help=True)
app.add_typer(dataset_app, name="dataset")
app.add_typer(lab_app, name="lab")


def _load_config(path: Optional[Path], overrides: dict | None = None) -> Config:
    config = Config.load(path)
    return config.merged(overrides) if overrides else config


def _fail(exc: Exception) -> None:
    typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=2)


@app.callback()
def _root(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Errors only."),
) -> None:
    configure_logging("DEBUG" if verbose else "ERROR" if quiet else "INFO")


@app.command()
def version() -> None:
    """Print the software version."""
    typer.echo(f"cvtrust {__version__}")


@app.command()
def info() -> None:
    """Print the coverage statement for this build: what it assesses, and what it does not."""
    from ..reporting.render import render_coverage
    from ..risk.coverage import CoverageStatement

    render_coverage(CoverageStatement.build([], (1,)))


@dataset_app.command("scan")
def dataset_scan(
    root: Path = typer.Argument(..., help="Dataset root directory."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML configuration."),
    adapter: Optional[str] = typer.Option(None, "--adapter", help="Force a dataset adapter."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the JSON report here."),
    manifest_out: Optional[Path] = typer.Option(
        None, "--manifest-out", help="Write the dataset manifest here."
    ),
    reference: Optional[Path] = typer.Option(
        None, "--reference",
        help="JSON file listing the sample ids that form the trusted reference "
             "distribution. Without it the OOD detector self-references and says so.",
    ),
    calibration: Optional[Path] = typer.Option(
        None, "--calibration", help="Calibration table from `cvtrust lab evaluate`."
    ),
    detectors: Optional[str] = typer.Option(
        None, "--detectors", help="Comma-separated subset of detectors to run."
    ),
    full: bool = typer.Option(False, "--full", help="Print every finding, not just the top ones."),
) -> None:
    """Analyse a dataset and produce an assurance report."""
    from ..pipeline import analyse
    from ..reporting.render import render_report

    try:
        cfg = _load_config(config, {"calibration_path": str(calibration)} if calibration else None)
        reference_ids = None
        if reference:
            payload = json.loads(reference.read_text(encoding="utf-8"))
            reference_ids = payload if isinstance(payload, list) else payload.get("samples", [])
        report, ctx, _ = analyse(
            root, cfg,
            adapter_name=adapter,
            reference_sample_ids=reference_ids,
            detectors=tuple(d.strip() for d in detectors.split(",")) if detectors else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_report(report, full=full)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nJSON report written to {out}", fg=typer.colors.BLUE)
    if manifest_out:
        manifest_out.parent.mkdir(parents=True, exist_ok=True)
        manifest_out.write_text(ctx.manifest.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"Manifest written to {manifest_out}", fg=typer.colors.BLUE)

    # Exit code carries the assessment so the command composes into a pipeline:
    # 0 clean, 1 review, 3 quarantine.
    raise typer.Exit(
        code={"QUARANTINE REQUIRED": 3}.get(
            report.summary.overall, 0 if report.summary.overall == "NO ACTIONABLE FINDINGS" else 1
        )
    )


@dataset_app.command("manifest")
def dataset_manifest(
    root: Path = typer.Argument(..., help="Dataset root directory."),
    out: Path = typer.Option(Path("manifest.json"), "--out", "-o"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    adapter: Optional[str] = typer.Option(None, "--adapter"),
) -> None:
    """Build and write the dataset manifest (its cryptographic identity)."""
    from ..datasets.contributors import ContributorResolver
    from ..datasets.manifest import build_manifest
    from ..pipeline import load_dataset

    try:
        cfg = _load_config(config)
        data = load_dataset(root, adapter)
        resolver = ContributorResolver(cfg.contributor, Path(root))
        manifest, _, _, issues = build_manifest(data, resolver)
    except CvTrustError as exc:
        _fail(exc)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"manifest_id  {manifest.manifest_id}", fg=typer.colors.GREEN)
    typer.echo(f"digest       {manifest.digest}")
    typer.echo(f"samples      {manifest.counts['samples']}")
    typer.echo(f"issues       {len(issues) + len(data.issues)}")
    typer.echo(f"written to   {out}")


@dataset_app.command("verify")
def dataset_verify(
    manifest_path: Path = typer.Argument(..., help="A manifest produced by `dataset manifest`."),
    root: Path = typer.Argument(..., help="Dataset root to verify against."),
) -> None:
    """Re-verify a dataset against a manifest: detects post-baseline tampering."""
    from ..datasets.manifest import DatasetManifest, verify_manifest

    try:
        manifest = DatasetManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    except Exception as exc:
        _fail(CvTrustError(f"cannot read manifest {manifest_path}: {exc}"))
        return

    result = verify_manifest(manifest, Path(root))
    ok = typer.style("PASS", fg=typer.colors.GREEN, bold=True)
    bad = typer.style("FAIL", fg=typer.colors.RED, bold=True)

    typer.echo(f"manifest self-consistency  {ok if result.manifest_self_consistent else bad}")
    if not result.manifest_self_consistent:
        typer.echo(f"  recorded digest   {result.manifest_digest}")
        typer.echo(f"  recomputed digest {result.digest_recomputed}")
        typer.secho("  the manifest file itself has been altered", fg=typer.colors.RED)

    typer.echo(f"dataset correspondence     {ok if result.dataset_matches else bad}")
    typer.echo(f"  checked  {result.checked} recorded sample(s)")
    for relpath in result.missing[:20]:
        typer.secho(f"  MISSING   {relpath}", fg=typer.colors.RED)
    for entry in result.modified[:20]:
        typer.secho(f"  MODIFIED  {entry['relpath']}", fg=typer.colors.RED)
        typer.echo(f"            expected {entry['expected_sha256'][:24]}... "
                   f"({entry['expected_size']} bytes)")
        typer.echo(f"            actual   {entry['actual_sha256'][:24]}... "
                   f"({entry['actual_size']} bytes)")
    for relpath in result.added[:20]:
        typer.secho(f"  ADDED     {relpath}", fg=typer.colors.YELLOW)

    raise typer.Exit(
        code=0 if (result.manifest_self_consistent and result.dataset_matches) else 3
    )


@lab_app.command("generate")
def lab_generate(
    out: Path = typer.Option(Path("attack_lab/_clean"), "--out", "-o"),
    seed: int = typer.Option(20260917, "--seed"),
    per_class: int = typer.Option(14, "--per-class", help="Samples per class per contributor."),
    coco: bool = typer.Option(True, "--coco/--no-coco", help="Also export a COCO view."),
    yolo: bool = typer.Option(False, "--yolo/--no-yolo", help="Also export a YOLO view."),
) -> None:
    """Generate the reproducible clean baseline corpus."""
    from ..attack_lab.synth import generate_clean_dataset

    result = generate_clean_dataset(
        out, seed=seed, per_class_per_contributor=per_class,
        export_coco=coco, export_yolo=yolo,
    )
    typer.secho(f"generated {len(result.samples)} samples -> {result.root}", fg=typer.colors.GREEN)


@lab_app.command("attack")
def lab_attack(
    clean_root: Path = typer.Argument(..., help="Clean dataset root (…/_clean/dataset)."),
    out_dir: Path = typer.Argument(..., help="Scenario output directory."),
    scenario: str = typer.Option(..., "--scenario", "-s", help="Attack scenario name."),
    seed: Optional[int] = typer.Option(None, "--seed"),
) -> None:
    """Apply a reproducible attack, writing ground truth outside the dataset root."""
    from ..attack_lab.attacks import SCENARIOS

    if scenario not in SCENARIOS:
        _fail(CvTrustError(f"unknown scenario {scenario!r}; available: "
                           f"{', '.join(sorted(SCENARIOS))}"))
        return
    kwargs = {"seed": seed} if seed is not None else {}
    result = SCENARIOS[scenario](clean_root, out_dir, **kwargs)
    typer.secho(
        f"{scenario}: {result.ground_truth['affected_count']} of "
        f"{result.ground_truth['total_samples']} samples affected -> {result.out_dir}",
        fg=typer.colors.GREEN,
    )


@lab_app.command("evaluate")
def lab_evaluate(
    lab_dir: Path = typer.Argument(Path("attack_lab"), help="Directory of scenario folders."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Path = typer.Option(Path("reports/evaluation.json"), "--out", "-o"),
    calibration_out: Optional[Path] = typer.Option(
        Path("reports/calibration.json"), "--calibration-out",
        help="Write the measured calibration table here.",
    ),
    scenarios: Optional[str] = typer.Option(None, "--scenarios", help="Comma-separated subset."),
) -> None:
    """Measure detector precision/recall against attack ground truth, and calibrate."""
    from ..attack_lab.evaluate import evaluate_all
    from ..reporting.render import render_evaluation

    try:
        cfg = _load_config(config)
        report, calibration = evaluate_all(
            lab_dir, cfg,
            [s.strip() for s in scenarios.split(",")] if scenarios else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_evaluation(report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"\nevaluation written to {out}", fg=typer.colors.BLUE)
    if calibration_out:
        calibration_out.parent.mkdir(parents=True, exist_ok=True)
        calibration_out.write_text(calibration.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"calibration written to {calibration_out}", fg=typer.colors.BLUE)


@app.command("demo")
def demo(
    workdir: Path = typer.Option(Path("attack_lab"), "--workdir", "-w"),
    seed: int = typer.Option(20260917, "--seed"),
    per_class: int = typer.Option(14, "--per-class"),
    keep: bool = typer.Option(False, "--keep", help="Reuse an existing corpus instead of regenerating."),
    reports_dir: Optional[Path] = typer.Option(
        None, "--reports-dir",
        help="Where to write the demo reports. Defaults to <workdir>/reports.",
    ),
) -> None:
    """One-command end-to-end demonstration: clean baseline, attacks, detection, evidence."""
    from ..reporting.demo import run_demo

    try:
        run_demo(
            workdir, seed=seed, per_class=per_class,
            regenerate=not keep, reports_dir=reports_dir,
        )
    except CvTrustError as exc:
        _fail(exc)


def main() -> None:  # pragma: no cover - entry point
    try:
        app()
    except CvTrustError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    main()
