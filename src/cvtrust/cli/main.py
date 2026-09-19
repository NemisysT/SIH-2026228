"""Command-line interface.

Everything the platform does is reachable from here, offline, with no service to
start.  Commands are grouped by the object they act on:

``dataset``     scan, verify, manifest
``model``       manifest, verify, assess
``provenance``  keygen, trust, record, verify, verify-log, anchor, benchmark
``assurance``   shift, assess  (Module 4: distribution shift + evidence fusion)
``lab``         generate the synthetic corpus, run attacks, evaluate, calibrate
``demo``        the end-to-end judge-facing demonstration
``info``        what this build supports and what it does not
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
    "offline dataset forensics (Module 1), model forensics with backdoor "
    "assurance (Module 2), inference provenance with cryptographic integrity "
    "(Module 3), and distribution-shift characterisation with cross-module "
    "evidence fusion (Module 4).",
    no_args_is_help=True,
    add_completion=False,
)
dataset_app = typer.Typer(help="Dataset ingestion, integrity and forensics.", no_args_is_help=True)
model_app = typer.Typer(
    help="Model ingestion, identity and backdoor assurance (Module 2).",
    no_args_is_help=True,
)
provenance_app = typer.Typer(
    help="Inference provenance and cryptographic integrity (Module 3).",
    no_args_is_help=True,
)
trust_app = typer.Typer(
    help="The local, offline trust store: which keys the operator authorises.",
    no_args_is_help=True,
)
provenance_app.add_typer(trust_app, name="trust")
assurance_app = typer.Typer(
    help="Distribution shift, cross-module evidence fusion and the assurance "
    "policy engine (Module 4).",
    no_args_is_help=True,
)
lab_app = typer.Typer(help="Synthetic attack laboratory and evaluation.", no_args_is_help=True)
app.add_typer(dataset_app, name="dataset")
app.add_typer(model_app, name="model")
app.add_typer(provenance_app, name="provenance")
app.add_typer(assurance_app, name="assurance")
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
    from ..models import REGISTERED_ADAPTERS
    from ..reporting.render import render_coverage
    from ..risk.coverage import CoverageStatement

    from ..risk.coverage import build_capability_statement

    render_coverage(CoverageStatement.build([], (1, 2, 3, 4)))
    typer.echo()
    typer.secho(
        "Module 4 assurance capabilities (what this BUILD implements; a given "
        "run still reports NOT_ASSESSED for anything its inputs did not "
        "support):",
        bold=True,
    )
    for entry in build_capability_statement().entries:
        typer.echo(f"  {entry.capability:26s} {entry.coverage.value}")
        if entry.reason:
            typer.secho(f"      {entry.reason}", fg=typer.colors.YELLOW)
    typer.echo()
    typer.secho("Model formats available in this environment:", bold=True)
    if REGISTERED_ADAPTERS:
        for name in REGISTERED_ADAPTERS:
            typer.echo(f"  {name}")
    else:
        typer.secho(
            "  none — install the 'onnx' and/or 'torch' extras from local wheels. "
            "Nothing is ever downloaded at run time.",
            fg=typer.colors.YELLOW,
        )


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


# ---------------------------------------------------------------------------
# Module 2 — model assurance
# ---------------------------------------------------------------------------


@model_app.command("manifest")
def model_manifest(
    path: Path = typer.Argument(..., help="Model artifact (.onnx, .pt, .pth)."),
    out: Path = typer.Option(Path("model-manifest.json"), "--out", "-o"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    adapter: Optional[str] = typer.Option(None, "--model-adapter"),
) -> None:
    """Build and write a model manifest: the artifact's cryptographic identity."""
    from ..model_pipeline import load_model
    from ..models.manifest import build_model_manifest

    try:
        cfg = _load_config(config)
        handle, model_adapter = load_model(path, cfg, adapter)
        manifest = build_model_manifest(handle, model_adapter)
    except CvTrustError as exc:
        _fail(exc)
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"manifest_id       {manifest.manifest_id}", fg=typer.colors.GREEN)
    typer.echo(f"model_id          {manifest.model_id}")
    typer.echo(f"format            {manifest.model_format}")
    typer.echo(f"file sha256       {manifest.file_sha256}")
    typer.echo(f"graph digest      {manifest.graph_digest or 'unavailable'}")
    typer.echo(f"parameter digest  {manifest.parameter_digest or 'unavailable'}")
    typer.echo(f"parameters        {manifest.parameter_count}")
    typer.echo(f"access mode       {manifest.access_mode.value}")
    typer.echo(f"capabilities      {', '.join(manifest.capabilities)}")
    if manifest.unavailable_fields:
        typer.secho(
            f"unavailable       {', '.join(manifest.unavailable_fields)}",
            fg=typer.colors.YELLOW,
        )
    typer.echo(f"written to        {out}")


@model_app.command("verify")
def model_verify(
    manifest_path: Path = typer.Argument(..., help="A manifest from `model manifest`."),
    path: Path = typer.Argument(..., help="Model artifact to verify against it."),
) -> None:
    """Re-verify a model artifact against a manifest: detects post-assurance change."""
    from ..models.manifest import load_model_manifest, verify_model_manifest

    try:
        manifest = load_model_manifest(manifest_path)
    except CvTrustError as exc:
        _fail(exc)
        return

    result = verify_model_manifest(manifest, path)
    ok = typer.style("PASS", fg=typer.colors.GREEN, bold=True)
    bad = typer.style("FAIL", fg=typer.colors.RED, bold=True)
    unknown = typer.style("UNAVAILABLE", fg=typer.colors.YELLOW)

    typer.echo(f"manifest self-consistency  {ok if result.manifest_self_consistent else bad}")
    typer.echo(f"artifact present           {ok if result.artifact_present else bad}")
    typer.echo(f"file digest                {ok if result.file_match else bad}")
    if not result.file_match and result.actual_file_sha256:
        typer.echo(f"  expected {result.expected_file_sha256}")
        typer.echo(f"  actual   {result.actual_file_sha256}")
    for label, value in (
        ("graph digest", result.graph_match),
        ("parameter digest", result.parameter_match),
    ):
        typer.echo(
            f"{label:26s} {ok if value else bad if value is False else unknown}"
        )
    for entry in result.changed_parameters[:20]:
        typer.secho(f"  CHANGED  {entry['name']} ({entry['change']})", fg=typer.colors.RED)
    for note in result.notes:
        typer.secho(f"  note: {note}", fg=typer.colors.YELLOW)

    raise typer.Exit(code=0 if result.ok else 3)


@model_app.command("assess")
def model_assess(
    path: Path = typer.Argument(..., help="Model artifact under assessment."),
    reference: Optional[Path] = typer.Option(
        None, "--reference", "-r",
        help="Trusted reference model. Without it, identity and structural "
             "modification are NOT_ASSESSED rather than clean.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    adapter: Optional[str] = typer.Option(None, "--model-adapter"),
    calibration: Optional[Path] = typer.Option(
        None, "--calibration", help="Calibration table from `cvtrust lab model-evaluate`."
    ),
    detectors: Optional[str] = typer.Option(
        None, "--detectors", help="Comma-separated subset of model detectors."
    ),
    black_box: bool = typer.Option(
        False, "--black-box",
        help="Genuinely drop graph/parameter/activation/gradient access before "
             "analysis, to exercise and report the black-box pathway.",
    ),
    allow_unsafe: bool = typer.Option(
        False, "--allow-unsafe-deserialisation",
        help="Permit torch.load(weights_only=False). This EXECUTES CODE from an "
             "untrusted artifact; prefer re-exporting to ONNX or TorchScript.",
    ),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the JSON report here."),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown-out"),
    full: bool = typer.Option(False, "--full", help="Print every finding."),
) -> None:
    """Assess a model: identity, structure, parameters, behaviour, backdoor."""
    from ..model_pipeline import assess_model
    from ..reporting.model_render import render_model_markdown, render_model_report

    overrides: dict = {}
    if calibration:
        overrides["calibration_path"] = str(calibration)
    if allow_unsafe:
        overrides["model"] = {"allow_unsafe_deserialisation": True}

    try:
        cfg = _load_config(config, overrides or None)
        report, _, _ = assess_model(
            path, cfg,
            reference_path=reference,
            adapter_name=adapter,
            detectors=tuple(d.strip() for d in detectors.split(",")) if detectors else None,
            force_black_box=black_box,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_model_report(report, full=full)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nJSON report written to {out}", fg=typer.colors.BLUE)
    if markdown_out:
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.write_text(render_model_markdown(report), encoding="utf-8")
        typer.secho(f"Markdown report written to {markdown_out}", fg=typer.colors.BLUE)

    # Same exit-code convention as `dataset scan`: 0 clean, 1 review, 3 quarantine.
    raise typer.Exit(
        code=3 if report.summary.overall == "QUARANTINE REQUIRED"
        else 0 if report.summary.overall.startswith("NO ANOMALY DETECTED")
        else 1
    )


# ---------------------------------------------------------------------------
# Module 3 — inference provenance and cryptographic integrity
# ---------------------------------------------------------------------------


@provenance_app.command("keygen")
def provenance_keygen(
    out: Path = typer.Option(Path("keys/signer.pem"), "--out", "-o",
                             help="Where to write the PKCS#8 private key."),
    public_out: Optional[Path] = typer.Option(
        None, "--public-out", help="Defaults to <out>.pub.json."
    ),
    label: Optional[str] = typer.Option(None, "--label", help="A name for the key. A label."),
    passphrase: Optional[str] = typer.Option(
        None, "--passphrase",
        help="Encrypts the private key at rest. Strongly preferred; without it "
             "--allow-unencrypted is required.",
    ),
    allow_unencrypted: bool = typer.Option(
        False, "--allow-unencrypted",
        help="Write the private key with no passphrase. For tests and demos. "
             "This software cannot protect a key from a compromised host either "
             "way -- see docs/cryptographic-model.md.",
    ),
) -> None:
    """Generate an Ed25519 signing keypair locally. Nothing is registered anywhere."""
    from ..provenance.keys import generate_keypair

    try:
        _, info = generate_keypair(
            private_path=out, public_path=public_out, label=label,
            passphrase=passphrase, allow_unencrypted=allow_unencrypted,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    typer.secho(f"key_id       {info.key_id}", fg=typer.colors.GREEN)
    typer.echo(f"public key   {info.public_key_hex}")
    typer.echo(f"private key  {info.private_key_path}"
               f"{'' if info.encrypted else '  (UNENCRYPTED)'}")
    typer.echo(f"public half  {info.public_key_path}")
    typer.secho(
        "\nThis key is trusted by nobody yet. Add its public half to a trust "
        "store with `cvtrust provenance trust add`, on the machine that will "
        "verify -- and get it there through a channel independent of the one "
        "that will supply the records.",
        fg=typer.colors.YELLOW,
    )


@trust_app.command("add")
def provenance_trust_add(
    public_key: Path = typer.Argument(..., help="A .pub.json from `provenance keygen`."),
    store: Path = typer.Option(Path("trust_store.json"), "--store", "-s"),
    label: Optional[str] = typer.Option(None, "--label"),
    valid_from: Optional[str] = typer.Option(None, "--valid-from", help="ISO-8601 UTC."),
    valid_until: Optional[str] = typer.Option(None, "--valid-until", help="ISO-8601 UTC."),
    purpose: str = typer.Option(
        "inference_provenance", "--purpose",
        help="inference_provenance | log_anchor | any",
    ),
    provenance: Optional[str] = typer.Option(
        None, "--provenance",
        help="How this key was obtained. The most important field for a "
             "reviewer: a key obtained through the same channel as the records "
             "establishes nothing.",
    ),
) -> None:
    """Record an operator decision to trust a key."""
    from ..provenance.keys import read_public_key_file
    from ..provenance.trust import KeyPurpose, TrustStore, trust_key

    try:
        payload = read_public_key_file(public_key)
        updated = trust_key(
            TrustStore.load_or_empty(store),
            public_key=str(payload["public_key"]),
            label=label or payload.get("label"),
            valid_from=valid_from,
            valid_until=valid_until,
            purpose=KeyPurpose(purpose),
            provenance=provenance,
        )
        updated.save(store)
    except (CvTrustError, ValueError) as exc:
        _fail(exc if isinstance(exc, CvTrustError) else CvTrustError(str(exc)))
        return

    typer.secho(f"trusted {payload['key_id']}", fg=typer.colors.GREEN)
    typer.echo(f"store   {store} ({len(updated.keys)} key(s))")
    if not provenance:
        typer.secho(
            "no --provenance recorded: a reviewer cannot tell how this key was "
            "obtained, and that is the assumption the whole trust model rests on",
            fg=typer.colors.YELLOW,
        )


@trust_app.command("revoke")
def provenance_trust_revoke(
    key_id: str = typer.Argument(..., help="Full 64-character key id."),
    reason: str = typer.Option(..., "--reason", help="Recorded in the store; required."),
    store: Path = typer.Option(Path("trust_store.json"), "--store", "-s"),
) -> None:
    """Revoke a key. Revocation is absolute and takes effect on this store only."""
    from ..provenance.trust import TrustStore, revoke_key

    try:
        updated = revoke_key(TrustStore.load(store), key_id, reason=reason)
        updated.save(store)
    except CvTrustError as exc:
        _fail(exc)
        return
    typer.secho(f"revoked {key_id}", fg=typer.colors.YELLOW)
    typer.echo(f"reason  {reason}")
    typer.secho(
        "There is no revocation service. This takes effect for verifications "
        "that read THIS store, and nowhere else.",
        fg=typer.colors.YELLOW,
    )


@trust_app.command("list")
def provenance_trust_list(
    store: Path = typer.Option(Path("trust_store.json"), "--store", "-s"),
) -> None:
    """Print the trust store."""
    from ..provenance.trust import TrustStore

    try:
        loaded = TrustStore.load(store)
    except CvTrustError as exc:
        _fail(exc)
        return

    typer.secho(f"{len(loaded.keys)} key(s) in {store}", bold=True)
    typer.echo(f"store digest {loaded.digest()[:32]}...")
    typer.echo()
    for key in loaded.keys:
        colour = {
            "TRUSTED": typer.colors.GREEN,
            "REVOKED": typer.colors.RED,
            "UNKNOWN": typer.colors.YELLOW,
        }[key.status.value]
        typer.secho(f"  {key.key_id}  {key.status.value}", fg=colour)
        typer.echo(f"    label     {key.label or '-'}")
        typer.echo(f"    purpose   {key.purpose.value}")
        typer.echo(f"    window    {key.valid_from or 'open'} .. {key.valid_until or 'open'}")
        typer.echo(f"    obtained  {key.provenance or 'NOT RECORDED'}")
        if key.revoked_at:
            typer.echo(f"    revoked   {key.revoked_at}: {key.revocation_reason}")
    typer.echo()
    typer.secho(loaded.administrative_model, fg=typer.colors.BLUE)


@provenance_app.command("record")
def provenance_record(
    input_path: Path = typer.Argument(..., help="The inference input artifact."),
    output_json: Path = typer.Argument(..., help="JSON file holding the inference output."),
    key: Path = typer.Option(..., "--key", "-k", help="Ed25519 private key (PKCS#8 PEM)."),
    log: Path = typer.Option(Path("provenance.jsonl"), "--log", "-l"),
    model_manifest: Optional[Path] = typer.Option(
        None, "--model-manifest",
        help="A manifest from `cvtrust model manifest`. Module 3 binds Module "
             "2's identity rather than computing its own.",
    ),
    model_artifact: Optional[Path] = typer.Option(
        None, "--model-artifact",
        help="Bind a model by file digest alone, when no manifest exists.",
    ),
    preprocessing: Optional[Path] = typer.Option(
        None, "--preprocessing", help="JSON preprocessing configuration."
    ),
    inference_config: Optional[Path] = typer.Option(
        None, "--inference-config", help="JSON inference configuration."
    ),
    passphrase: Optional[str] = typer.Option(None, "--passphrase"),
    log_id: Optional[str] = typer.Option(
        None, "--log-id", help="Defaults to the existing log's id, or the file stem."
    ),
    producer: Optional[str] = typer.Option(None, "--producer", help="A label. UNTRUSTED."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Create and sign a provenance record, appending it to a log."""
    from ..provenance.binding import bind_config, bind_input, bind_output
    from ..provenance.keys import load_private_key
    from ..provenance.log import ProvenanceLog
    from ..provenance.output import raw_output
    from ..provenance.record import create_provenance_record

    try:
        _load_config(config)
        private_key = load_private_key(key, passphrase)
        model_binding = _model_binding_from_cli(model_manifest, model_artifact)
        output_payload = json.loads(output_json.read_text(encoding="utf-8"))
        canonical = _canonical_output_from(output_payload)
        pre = bind_config(_read_json(preprocessing))
        inf = bind_config(_read_json(inference_config))

        existing = ProvenanceLog.load(log) if log.is_file() else ProvenanceLog.new(
            log_id or log.stem, log
        )
        existing.path = log
        if log_id and existing.log_id != log_id and len(existing) == 0:
            existing.log_id = log_id

        def factory(sequence_number: int, previous_record_digest):
            return create_provenance_record(
                input_binding=bind_input(input_path),
                model_binding=model_binding,
                preprocessing=pre,
                inference=inf,
                output=bind_output(canonical),
                log_id=existing.log_id,
                sequence_number=sequence_number,
                previous_record_digest=previous_record_digest,
                producer=producer,
            )

        entry = existing.append_signed(factory, private_key)
        existing.save(log)
    except (CvTrustError, ValueError, KeyError) as exc:
        _fail(exc if isinstance(exc, CvTrustError) else CvTrustError(str(exc)))
        return

    typer.secho(f"record_id     {entry.record.record_id}", fg=typer.colors.GREEN)
    typer.echo(f"entry digest  {entry.entry_digest()}")
    typer.echo(f"sequence      {entry.record.sequence.sequence_number}")
    typer.echo(f"input digest  {entry.record.input.raw_input_digest}")
    typer.echo(f"model digest  {entry.record.model.file_sha256}")
    typer.echo(f"output digest {entry.record.output.digest}")
    assert entry.signature is not None
    typer.echo(f"signed by     {entry.signature.key_id}")
    typer.echo(f"log           {log} ({len(existing)} entries)")


@provenance_app.command("verify")
def provenance_verify(
    record_file: Path = typer.Argument(..., help="A single signed record, as JSON."),
    store: Optional[Path] = typer.Option(None, "--store", "-s", help="Trust store."),
    input_artifact: Optional[Path] = typer.Option(
        None, "--input", help="Corroborate the bound input against this file."
    ),
    model_manifest: Optional[Path] = typer.Option(
        None, "--model-manifest", help="Corroborate the bound model against this."
    ),
    replay_db: Optional[Path] = typer.Option(None, "--replay-db"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown-out"),
    full: bool = typer.Option(False, "--full"),
) -> None:
    """Verify one provenance record outside a log."""
    from ..provenance.record import SignedRecord
    from ..provenance.replay import ReplayDatabase
    from ..provenance.trust import TrustStore
    from ..provenance_pipeline import verify_single_record
    from ..reporting.provenance_render import (
        render_provenance_markdown,
        render_provenance_report,
    )

    try:
        cfg = _load_config(config)
        entry = SignedRecord.model_validate_json(
            record_file.read_text(encoding="utf-8")
        )
        report, _, database = verify_single_record(
            entry, cfg,
            trust_store=TrustStore.load(store) if store else None,
            expected=_expected_from_cli(input_artifact, model_manifest),
            replay_database=ReplayDatabase.load_or_empty(replay_db) if replay_db else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return
    except Exception as exc:
        _fail(CvTrustError(f"cannot read record {record_file}: {exc}"))
        return

    render_provenance_report(report, full=full)
    if replay_db and database is not None:
        database.save(replay_db)
    _write_provenance_outputs(report, out, markdown_out, render_provenance_markdown)
    raise typer.Exit(code=_provenance_exit_code(report))


@provenance_app.command("verify-log")
def provenance_verify_log(
    log: Path = typer.Argument(..., help="A provenance log (JSONL)."),
    store: Optional[Path] = typer.Option(None, "--store", "-s"),
    anchor: Optional[Path] = typer.Option(
        None, "--anchor",
        help="An out-of-band log anchor. WITHOUT ONE, tail truncation is not "
             "detectable and is reported as such.",
    ),
    replay_db: Optional[Path] = typer.Option(
        None, "--replay-db",
        help="Local replay database. Without one, replay is NOT assessed.",
    ),
    model_manifest: Optional[Path] = typer.Option(None, "--model-manifest"),
    input_artifact: Optional[Path] = typer.Option(None, "--input"),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Do not write observations back to the replay database.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
    markdown_out: Optional[Path] = typer.Option(None, "--markdown-out"),
    full: bool = typer.Option(False, "--full"),
) -> None:
    """Verify a whole provenance log: bindings, signatures, trust, chain, replay."""
    from ..provenance_pipeline import load_verification_inputs, verify_log as run_verify
    from ..reporting.provenance_render import (
        render_provenance_markdown,
        render_provenance_report,
    )

    try:
        cfg = _load_config(config)
        provenance_log, trust_store, database, log_anchor = load_verification_inputs(
            log_path=log, trust_store_path=store,
            replay_db_path=replay_db, anchor_path=anchor,
        )
        report, _, updated = run_verify(
            provenance_log, cfg,
            trust_store=trust_store,
            expected=_expected_from_cli(input_artifact, model_manifest),
            replay_database=database,
            anchor=log_anchor,
            record_observations=not dry_run,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_provenance_report(report, full=full)
    if replay_db and updated is not None and not dry_run:
        updated.save(replay_db)
        typer.secho(f"replay database updated: {replay_db}", fg=typer.colors.BLUE)
    _write_provenance_outputs(report, out, markdown_out, render_provenance_markdown)
    raise typer.Exit(code=_provenance_exit_code(report))


@provenance_app.command("anchor")
def provenance_anchor(
    log: Path = typer.Argument(..., help="The log to anchor."),
    out: Path = typer.Option(Path("anchor.json"), "--out", "-o"),
    note: Optional[str] = typer.Option(None, "--note"),
) -> None:
    """Record a log's head out of band. The only thing that makes truncation detectable."""
    from ..provenance.chain import build_anchor
    from ..provenance.log import ProvenanceLog

    try:
        provenance_log = ProvenanceLog.load(log)
        anchor = build_anchor(provenance_log.entries, note=note)
    except (CvTrustError, ValueError) as exc:
        _fail(exc if isinstance(exc, CvTrustError) else CvTrustError(str(exc)))
        return

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(anchor.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"head digest  {anchor.head_entry_digest}", fg=typer.colors.GREEN)
    typer.echo(f"entries      {anchor.entry_count}")
    typer.echo(f"written to   {out}")
    typer.secho(
        "\nStore this somewhere whoever writes the log cannot reach. An anchor "
        "kept beside the log it anchors protects against nothing.",
        fg=typer.colors.YELLOW,
    )


@provenance_app.command("benchmark")
def provenance_benchmark(
    records: int = typer.Option(200, "--records", "-n"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """Measure record creation, signing, verification and chain-verification cost."""
    from ..provenance.benchmark import run_benchmark, render_benchmark

    result = run_benchmark(record_count=records)
    render_benchmark(result)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nbenchmark written to {out}", fg=typer.colors.BLUE)


@lab_app.command("provenance-build")
def lab_provenance_build(
    lab_dir: Path = typer.Option(Path("provenance_lab"), "--out", "-o"),
    seed: int = typer.Option(20260917, "--seed"),
    records: int = typer.Option(6, "--records", help="Records in the clean baseline."),
    scenarios: Optional[str] = typer.Option(None, "--scenarios", help="Comma-separated subset."),
) -> None:
    """Build the reproducible provenance attack scenarios."""
    from ..attack_lab.provenance_attacks import build_lab

    try:
        _, built = build_lab(
            lab_dir, seed=seed, record_count=records,
            scenarios=[s.strip() for s in scenarios.split(",")] if scenarios else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    for scenario in built:
        typer.echo(f"  {scenario.name:30s} {', '.join(scenario.attack_classes)}")
    typer.secho(f"{len(built)} scenario(s) written under {lab_dir}", fg=typer.colors.GREEN)


@lab_app.command("provenance-evaluate")
def lab_provenance_evaluate(
    lab_dir: Path = typer.Argument(Path("provenance_lab"), help="Provenance lab directory."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Path = typer.Option(Path("reports/provenance_evaluation.json"), "--out", "-o"),
    scenarios: Optional[str] = typer.Option(None, "--scenarios"),
) -> None:
    """Check every scenario's verification outcome against its ground truth, exactly."""
    from ..attack_lab.provenance_evaluate import evaluate_lab
    from ..reporting.provenance_render import render_provenance_evaluation

    try:
        cfg = _load_config(config)
        report = evaluate_lab(
            lab_dir, cfg,
            scenarios=[s.strip() for s in scenarios.split(",")] if scenarios else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_provenance_evaluation(report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"\nevaluation written to {out}", fg=typer.colors.BLUE)
    raise typer.Exit(code=0 if report.all_passed else 1)


# -- provenance CLI helpers -------------------------------------------------


def _read_json(path: Optional[Path]) -> dict:
    """An absent configuration file is an empty configuration, and is bound as one.

    Not skipped: a record whose preprocessing digest covers ``{}`` states that
    no preprocessing was declared, which is a checkable claim. Omitting the
    field entirely would leave nothing to check.
    """
    if path is None:
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_output_from(payload: dict):
    """Build a canonical output from a JSON file, by its declared task."""
    from ..provenance.output import (
        classification_output,
        detection_output,
        keypoint_output,
        raw_output,
        segmentation_output,
    )

    task = str(payload.get("task", "raw"))
    if task == "classification":
        return classification_output(
            payload["scores"], labels=payload.get("labels")
        )
    if task == "detection":
        return detection_output(
            payload["detections"],
            labels=payload.get("labels", ()),
            coordinate_space=payload.get("coordinate_space", "input_pixels"),
        )
    if task == "segmentation":
        return segmentation_output(payload["masks"], labels=payload.get("labels", ()))
    if task == "keypoints":
        return keypoint_output(payload["keypoints"])
    return raw_output(payload)


def _model_binding_from_cli(manifest_path: Optional[Path], artifact: Optional[Path]):
    from ..core.hashing import sha256_file
    from ..provenance.binding import ModelBinding, bind_model_manifest

    if manifest_path is not None:
        from ..models.manifest import load_model_manifest

        return bind_model_manifest(load_model_manifest(manifest_path))
    if artifact is not None:
        digest = sha256_file(artifact)
        return ModelBinding(
            model_id=f"M-{digest[:16]}",
            file_sha256=digest,
            model_format=artifact.suffix.lstrip(".") or "unknown",
        )
    raise CvTrustError(
        "a record must bind a model: supply --model-manifest (preferred, it "
        "carries Module 2's graph and parameter digests too) or --model-artifact"
    )


def _expected_from_cli(input_artifact: Optional[Path], model_manifest: Optional[Path]):
    from ..core.hashing import sha256_file
    from ..provenance.verify import ExpectedBinding

    if input_artifact is None and model_manifest is None:
        return None
    values: dict = {}
    sources: list[str] = []
    if input_artifact is not None:
        values["raw_input_digest"] = sha256_file(input_artifact)
        sources.append(f"input artifact {input_artifact}")
    if model_manifest is not None:
        from ..models.manifest import load_model_manifest

        manifest = load_model_manifest(model_manifest)
        values.update(
            model_id=manifest.model_id,
            model_file_sha256=manifest.file_sha256,
            model_graph_digest=manifest.graph_digest,
            model_parameter_digest=manifest.parameter_digest,
        )
        sources.append(f"model manifest {manifest.manifest_id}")
    return ExpectedBinding(source="; ".join(sources), **values)


def _write_provenance_outputs(report, out, markdown_out, renderer) -> None:
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nJSON report written to {out}", fg=typer.colors.BLUE)
    if markdown_out:
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.write_text(renderer(report), encoding="utf-8")
        typer.secho(f"Markdown report written to {markdown_out}", fg=typer.colors.BLUE)


def _provenance_exit_code(report) -> int:
    """Same convention as `dataset scan` and `model assess`: 0 clean, 1 review, 3 stop."""
    overall = report.summary.overall
    if overall == "PROVENANCE COMPROMISED":
        return 3
    if overall.startswith("PROVENANCE VERIFIED"):
        return 0
    if overall == "NO RECORDS":
        return 0
    return 1


@lab_app.command("model-build")
def lab_model_build(
    lab_dir: Path = typer.Option(Path("model_lab"), "--out", "-o"),
    seed: int = typer.Option(20260917, "--seed"),
    per_class: int = typer.Option(60, "--per-class"),
    epochs: int = typer.Option(30, "--epochs"),
    scenarios: Optional[str] = typer.Option(None, "--scenarios", help="Comma-separated subset."),
) -> None:
    """Train the reference model and build the reproducible model attack scenarios."""
    from ..attack_lab.model_attacks import build_lab

    try:
        reference, built = build_lab(
            lab_dir, seed=seed, per_class=per_class, epochs=epochs,
            scenarios=[s.strip() for s in scenarios.split(",")] if scenarios else None,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    typer.secho(f"reference model -> {reference.root}", fg=typer.colors.GREEN)
    for scenario in built:
        typer.echo(f"  {scenario.name:28s} {', '.join(scenario.attack_classes)}")
    typer.secho(f"{len(built)} scenario(s) written under {lab_dir}", fg=typer.colors.GREEN)


@lab_app.command("model-evaluate")
def lab_model_evaluate(
    lab_dir: Path = typer.Argument(Path("model_lab"), help="Model lab directory."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    out: Path = typer.Option(Path("reports/model_evaluation.json"), "--out", "-o"),
    calibration_out: Optional[Path] = typer.Option(
        Path("reports/model_calibration.json"), "--calibration-out"
    ),
    artifact: str = typer.Option(
        "model.onnx", "--artifact",
        help="Which artifact to assess per scenario: model.onnx or model.pt.",
    ),
    scenarios: Optional[str] = typer.Option(None, "--scenarios"),
    black_box: bool = typer.Option(
        False, "--black-box", help="Evaluate the black-box pathway instead."
    ),
) -> None:
    """Measure the model detectors against model-lab ground truth, and calibrate."""
    from ..attack_lab.model_evaluate import evaluate_model_lab
    from ..reporting.model_render import render_model_evaluation

    reference_artifact = "reference.pt" if artifact.endswith(".pt") else "reference.onnx"
    try:
        cfg = _load_config(config)
        report, calibration = evaluate_model_lab(
            lab_dir, cfg,
            scenarios=[s.strip() for s in scenarios.split(",")] if scenarios else None,
            artifact=artifact,
            reference_artifact=reference_artifact,
            force_black_box=black_box,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_model_evaluation(report)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    typer.secho(f"\nevaluation written to {out}", fg=typer.colors.BLUE)
    if calibration_out:
        calibration_out.parent.mkdir(parents=True, exist_ok=True)
        calibration_out.write_text(calibration.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"calibration written to {calibration_out}", fg=typer.colors.BLUE)


def _context_from(path: Optional[Path], inline: Optional[str], label: str):
    """Load a declared operational context from a file or a k=v string.

    Both forms exist because both are real: an analyst running one comparison
    types ``--current-context "illumination=low,sensor=sensor_b"``, and an
    operator wiring this into a pipeline has a JSON file already. Neither is
    validated against anything, because nothing in this system can validate a
    claim about the physical world, and the report says so.
    """
    from ..shift.context import OperationalContext

    payload: dict = {}
    if path:
        try:
            payload.update(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            raise CvTrustError(f"could not read {label} context from {path}: {exc}") from exc
    if inline:
        for item in inline.split(","):
            if not item.strip():
                continue
            if "=" not in item:
                raise CvTrustError(
                    f"{label} context entry {item!r} is not in key=value form"
                )
            key, value = item.split("=", 1)
            payload[key.strip()] = value.strip()
    return OperationalContext.from_mapping(payload)


@assurance_app.command("shift")
def assurance_shift(
    current_root: Path = typer.Argument(..., help="The population under assessment."),
    reference_root: Optional[Path] = typer.Option(
        None, "--reference",
        help="A separately declared reference corpus. The strong form: the "
             "population under assessment cannot influence its own baseline.",
    ),
    reference_samples: Optional[Path] = typer.Option(
        None, "--reference-samples",
        help="JSON list of sample ids INSIDE the current dataset to use as the "
             "reference instead. Weaker, and reported as such.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    adapter: Optional[str] = typer.Option(None, "--adapter"),
    reference_context: Optional[Path] = typer.Option(
        None, "--reference-context", help="JSON declaring the reference population's conditions."
    ),
    current_context: Optional[Path] = typer.Option(
        None, "--current-context", help="JSON declaring the current population's conditions."
    ),
    declare: Optional[str] = typer.Option(
        None, "--declare",
        help="Inline current-population context, e.g. "
             "'illumination=low,sensor=sensor_b'. A CLAIM, never verified.",
    ),
    reference_declare: Optional[str] = typer.Option(
        None, "--reference-declare", help="Inline reference-population context."
    ),
    reference_provenance: Optional[str] = typer.Option(
        None, "--reference-provenance",
        help="Where the reference corpus came from. Recorded verbatim and never "
             "validated.",
    ),
    reference_trust: str = typer.Option(
        "UNKNOWN", "--reference-trust",
        help="UNKNOWN | ASSERTED_BY_OPERATOR | ASSESSED_CLEAN. Never inferred.",
    ),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the shift assessment JSON here."),
) -> None:
    """Characterise population-level distribution shift against a reference.

    This is NOT Module 1's per-sample OOD detector. That one asks whether an
    individual image is unusual; this asks whether the operating population has
    moved. A population can shift without any single sample being remarkable,
    and a handful of remarkable samples do not make a population shift.
    """
    from ..assurance_pipeline import characterise_shift
    from ..shift.reference import ReferenceTrust, load_reference_ids

    try:
        cfg = _load_config(config)
        ids = load_reference_ids(reference_samples) if reference_samples else None
        if reference_root is None and not ids:
            raise CvTrustError(
                "a shift analysis needs a reference population: pass --reference "
                "<corpus> or --reference-samples <ids.json>. Without one the "
                "outcome would be NOT_ASSESSED, which this command will not "
                "fabricate."
            )
        assessment, _ = characterise_shift(
            reference_root, current_root, cfg,
            reference_sample_ids=ids,
            adapter_name=adapter,
            reference_context=_context_from(reference_context, reference_declare, "reference"),
            current_context=_context_from(current_context, declare, "current"),
            reference_provenance=reference_provenance,
            reference_trust=ReferenceTrust(reference_trust.upper()),
        )
    except (CvTrustError, ValueError) as exc:
        _fail(exc if isinstance(exc, CvTrustError) else CvTrustError(str(exc)))
        return

    typer.secho(f"\n{assessment.verdict.value}", bold=True)
    typer.echo(assessment.statement)
    typer.echo()
    for result in assessment.metrics:
        typer.echo(
            f"  {result.metric:34s} {result.status.value:20s} "
            + (
                f"stat={result.statistic:<12.6g} "
                f"p={'-' if result.p_value is None else format(result.p_value, '.4g')}"
                if result.statistic is not None
                else (result.reason or "")
            )
        )
    typer.echo()
    typer.secho(assessment.reference.get("caveat", ""), fg=typer.colors.YELLOW)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nshift assessment written to {out}", fg=typer.colors.BLUE)

    raise typer.Exit(code=0 if assessment.resolved() else 2)


@assurance_app.command("assess")
def assurance_assess(
    dataset_report: Optional[Path] = typer.Option(
        None, "--dataset-report", help="JSON report from `cvtrust dataset scan`."
    ),
    model_report: Optional[Path] = typer.Option(
        None, "--model-report", help="JSON report from `cvtrust model assess`."
    ),
    provenance_report: Optional[Path] = typer.Option(
        None, "--provenance-report",
        help="JSON report from `cvtrust provenance verify-log`.",
    ),
    shift_assessment: Optional[Path] = typer.Option(
        None, "--shift", help="JSON assessment from `cvtrust assurance shift`."
    ),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    calibration: Optional[Path] = typer.Option(
        None, "--calibration", help="Calibration table from `cvtrust lab evaluate`."
    ),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the JSON report here."),
    markdown_out: Optional[Path] = typer.Option(
        None, "--markdown-out", help="Write the Markdown rendering here."
    ),
    full: bool = typer.Option(False, "--full", help="Print the whole lineage."),
) -> None:
    """Fuse the evidence supplied and produce a pipeline assurance decision.

    Every argument is optional, and that is the design: every real deployment
    is missing something, and the only honest response to a missing input is
    NOT_ASSESSED in that scope. Supplying nothing produces a NOT_ASSESSED
    decision rather than an ACCEPT.
    """
    from ..assurance_pipeline import assess_pipeline, exit_code_for
    from ..reporting.assurance_render import (
        render_assurance_markdown,
        render_assurance_report,
    )
    from ..risk.calibration import CalibrationSet
    from ..shift.characterize import ShiftAssessment

    try:
        cfg = _load_config(
            config, {"calibration_path": str(calibration)} if calibration else None
        )
        shift = None
        if shift_assessment:
            shift = ShiftAssessment.model_validate(
                json.loads(shift_assessment.read_text(encoding="utf-8"))
            )
        report, _ = assess_pipeline(
            cfg,
            dataset_report=dataset_report,
            model_report=model_report,
            provenance_report=provenance_report,
            shift=shift,
            calibration=CalibrationSet.load(cfg.calibration_path),
        )
    except (CvTrustError, ValueError) as exc:
        _fail(exc if isinstance(exc, CvTrustError) else CvTrustError(str(exc)))
        return

    render_assurance_report(report, full=full)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        typer.secho(f"\nJSON report written to {out}", fg=typer.colors.BLUE)
    if markdown_out:
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.write_text(render_assurance_markdown(report), encoding="utf-8")
        typer.secho(f"Markdown report written to {markdown_out}", fg=typer.colors.BLUE)

    # 0 accept, 1 review, 2 NOT ASSESSED, 3 quarantine. NOT_ASSESSED gets its
    # own code so a pipeline can tell "we checked and found nothing" from "we
    # checked nothing".
    raise typer.Exit(code=exit_code_for(report))


@lab_app.command("assurance-build")
def lab_assurance_build(
    out: Path = typer.Option(Path("assurance_lab"), "--out", "-o"),
    seed: int = typer.Option(20260917, "--seed"),
    per_class: int = typer.Option(8, "--per-class"),
) -> None:
    """Build the Module 4 population pairs: legitimate operational changes."""
    from ..attack_lab.assurance_scenarios import build_lab

    lab = build_lab(out, seed=seed, per_class_per_contributor=per_class)
    typer.secho(
        f"built {len(lab.pairs)} population pair(s) against a "
        f"{lab.spec['reference_samples']}-sample reference -> {lab.root}",
        fg=typer.colors.GREEN,
    )


@lab_app.command("assurance-evaluate")
def lab_assurance_evaluate(
    lab_dir: Path = typer.Argument(Path("assurance_lab"), help="Built assurance lab."),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
    dataset_lab: Optional[Path] = typer.Option(
        None, "--dataset-lab", help="Built Module 1 attack lab, for the pipeline scenarios."
    ),
    provenance_lab: Optional[Path] = typer.Option(
        None, "--provenance-lab", help="Built Module 3 provenance lab."
    ),
    model_lab: Optional[Path] = typer.Option(
        None, "--model-lab", help="Built Module 2 model lab."
    ),
    out: Path = typer.Option(Path("reports/assurance-evaluation.json"), "--out", "-o"),
    pairs_only: bool = typer.Option(
        False, "--pairs-only", help="Skip the end-to-end pipeline scenarios."
    ),
) -> None:
    """Measure the shift subsystem and the fusion engine against declared expectations.

    A pipeline scenario whose upstream lab was not supplied is reported NOT_RUN
    with the reason. It is never faked and never silently dropped.
    """
    import json as _json

    from ..attack_lab.assurance_evaluate import (
        evaluate_lab,
        render_evaluation,
        write_evaluation,
    )
    from ..attack_lab.assurance_scenarios import AssuranceLab, PopulationPair

    try:
        cfg = _load_config(config)
        spec_path = lab_dir / "lab_spec.json"
        if not spec_path.is_file():
            raise CvTrustError(
                f"{lab_dir} does not contain lab_spec.json; run "
                "`cvtrust lab assurance-build` first"
            )
        spec = _json.loads(spec_path.read_text(encoding="utf-8"))
        pairs = []
        for name in spec["pairs"]:
            truth = _json.loads(
                (lab_dir / name / "ground_truth.json").read_text(encoding="utf-8")
            )
            context = _json.loads(
                (lab_dir / name / "context.json").read_text(encoding="utf-8")
            )
            pairs.append(
                PopulationPair(
                    name=name,
                    reference_root=lab_dir / "_reference" / "dataset",
                    current_root=lab_dir / name / "dataset",
                    reference_context=context["reference"],
                    current_context=context["current"],
                    ground_truth=truth,
                )
            )
        lab = AssuranceLab(
            root=lab_dir,
            baseline_root=lab_dir / "_reference" / "dataset",
            pairs=pairs,
            spec=spec,
        )
        evaluation = evaluate_lab(
            lab, cfg,
            dataset_lab_root=dataset_lab,
            model_lab=model_lab,
            provenance_lab_root=provenance_lab,
            include_scenarios=not pairs_only,
        )
    except CvTrustError as exc:
        _fail(exc)
        return

    render_evaluation(evaluation)
    write_evaluation(evaluation, out)
    typer.secho(f"\nevaluation written to {out}", fg=typer.colors.BLUE)
    raise typer.Exit(code=0 if evaluation.all_passed else 1)


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
