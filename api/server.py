"""HTTP face on the cvtrust pipeline, for the judge-facing dashboard in ``web/``.

This process is purely additive: it imports the existing, unmodified
``cvtrust`` package and exposes its pipeline over JSON. No detector, no
scoring rule and no report field is redefined here — this module only calls
into ``cvtrust`` and serialises what comes back. The assurance pipeline
itself is unaffected and stays runnable exactly as before from the CLI.

Run with:

    ./.venv/bin/uvicorn api.server:app --reload --port 8000

from the ``cv-trust`` project root (the ``cvtrust`` package must already be
installed into the venv, which it is via ``pip install -e .``).
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from cvtrust.attack_lab.attacks import SCENARIOS
from cvtrust.attack_lab.evaluate import EvaluationReport, evaluate_scenario
from cvtrust.attack_lab.synth import generate_clean_dataset
from cvtrust.core.config import Config
from cvtrust.core.errors import CvTrustError
from cvtrust.datasets.contributors import ContributorResolver
from cvtrust.datasets.manifest import build_manifest, verify_manifest
from cvtrust.pipeline import analyse, load_dataset
from cvtrust.risk.coverage import CoverageStatement

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_WORKDIR = PROJECT_ROOT / "attack_lab" / "_web_demo"

app = FastAPI(title="cvtrust demo API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache of the last demo run: this process is a local, single-user
# judge-facing demo server, not a multi-tenant service, so a module-level
# cache is the right amount of state.
_demo_cache: dict[str, Any] | None = None


def _fail(exc: Exception) -> None:
    raise HTTPException(status_code=422, detail=str(exc))


@app.get("/api/health")
def health() -> dict[str, str]:
    from cvtrust import __version__

    return {"status": "ok", "cvtrust_version": __version__}


@app.get("/api/coverage")
def coverage() -> dict[str, Any]:
    return CoverageStatement.build([], (1,)).model_dump(mode="json")


class ScanRequest(BaseModel):
    root: str
    detectors: Optional[list[str]] = None
    adapter: Optional[str] = None


@app.post("/api/dataset/scan")
def dataset_scan(req: ScanRequest) -> dict[str, Any]:
    root = Path(req.root)
    if not root.is_absolute():
        root = PROJECT_ROOT / root
    if not root.is_dir():
        raise HTTPException(status_code=404, detail=f"no such directory: {root}")

    config = Config()
    try:
        report, _ctx, _outputs = analyse(
            root, config, adapter_name=req.adapter, detectors=req.detectors
        )
    except CvTrustError as exc:
        _fail(exc)
        return {}
    return report.model_dump(mode="json")


def _run_demo_pipeline(*, seed: int = 20260917, per_class: int = 14) -> dict[str, Any]:
    """The same story as ``cvtrust demo``, returning data instead of printing it.

    Mirrors ``cvtrust.reporting.demo.run_demo`` step for step (clean baseline,
    a combined multi-contributor attack, detection, scoring against ground
    truth, then post-baseline tamper + re-verification) but every step's
    result is captured into a plain dict for the dashboard instead of being
    rendered to a console.
    """
    workdir = DEMO_WORKDIR
    clean_dir = workdir / "_clean"
    config = Config()

    t0 = time.time()
    generated = generate_clean_dataset(
        clean_dir, seed=seed, per_class_per_contributor=per_class, export_coco=True
    )
    clean_root = clean_dir / "dataset"

    dataset = load_dataset(clean_root)
    resolver = ContributorResolver(config.contributor, clean_root)
    manifest, _, _, _ = build_manifest(dataset, resolver)

    clean_report, _, _ = analyse(clean_root, config)

    scenario_dir = workdir / "combined"
    attack_result = SCENARIOS["combined"](clean_root, scenario_dir)

    attacked_report, _, _ = analyse(
        scenario_dir / "dataset",
        config,
        reference_sample_ids=set(attack_result.ground_truth["clean"]),
    )

    scenario_eval, _ = evaluate_scenario(scenario_dir, config)
    evaluation = EvaluationReport(
        config_hash=config.config_hash(),
        software_version=__import__("cvtrust").__version__,
        scenarios=[scenario_eval],
    )

    tampered_root = workdir / "_tampered" / "dataset"
    if tampered_root.parent.exists():
        shutil.rmtree(tampered_root.parent)
    shutil.copytree(clean_root, tampered_root)

    victim = manifest.samples[len(manifest.samples) // 2]
    victim_path = tampered_root / victim.relpath
    data = bytearray(victim_path.read_bytes())
    data[-1] = (data[-1] + 1) % 256
    victim_path.write_bytes(bytes(data))
    injected = tampered_root / manifest.samples[0].relpath
    shutil.copy2(injected, injected.with_name("injected_after_baseline.jpg"))

    verification = verify_manifest(manifest, tampered_root)

    duration_s = round(time.time() - t0, 2)

    return {
        "duration_s": duration_s,
        "baseline": {
            "manifest_id": manifest.manifest_id,
            "digest": manifest.digest,
            "samples": manifest.counts["samples"],
            "classes": list(manifest.classes),
            "contributors": manifest.contributors,
            "attribution": manifest.attribution["sidecar"] or "path/native",
        },
        "clean_report": clean_report.model_dump(mode="json"),
        "attack": {
            "scenario": "combined",
            "affected_count": attack_result.ground_truth["affected_count"],
            "total_samples": attack_result.ground_truth["total_samples"],
        },
        "attacked_report": attacked_report.model_dump(mode="json"),
        "evaluation": evaluation.model_dump(mode="json"),
        "verification": {
            "manifest_self_consistent": verification.manifest_self_consistent,
            "dataset_matches": verification.dataset_matches,
            "checked": verification.checked,
            "modified": verification.modified,
            "added": verification.added,
            "missing": verification.missing,
        },
    }


@app.get("/api/demo")
def get_demo(refresh: bool = False) -> dict[str, Any]:
    """Return the cached demo run, computing it on first request (or on ``?refresh=true``)."""
    global _demo_cache
    if _demo_cache is None or refresh:
        try:
            _demo_cache = _run_demo_pipeline()
        except CvTrustError as exc:
            _fail(exc)
    return _demo_cache  # type: ignore[return-value]
