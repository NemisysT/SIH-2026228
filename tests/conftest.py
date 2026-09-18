"""Shared fixtures.

The synthetic corpus is generated once per session and reused: generation is
deterministic, so sharing it costs nothing in isolation and saves the whole
suite from re-rendering several hundred images per test module.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from cvtrust.attack_lab.synth import generate_clean_dataset
from cvtrust.core.config import Config

logging.getLogger("cvtrust").setLevel(logging.ERROR)

#: Small enough for a fast suite, large enough that class-support minimums,
#: kNN neighbourhoods and the OOD covariance estimate are all satisfied.
PER_CLASS = 8
SEED = 20260917


@pytest.fixture(scope="session")
def clean_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("clean")
    generate_clean_dataset(
        out, seed=SEED, per_class_per_contributor=PER_CLASS, export_coco=True, export_yolo=True
    )
    return out


@pytest.fixture(scope="session")
def clean_root(clean_dir: Path) -> Path:
    return clean_dir / "dataset"


@pytest.fixture
def config() -> Config:
    return Config()
