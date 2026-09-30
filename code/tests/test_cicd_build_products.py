"""Four CI products all resolve to cicd_build (Phase 30)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "cicd"

_PRODUCT_FILES = {
    "jenkins": "jenkins.txt",
    "gha": "gha.txt",
    "gitlab": "gitlab.json",
    "circleci": "circleci.txt",
}

APP_RUNTIME = '{"level":"info","msg":"hello","ts":"2024-01-15T10:00:01Z"}'


@pytest.mark.parametrize("product", sorted(_PRODUCT_FILES))
def test_ci_product_is_cicd_build(product: str) -> None:
    path = FIXTURE_DIR / _PRODUCT_FILES[product]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    assert resolve_log_source(path, lines[0]) == "cicd_build"
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, "cicd_build", default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1


def test_generic_app_runtime_stays_app_runtime() -> None:
    assert detect_log_source_from_line(APP_RUNTIME) == "app_runtime"
    assert resolve_log_source(Path("jenkins.txt"), APP_RUNTIME) == "app_runtime"
