"""Parametrized application subtype extractors excluding access formats (Phase 25)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.application import APPLICATION_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "application"

_FILE_FOR_SOURCE = {
    "web_error": "web_error.txt",
    "app_runtime": "app_runtime.json",
    "app_exception": "app_exception.txt",
    "api_gateway": "kong.json",
    "api_audit": "api_audit.json",
    "feature_flag": "feature_flag.json",
    "apm": "apm.json",
}


@pytest.mark.parametrize("log_source", sorted(_FILE_FOR_SOURCE))
def test_subtype_fixture_extracts(log_source: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == log_source
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1


def test_all_application_sources_have_fixtures() -> None:
    access_files = ("apache_combined.txt", "nginx_access.txt", "iis_w3c.txt")
    for name in access_files:
        assert (FIXTURE_DIR / name).is_file()
    missing = [
        source
        for source in sorted(APPLICATION_LOG_SOURCES)
        if source != "web_access" and not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []
    assert "web_access" in APPLICATION_LOG_SOURCES
