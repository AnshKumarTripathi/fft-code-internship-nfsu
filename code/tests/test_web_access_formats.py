"""Apache combined, Nginx combined, and IIS W3C access formats (Phase 25)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "application"

_FILES = ("apache_combined.txt", "nginx_access.txt", "iis_w3c.txt")


def _data_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


@pytest.mark.parametrize("filename", _FILES)
def test_access_format_extracts_required_fields(filename: str) -> None:
    path = FIXTURE_DIR / filename
    lines = _data_lines(path)
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == "web_access"
    result = extract_entity_and_timestamp(lines[0], "web_access", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields.get("src_ip")
    assert result.raw_fields.get("status")
    assert result.raw_fields.get("method")
    assert result.raw_fields.get("path")
    ok = sum(
        1
        for line in lines
        if extract_entity_and_timestamp(line, "web_access", default_year=2024).extraction_ok
    )
    assert ok >= 1
