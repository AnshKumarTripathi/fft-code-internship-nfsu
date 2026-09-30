"""Parametrized telephony subtype extractors (Phase 34)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.telephony import TELEPHONY_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "telephony"

_FILE_FOR_SOURCE = {
    "voip": "voip.txt",
    "pbx": "pbx.csv",
    "video_conf": "video_conf.json",
    "ivr": "ivr.json",
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


def test_all_telephony_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(TELEPHONY_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []
