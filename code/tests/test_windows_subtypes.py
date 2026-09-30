"""Parametrized remaining Windows subtype extractors (Phase 20)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.windows import WINDOWS_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "windows"

# security and rdp have dedicated test modules; still require fixtures here.
SUBTYPES = (
    "windows_system",
    "windows_application",
    "windows_setup",
    "windows_forwarded",
    "windows_powershell",
    "windows_defender",
    "windows_task_scheduler",
    "windows_wmi",
    "windows_gpo",
    "windows_print",
    "windows_firewall",
    "windows_bitlocker",
    "windows_ad",
)

_FILE_FOR_SOURCE = {
    "windows_system": "system.txt",
    "windows_application": "application.txt",
    "windows_setup": "setup.txt",
    "windows_forwarded": "forwarded.txt",
    "windows_powershell": "powershell.txt",
    "windows_defender": "defender.txt",
    "windows_task_scheduler": "task_scheduler.txt",
    "windows_wmi": "wmi.txt",
    "windows_gpo": "gpo.txt",
    "windows_print": "print.txt",
    "windows_firewall": "firewall.txt",
    "windows_bitlocker": "bitlocker.txt",
    "windows_ad": "ad.txt",
    "windows_security": "security.txt",
    "windows_rdp": "rdp.txt",
}


@pytest.mark.parametrize("log_source", SUBTYPES)
def test_subtype_fixture_extracts(log_source: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == log_source
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=1999)
        if result.extraction_ok:
            ok += 1
            assert result.event_timestamp is not None
            assert result.event_timestamp.year == 2024
    assert ok >= 1


def test_all_windows_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(WINDOWS_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []


def test_forwarded_stores_inner_channel() -> None:
    line = (
        FIXTURE_DIR / "forwarded.txt"
    ).read_text(encoding="utf-8").splitlines()[0]
    result = extract_entity_and_timestamp(line, "windows_forwarded", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields.get("forwarded_channel") == "Security"


def test_ad_is_not_security_event_id() -> None:
    line = (FIXTURE_DIR / "ad.txt").read_text(encoding="utf-8").splitlines()[0]
    assert resolve_log_source(Path("unknown.log"), line) == "windows_ad"
    result = extract_entity_and_timestamp(line, "windows_ad", default_year=1999)
    assert result.raw_fields["event_id"] == 2889
    assert result.raw_fields["event_class"] == "ad"
