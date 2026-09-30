"""linux_wtmp last/utmpdump extractor tests (Phase 19)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

LAST = "alice    pts/0        192.168.1.10    Sun Aug 16 10:00:01 2026   still logged in"
UTMPDUMP = (
    "[7] [12345] [pts/0] [alice] [192.168.1.10] [0.0.0.0] [Sun Aug 16 10:00:00 2026]"
)
BOOT = "reboot   system boot  5.15.0-76-generic Sun Aug 16 07:00:00 2026"


def test_last_line_user_and_timestamp() -> None:
    assert resolve_log_source(Path("last.log"), LAST) == "linux_wtmp"
    result = extract_entity_and_timestamp(LAST, "linux_wtmp", default_year=2020)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "192.168.1.10"
    assert result.raw_fields["tty"] == "pts/0"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2026
    assert result.event_timestamp.month == 8
    assert result.event_timestamp.day == 16


def test_utmpdump_line() -> None:
    result = extract_entity_and_timestamp(UTMPDUMP, "linux_wtmp", default_year=2020)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["src_ip"] == "192.168.1.10"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2026


def test_last_boot_line() -> None:
    result = extract_entity_and_timestamp(BOOT, "linux_wtmp", default_year=2026)
    assert result.extraction_ok is True
    assert result.entity_id == "reboot"
    assert result.raw_fields["hostname"] == "5.15.0-76-generic"
