"""ClamAV vs Windows Defender isolation (Phase 24)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import (
    detect_log_source,
    detect_log_source_from_line,
    resolve_log_source,
)

WIN_1116 = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=1116 "
    "LogName=Microsoft-Windows-Windows Defender/Operational "
    "Provider=Microsoft-Windows-Windows Defender "
    "Computer=WIN-WS01 ThreatName=Trojan:Win32/Test"
)
CLAMAV = "Jan 15 10:00:01 scanhost clamd[221]: /tmp/eicar.com: Eicar-Test-Signature FOUND"


def test_defender_event_stays_windows_defender() -> None:
    assert detect_log_source_from_line(WIN_1116) == "windows_defender"
    assert resolve_log_source(Path("clamav.txt"), WIN_1116) == "windows_defender"


def test_clamav_is_antivirus_not_defender() -> None:
    assert detect_log_source_from_line(CLAMAV) == "antivirus"
    assert resolve_log_source(Path("defender.txt"), CLAMAV) == "antivirus"
    assert detect_log_source_from_line(CLAMAV) != "windows_defender"


def test_defender_txt_filename_stays_windows() -> None:
    assert detect_log_source(Path("defender.txt")) == "windows_defender"
    assert detect_log_source(Path("clamav.txt")) == "antivirus"
