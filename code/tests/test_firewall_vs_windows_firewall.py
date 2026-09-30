"""Network firewall vs Windows Filtering Platform isolation (Phase 23)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

WIN_5156 = (
    "TimeCreated=2024-01-15T14:00:01.000Z EventID=5156 "
    "LogName=Microsoft-Windows-Windows Firewall With Advanced Security/Firewall "
    "Provider=Microsoft-Windows-Windows Firewall With Advanced Security "
    "Computer=WIN-SRV01 SourceAddress=10.0.0.8 DestAddress=10.0.0.1"
)
WIN_5157 = (
    "TimeCreated=2024-01-15T14:00:02.000Z EventID=5157 "
    "LogName=Microsoft-Windows-Windows Firewall With Advanced Security/Firewall "
    "Provider=Microsoft-Windows-Windows Firewall With Advanced Security "
    "Computer=WIN-SRV01 SourceAddress=10.0.0.9 DestAddress=10.0.0.1"
)
PFSENSE = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)


def test_windows_5156_stays_windows_firewall() -> None:
    assert detect_log_source_from_line(WIN_5156) == "windows_firewall"
    assert resolve_log_source(Path("pfsense.txt"), WIN_5156) == "windows_firewall"
    assert detect_log_source_from_line(WIN_5157) == "windows_firewall"


def test_pfsense_is_firewall_not_windows() -> None:
    assert detect_log_source_from_line(PFSENSE) == "firewall"
    assert resolve_log_source(Path("firewall.txt"), PFSENSE) == "firewall"
    assert detect_log_source_from_line(PFSENSE) != "windows_firewall"


def test_firewall_txt_filename_stays_windows() -> None:
    assert detect_log_source(Path("firewall.txt")) == "windows_firewall"
    assert detect_log_source(Path("pfsense.txt")) == "firewall"
    assert detect_log_source(Path("windows_firewall.log")) == "windows_firewall"
