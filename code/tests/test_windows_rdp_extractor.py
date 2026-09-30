"""windows_rdp extractor tests (Phase 20)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "windows" / "rdp.txt"

RDP_21 = (
    "TimeCreated=2024-01-15T11:00:01.000Z EventID=21 "
    "LogName=Microsoft-Windows-TerminalServices-LocalSessionManager/Operational "
    "Provider=Microsoft-Windows-TerminalServices-LocalSessionManager "
    "Computer=WIN-RDS01 User=alice Address=10.0.0.8 SessionID=1"
)
RDP_1149 = (
    "TimeCreated=2024-01-15T11:00:04.000Z EventID=1149 "
    "LogName=Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational "
    "Provider=Microsoft-Windows-TerminalServices-RemoteConnectionManager "
    "Computer=WIN-RDS01 User=bob Address=10.0.0.9"
)
SECURITY_TYPE_10 = (
    "TimeCreated=2024-01-15T10:00:05.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=10 "
    "AuthenticationPackageName=Negotiate"
)


def test_terminalservices_21_is_windows_rdp() -> None:
    assert resolve_log_source(Path("server1.log"), RDP_21) == "windows_rdp"
    result = extract_entity_and_timestamp(RDP_21, "windows_rdp", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["event_id"] == 21
    assert result.raw_fields["event_class"] == "rdp_logon"


def test_1149_is_windows_rdp() -> None:
    assert resolve_log_source(Path("mixed.log"), RDP_1149) == "windows_rdp"
    result = extract_entity_and_timestamp(RDP_1149, "windows_rdp", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "bob"
    assert result.raw_fields["event_id"] == 1149


def test_security_logon_type_10_is_not_rdp() -> None:
    assert resolve_log_source(Path("rdp.txt"), SECURITY_TYPE_10) == "windows_security"


def test_rdp_fixture_has_extraction_ok() -> None:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "windows_rdp", default_year=1999).extraction_ok
        for line in lines
    )
