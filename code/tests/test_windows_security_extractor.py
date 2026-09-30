"""windows_security extractor tests (Phase 20)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "windows" / "security.txt"

LOGON = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2 "
    "AuthenticationPackageName=Negotiate"
)
FAIL = (
    "TimeCreated=2024-01-15T10:00:02.000Z EventID=4625 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=mallory IpAddress=10.0.0.9 LogonType=3 "
    "AuthenticationPackageName=NTLM"
)
KERBEROS = (
    "TimeCreated=2024-01-15T10:00:03.000Z EventID=4768 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 ServiceName=krbtgt"
)
NTLM = (
    "TimeCreated=2024-01-15T10:00:04.000Z EventID=4776 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=bob WorkstationName=WS-BOB Status=0x0"
)
NTLM_LOGON = (
    "TimeCreated=2024-01-15T10:00:06.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=eve IpAddress=10.0.0.12 LogonType=3 "
    "AuthenticationPackageName=NTLM"
)
LOGON_TYPE_10 = (
    "TimeCreated=2024-01-15T10:00:05.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=10 "
    "AuthenticationPackageName=Negotiate"
)
XML_4624 = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
    "<System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>"
    "<EventID>4624</EventID>"
    '<TimeCreated SystemTime="2024-01-15T10:00:01.0000000Z"/>'
    "<Channel>Security</Channel><Computer>WIN-DC01</Computer></System>"
    '<EventData><Data Name="TargetUserName">alice</Data>'
    '<Data Name="IpAddress">10.0.0.8</Data>'
    '<Data Name="LogonType">2</Data></EventData></Event>'
)


def test_4624_extracts_user_ip_logon_type() -> None:
    assert resolve_log_source(Path("server1.log"), LOGON) == "windows_security"
    result = extract_entity_and_timestamp(LOGON, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["logon_type"] == "2"
    assert result.raw_fields["event_id"] == 4624
    assert result.raw_fields["auth_result"] == "success"
    assert result.raw_fields["event_class"] == "logon"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_4625_failure() -> None:
    result = extract_entity_and_timestamp(FAIL, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "mallory"
    assert result.raw_fields["auth_result"] == "failure"
    assert result.raw_fields["event_class"] == "logon"
    assert result.raw_fields["event_id"] == 4625


def test_4768_kerberos_event_class() -> None:
    assert resolve_log_source(Path("ad.txt"), KERBEROS) == "windows_security"
    result = extract_entity_and_timestamp(KERBEROS, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields["event_class"] == "kerberos"
    assert result.raw_fields["event_id"] == 4768


def test_4776_ntlm_event_class() -> None:
    result = extract_entity_and_timestamp(NTLM, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields["event_class"] == "ntlm"
    assert result.raw_fields["username"] == "bob"
    assert result.raw_fields["workstation"] == "WS-BOB"


def test_4624_logon_type_3_ntlm_event_class() -> None:
    result = extract_entity_and_timestamp(NTLM_LOGON, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields["event_class"] == "ntlm"
    assert result.raw_fields["logon_type"] == "3"


def test_4624_logon_type_10_stays_windows_security() -> None:
    assert resolve_log_source(Path("rdp.txt"), LOGON_TYPE_10) == "windows_security"
    result = extract_entity_and_timestamp(LOGON_TYPE_10, "windows_security", default_year=1999)
    assert result.raw_fields["logon_type"] == "10"
    assert result.raw_fields["event_class"] == "logon"


def test_xml_stretch_4624() -> None:
    assert resolve_log_source(Path("unknown.log"), XML_4624) == "windows_security"
    result = extract_entity_and_timestamp(XML_4624, "windows_security", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["event_id"] == 4624
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_security_fixture_has_extraction_ok() -> None:
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 10
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, "windows_security", default_year=1999)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1
