"""MIT kerberos_kdc extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "kerberos_kdc.txt"
)

AS_REQ = (
    "Jan 15 10:00:01 kdc krb5kdc[123]: AS_REQ (6 etypes {18 17 16 23 25 26}) "
    "10.0.0.8: ISSUE: authtime 1705312801, alice@EXAMPLE.COM for "
    "krbtgt/EXAMPLE.COM@EXAMPLE.COM"
)
WIN_4768 = (
    "TimeCreated=2024-01-15T10:00:03.000Z EventID=4768 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8"
)


def test_as_req_extracts_principal() -> None:
    assert resolve_log_source(Path("messages"), AS_REQ) == "kerberos_kdc"
    result = extract_entity_and_timestamp(AS_REQ, "kerberos_kdc", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["req_type"] == "AS_REQ"
    assert result.raw_fields["auth_result"] == "success"
    assert result.raw_fields["src_ip"] == "10.0.0.8"


def test_as_req_is_not_windows_security() -> None:
    assert resolve_log_source(Path("security.txt"), AS_REQ) == "kerberos_kdc"
    assert resolve_log_source(Path("kdc.log"), WIN_4768) == "windows_security"


def test_kerberos_kdc_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "kerberos_kdc", default_year=2024).extraction_ok
        for line in lines
    )
