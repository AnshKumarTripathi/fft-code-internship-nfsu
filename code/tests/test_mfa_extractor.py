"""Duo MFA extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "mfa.txt"

DUO_OK = (
    '{"isotimestamp":"2024-01-15T10:00:01+00:00","username":"alice",'
    '"eventtype":"authentication","result":"success","ip":"10.0.0.8"}'
)
DUO_FAIL = (
    '{"isotimestamp":"2024-01-15T10:00:02+00:00","username":"mallory",'
    '"eventtype":"authentication","result":"failure","ip":"10.0.0.9"}'
)
DUO_SYSLOG = (
    "Jan 15 10:00:06 duo duo_auth_proxy[1]: Success. Logging you in... "
    "user=alice ip=10.0.0.8"
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
IDP = (
    '{"uuid":"a1","published":"2024-01-15T10:00:01.000Z",'
    '"eventType":"user.session.start",'
    '"actor":{"alternateId":"alice@example.com"},'
    '"client":{"ipAddress":"10.0.0.8"},'
    '"outcome":{"result":"SUCCESS"}}'
)


def test_duo_json_success_and_failure() -> None:
    assert resolve_log_source(Path("duo.log"), DUO_OK) == "mfa"
    ok = extract_entity_and_timestamp(DUO_OK, "mfa", default_year=1999)
    assert ok.extraction_ok is True
    assert ok.entity_id == "alice"
    assert ok.raw_fields["auth_result"] == "success"
    assert ok.raw_fields["protocol"] == "duo"
    fail = extract_entity_and_timestamp(DUO_FAIL, "mfa", default_year=1999)
    assert fail.raw_fields["auth_result"] == "failure"


def test_duo_syslog_is_not_linux_syslog() -> None:
    assert resolve_log_source(Path("syslog"), DUO_SYSLOG) == "mfa"
    assert resolve_log_source(Path("syslog"), SYSLOG) == "linux_syslog"
    result = extract_entity_and_timestamp(DUO_SYSLOG, "mfa", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"


def test_duo_is_not_idp() -> None:
    assert resolve_log_source(Path("idp.txt"), DUO_OK) == "mfa"
    assert resolve_log_source(Path("duo.log"), IDP) == "idp"


def test_mfa_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "mfa", default_year=2024).extraction_ok
        for line in lines
    )
