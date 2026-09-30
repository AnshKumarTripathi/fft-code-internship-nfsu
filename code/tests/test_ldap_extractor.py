"""ldap extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "ldap.txt"

BIND = (
    'Jan 15 10:00:01 ldap1 slapd[123]: conn=1001 op=0 BIND '
    'dn="uid=alice,ou=people,dc=example,dc=com" method=128'
)
FAIL = (
    "Jan 15 10:00:02 ldap1 slapd[123]: conn=1002 op=0 RESULT tag=97 err=49 "
    "text=Invalid credentials"
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"


def test_bind_extracts_uid_username() -> None:
    assert resolve_log_source(Path("syslog"), BIND) == "ldap"
    result = extract_entity_and_timestamp(BIND, "ldap", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["protocol"] == "ldap"
    assert result.raw_fields["bind_dn"].startswith("uid=alice")


def test_err_49_is_failure() -> None:
    result = extract_entity_and_timestamp(FAIL, "ldap", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields["auth_result"] == "failure"
    assert result.raw_fields["ldap_err"] == "49"


def test_slapd_is_not_linux_syslog() -> None:
    assert resolve_log_source(Path("syslog"), BIND) == "ldap"
    assert resolve_log_source(Path("syslog"), SYSLOG) == "linux_syslog"


def test_ldap_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "ldap", default_year=2024).extraction_ok
        for line in lines
    )
