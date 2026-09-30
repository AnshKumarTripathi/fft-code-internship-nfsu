"""linux_auditd extractor tests (Phase 21)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "unix_os" / "auditd.txt"

USER_AUTH = (
    'type=USER_AUTH msg=audit(1705312801.123:456): pid=1234 uid=0 auid=1000 '
    'exe="/usr/sbin/sshd" success=yes acct="alice" hostname=testhost addr=10.0.0.8'
)
USER_LOGIN = (
    'type=USER_LOGIN msg=audit(1705312802.123:457): pid=1234 uid=0 auid=1000 '
    'exe="/usr/sbin/sshd" success=yes acct="alice" hostname=testhost addr=10.0.0.8'
)
SYSCALL = (
    'type=SYSCALL msg=audit(1705312803.123:458): arch=c000003e syscall=59 '
    'success=yes pid=2000 auid=1000 uid=1000 exe="/usr/bin/sudo" comm="sudo"'
)
SSH = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"


def test_user_auth_extracts_username() -> None:
    assert resolve_log_source(Path("audit.log"), USER_AUTH) == "linux_auditd"
    result = extract_entity_and_timestamp(USER_AUTH, "linux_auditd", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["audit_type"] == "USER_AUTH"
    assert result.raw_fields["success"] == "yes"
    assert result.raw_fields["exe"] == "/usr/sbin/sshd"
    assert result.raw_fields["auid"] == "1000"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_user_login_extracts_username() -> None:
    result = extract_entity_and_timestamp(USER_LOGIN, "linux_auditd", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["audit_type"] == "USER_LOGIN"


def test_syscall_audit_type() -> None:
    result = extract_entity_and_timestamp(SYSCALL, "linux_auditd", default_year=1999)
    assert result.extraction_ok is True
    assert result.raw_fields["audit_type"] == "SYSCALL"
    assert result.raw_fields["exe"] == "/usr/bin/sudo"


def test_auditd_with_sshd_exe_is_not_ssh() -> None:
    assert resolve_log_source(Path("auth.log"), USER_AUTH) == "linux_auditd"
    assert resolve_log_source(Path("audit.log"), SSH) == "ssh"


def test_auditd_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "linux_auditd", default_year=2024).extraction_ok
        for line in lines
    )
