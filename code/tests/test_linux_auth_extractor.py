"""linux_auth (sudo/su/login) extractor tests (Phase 19)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

SUDO = (
    "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
    "USER=root ; COMMAND=/bin/ls"
)
SU = "Jan 15 10:17:00 testhost su[1234]: (to root) alice on pts/0"
LOGIN_FAIL = (
    "Jan 15 10:18:00 testhost login[2001]: FAILED LOGIN 1 FROM 192.168.1.50 "
    "FOR mallory, Authentication failure"
)
SSH = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"


def test_sudo_syslog_is_linux_auth_not_ssh() -> None:
    assert resolve_log_source(Path("auth.log"), SUDO) == "linux_auth"
    result = extract_entity_and_timestamp(SUDO, "linux_auth", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "sudo"
    assert result.raw_fields["tty"] == "pts/0"
    assert result.raw_fields["hostname"] == "testhost"


def test_su_syslog() -> None:
    assert resolve_log_source(Path("secure"), SU) == "linux_auth"
    result = extract_entity_and_timestamp(SU, "linux_auth", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "su"
    assert result.raw_fields["tty"] == "pts/0"


def test_login_failure() -> None:
    result = extract_entity_and_timestamp(LOGIN_FAIL, "linux_auth", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "mallory"
    assert result.raw_fields["src_ip"] == "192.168.1.50"
    assert result.raw_fields["auth_result"] == "login"


def test_ssh_in_auth_log_stays_ssh() -> None:
    assert resolve_log_source(Path("auth.log"), SSH) == "ssh"
