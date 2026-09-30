"""Linux PAM extractor and SSH isolation (Phase 19)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

SUDO_PAM = (
    "Jan 15 10:15:01 testhost sudo: pam_unix(sudo:session): "
    "session opened for user root by alice(uid=1000)"
)
SU_PAM = (
    "Jan 15 10:17:30 testhost su: pam_unix(su:auth): authentication failure; "
    "logname=alice uid=1000 euid=0 tty=/dev/pts/1 ruser= rhost=  user=bob"
)
SSHD_PAM = (
    "Jan 15 10:21:00 testhost sshd[99]: pam_unix(sshd:auth): authentication failure; "
    "logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root"
)


def test_sudo_pam_extracts_user() -> None:
    result = extract_entity_and_timestamp(SUDO_PAM, "linux_pam", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "root"
    assert result.raw_fields["username"] == "root"
    assert result.raw_fields["hostname"] == "testhost"
    assert result.raw_fields["service"] == "sudo"
    assert result.raw_fields["auth_result"] == "session_opened"


def test_su_pam_auth_failure() -> None:
    result = extract_entity_and_timestamp(SU_PAM, "linux_pam", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "bob"
    assert result.raw_fields["service"] == "su"
    assert result.raw_fields["auth_result"] == "failed"


def test_sshd_pam_is_ssh_not_linux_pam() -> None:
    assert resolve_log_source(Path("pam.log"), SSHD_PAM) == "ssh"
    result = extract_entity_and_timestamp(SSHD_PAM, "ssh", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields["auth_result"] == "pam"
    assert result.entity_id == "root"
