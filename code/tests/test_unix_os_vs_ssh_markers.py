"""Unix OS vs SSH / PAM / Windows marker isolation (Phase 21)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

SSH = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SUDO = (
    "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
    "USER=root ; COMMAND=/bin/ls"
)
PAM = (
    "Jan 15 10:15:01 testhost sudo: pam_unix(sudo:session): "
    "session opened for user root by alice(uid=1000)"
)
WIN = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
AUDIT = (
    'type=USER_AUTH msg=audit(1705312801.123:456): pid=1234 uid=0 auid=1000 '
    'exe="/usr/sbin/sshd" success=yes acct="alice"'
)


def test_ssh_pam_sudo_windows_not_unix_os() -> None:
    assert detect_log_source_from_line(SSH) == "ssh"
    assert detect_log_source_from_line(SUDO) == "linux_auth"
    assert detect_log_source_from_line(PAM) == "linux_pam"
    assert detect_log_source_from_line(WIN) == "windows_security"
    for line in (SSH, SUDO, PAM, WIN):
        source = detect_log_source_from_line(line)
        assert source is not None
        assert source not in {
            "linux_syslog",
            "linux_kern",
            "linux_auditd",
            "linux_journald",
        }


def test_unix_syslog_is_not_ssh() -> None:
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("auth.log"), SYSLOG) == "linux_syslog"


def test_auditd_not_ssh_despite_sshd_exe() -> None:
    assert detect_log_source_from_line(AUDIT) == "linux_auditd"
    assert resolve_log_source(Path("auth.log"), AUDIT) == "linux_auditd"


def test_ssh_line_not_unix_even_in_syslog_file() -> None:
    assert resolve_log_source(Path("syslog"), SSH) == "ssh"
