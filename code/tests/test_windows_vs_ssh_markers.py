"""Windows vs SSH (and Linux auth) marker isolation (Phase 20)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

SSH = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SUDO = (
    "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
    "USER=root ; COMMAND=/bin/ls"
)
WIN = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)
KERBEROS = (
    "TimeCreated=2024-01-15T10:00:03.000Z EventID=4768 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8"
)


def test_windows_line_is_never_ssh() -> None:
    assert detect_log_source_from_line(WIN) == "windows_security"
    assert resolve_log_source(Path("auth.log"), WIN) == "windows_security"
    assert not detect_log_source_from_line(WIN) == "ssh"


def test_ssh_line_is_never_windows() -> None:
    assert detect_log_source_from_line(SSH) == "ssh"
    assert resolve_log_source(Path("security.evtx.txt"), SSH) == "ssh"
    source = detect_log_source_from_line(SSH)
    assert source is not None
    assert not source.startswith("windows_")


def test_linux_auth_is_not_windows() -> None:
    assert detect_log_source_from_line(SUDO) == "linux_auth"
    assert resolve_log_source(Path("security.txt"), SUDO) == "linux_auth"


def test_kerberos_security_is_not_windows_ad() -> None:
    assert detect_log_source_from_line(KERBEROS) == "windows_security"
    assert resolve_log_source(Path("ad.txt"), KERBEROS) == "windows_security"
