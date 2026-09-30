"""Network firewall vs SSH marker isolation (Phase 23)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

SSH_FAIL = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SSH_ACCEPT = (
    "Jan 15 10:00:02 testhost sshd[1]: Accepted publickey for alice from 1.2.3.4 "
    "port 22 ssh2"
)
PFSENSE = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)
WEAK_ALLOW = "ALLOW tcp 10.0.0.1 -> 10.0.0.2"
WEAK_DENY = "deny from 10.0.0.8 to 1.2.3.4"
RADIUS = "Auth: Login OK [alice] cli 10.0.0.8"
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"


def test_ssh_not_firewall() -> None:
    assert detect_log_source_from_line(SSH_FAIL) == "ssh"
    assert detect_log_source_from_line(SSH_ACCEPT) == "ssh"
    assert resolve_log_source(Path("pfsense.txt"), SSH_FAIL) == "ssh"
    assert resolve_log_source(Path("firewall.log"), SSH_FAIL) == "ssh"


def test_pfsense_not_ssh() -> None:
    assert detect_log_source_from_line(PFSENSE) == "firewall"
    assert resolve_log_source(Path("auth.log"), PFSENSE) == "firewall"


def test_weak_allow_deny_do_not_steal() -> None:
    assert detect_log_source_from_line(WEAK_ALLOW) is None
    assert detect_log_source_from_line(WEAK_DENY) is None
    assert detect_log_source_from_line(SSH_FAIL) == "ssh"


def test_radius_and_generic_syslog_untouched() -> None:
    assert detect_log_source_from_line(RADIUS) == "radius"
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
