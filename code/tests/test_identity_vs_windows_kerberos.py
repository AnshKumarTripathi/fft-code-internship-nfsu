"""Identity vs SSH / Windows Kerberos marker isolation (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

SSH = "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
WIN_4768 = (
    "TimeCreated=2024-01-15T10:00:03.000Z EventID=4768 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8"
)
WIN_4769 = (
    "TimeCreated=2024-01-15T10:00:04.000Z EventID=4769 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8"
)
KDC = (
    "Jan 15 10:00:01 kdc krb5kdc[123]: AS_REQ (6 etypes {18 17 16}) "
    "10.0.0.8: ISSUE: authtime 1705312801, alice@EXAMPLE.COM for "
    "krbtgt/EXAMPLE.COM@EXAMPLE.COM"
)
AUDIT = (
    'type=USER_AUTH msg=audit(1705312801.123:456): pid=1234 uid=0 auid=1000 '
    'exe="/usr/sbin/sshd" success=yes acct="alice"'
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"


def test_windows_4768_stays_windows_security() -> None:
    assert detect_log_source_from_line(WIN_4768) == "windows_security"
    assert resolve_log_source(Path("kdc.log"), WIN_4768) == "windows_security"
    assert detect_log_source_from_line(WIN_4769) == "windows_security"


def test_mit_kdc_is_kerberos_kdc() -> None:
    assert detect_log_source_from_line(KDC) == "kerberos_kdc"
    assert resolve_log_source(Path("security.txt"), KDC) == "kerberos_kdc"


def test_ssh_not_identity() -> None:
    assert detect_log_source_from_line(SSH) == "ssh"
    assert resolve_log_source(Path("ldap.log"), SSH) == "ssh"
    assert resolve_log_source(Path("okta.json"), SSH) == "ssh"


def test_identity_not_ssh() -> None:
    assert detect_log_source_from_line(KDC) != "ssh"
    slapd = (
        'Jan 15 10:00:01 ldap1 slapd[123]: conn=1 op=0 BIND '
        'dn="uid=alice,ou=people,dc=example,dc=com" method=128'
    )
    assert detect_log_source_from_line(slapd) == "ldap"
    assert resolve_log_source(Path("auth.log"), slapd) == "ldap"


def test_auditd_and_generic_syslog_untouched() -> None:
    assert detect_log_source_from_line(AUDIT) == "linux_auditd"
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
