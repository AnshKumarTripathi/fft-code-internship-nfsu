"""Unix OS / macOS timestamps: syslog carry vs no-carry dialects (Phase 21)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

KERN_DEC = "Dec 31 23:59:00 testhost kernel: USB disconnect"
KERN_JAN = "Jan  1 00:00:01 testhost kernel: USB connect"
MACOS = (
    "2024-01-15 10:00:01.123456-0800  0x7f8a  Default     0x0                  "
    "0    0    loginwindow: [com.apple.loginwindow:] user alice logged in"
)
AUDIT = (
    'type=USER_AUTH msg=audit(1705312801.123:456): pid=1234 uid=0 auid=1000 '
    'exe="/usr/sbin/sshd" success=yes acct="alice" hostname=testhost'
)
DMESG = "[Mon Jan 15 10:00:01 2024] usb 1-1: USB disconnect"


def test_syslog_shaped_kern_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        KERN_DEC, "linux_kern", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        KERN_JAN, "linux_kern", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_macos_unified_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        MACOS, "macos_unified", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_auditd_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        AUDIT, "linux_auditd", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_dmesg_t_year_not_default_year() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        DMESG, "linux_dmesg", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999


ASL = (
    "[Time 2024-01-15 10:00:01.123 GMT] [Sender loginwindow] [PID 120] "
    "[Host macbook] [Message user alice logged in]"
)


def test_macos_asl_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        ASL, "macos_asl", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
