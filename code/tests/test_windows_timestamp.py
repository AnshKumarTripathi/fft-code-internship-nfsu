"""Windows timestamp parsing does not use syslog year-carry (Phase 20)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

WIN_ISO = (
    "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)
WIN_US = (
    "TimeCreated=1/15/2024 10:00:01 AM EventID=4624 LogName=Security "
    "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
)
SSH_DEC = "Dec 31 23:59:00 testhost sshd[1]: Failed password for alice from 1.2.3.4"
SSH_JAN = "Jan  1 00:00:01 testhost sshd[2]: Failed password for bob from 5.6.7.8"


def test_iso8601_year_not_default_year() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        WIN_ISO,
        "windows_security",
        default_year=1999,
        year_state=state,
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_us_datetime_parsed() -> None:
    result = extract_entity_and_timestamp(WIN_US, "windows_security", default_year=1999)
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert result.event_timestamp.month == 1
    assert result.event_timestamp.day == 15
    assert result.event_timestamp.hour == 10


def test_windows_line_does_not_advance_syslog_year_carry() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        SSH_DEC, "ssh", default_year=2023, year_state=state
    )
    extract_entity_and_timestamp(
        WIN_ISO, "windows_security", default_year=2023, year_state=state
    )
    third = extract_entity_and_timestamp(
        SSH_JAN, "ssh", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert third.event_timestamp is not None
    assert third.event_timestamp.year == 2024
