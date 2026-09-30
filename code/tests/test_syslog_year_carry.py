"""Year-carry vs file_mtime syslog timestamp policy."""

from __future__ import annotations

from src.ingestion.syslog_time import (
    SyslogYearState,
    parse_syslog_timestamp,
)


def test_carry_dec_31_then_jan_1_increments_year() -> None:
    state = SyslogYearState(year=2015)
    dec, dec_ok = parse_syslog_timestamp(
        "Dec 31 23:59:59 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_state=state,
        year_policy="carry",
    )
    jan, jan_ok = parse_syslog_timestamp(
        "Jan  1 00:00:01 LabSZ sshd[2]: Failed password for bob from 1.2.3.5",
        default_year=2015,
        year_state=state,
        year_policy="carry",
    )
    assert dec_ok and jan_ok
    assert dec is not None and jan is not None
    assert dec.year == 2015
    assert dec.month == 12
    assert jan.year == 2016
    assert jan.month == 1
    assert jan.day == 1


def test_file_mtime_keeps_both_lines_in_start_year() -> None:
    state = SyslogYearState(year=2015)
    dec, _ = parse_syslog_timestamp(
        "Dec 31 23:59:59 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_state=state,
        year_policy="file_mtime",
    )
    jan, _ = parse_syslog_timestamp(
        "Jan  1 00:00:01 LabSZ sshd[2]: Failed password for bob from 1.2.3.5",
        default_year=2015,
        year_state=state,
        year_policy="file_mtime",
    )
    assert dec is not None and jan is not None
    assert dec.year == 2015
    assert jan.year == 2015


def test_explicit_year_overrides_carry_state() -> None:
    state = SyslogYearState(year=2015)
    parsed, ok = parse_syslog_timestamp(
        "2017 Jan 5 12:34:56 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_state=state,
        year_policy="carry",
    )
    assert ok
    assert parsed is not None
    assert parsed.year == 2017
    assert state.year == 2017


def test_invalid_calendar_date_fails() -> None:
    parsed, ok = parse_syslog_timestamp(
        "Feb 30 12:00:00 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_policy="carry",
    )
    assert ok is False
    assert parsed is None


def test_leap_year_feb_29_2015_fails() -> None:
    parsed, ok = parse_syslog_timestamp(
        "Feb 29 12:00:00 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_policy="carry",
    )
    assert ok is False
    assert parsed is None


def test_backward_month_jump_does_not_invent_year(caplog) -> None:
    state = SyslogYearState(year=2015)
    parse_syslog_timestamp(
        "Mar 10 12:00:00 LabSZ sshd[1]: Failed password for alice from 1.2.3.4",
        default_year=2015,
        year_state=state,
        year_policy="carry",
    )
    jan, ok = parse_syslog_timestamp(
        "Jan  1 00:00:01 LabSZ sshd[2]: Failed password for bob from 1.2.3.5",
        default_year=2015,
        year_state=state,
        year_policy="carry",
    )
    assert ok
    assert jan is not None
    assert jan.year == 2015
    assert state.warned_backward_jump is True
    assert "jumped backward" in caplog.text


def test_missing_syslog_prefix_fails() -> None:
    parsed, ok = parse_syslog_timestamp(
        "not a syslog line",
        default_year=2015,
    )
    assert ok is False
    assert parsed is None
