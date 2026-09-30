"""Email syslog carry vs collab JSON no-carry timestamps (Phase 29)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

SMTP_DEC = "Dec 31 23:59:00 mail postfix/smtpd[1234]: connect from unknown[203.0.113.10]"
SMTP_JAN = "Jan  1 00:00:01 mail postfix/smtpd[1234]: connect from unknown[203.0.113.11]"
COLLAB = (
    '{"platform":"slack","actor":"alice","action":"file_share",'
    '"workspace":"T123","ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
)


def test_postfix_smtp_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        SMTP_DEC, "smtp", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        SMTP_JAN, "smtp", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_collab_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        COLLAB, "collab_audit", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
