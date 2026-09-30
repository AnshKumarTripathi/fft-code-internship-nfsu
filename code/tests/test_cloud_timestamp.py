"""Cloud timestamps do not mutate syslog year-carry state (Phase 27)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

TRAIL = (
    '{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:01Z",'
    '"eventSource":"iam.amazonaws.com","eventName":"ConsoleLogin",'
    '"userIdentity":{"type":"IAMUser","userName":"alice",'
    '"arn":"arn:aws:iam::123456789012:user/alice"},'
    '"sourceIPAddress":"10.0.0.8"}'
)
ALB = (
    "h2 2024-01-15T10:00:01.000000Z app/my-loadbalancer/50dc6c495c0c9188 "
    "192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "
    '"GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0"'
)


def test_cloudtrail_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        TRAIL, "aws_cloudtrail", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_alb_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        ALB, "aws_elb", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
