"""Application timestamps do not mutate syslog year-carry (Phase 25)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

COMBINED = (
    '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
)
IIS = (
    "2024-01-15 10:00:01 10.0.0.1 GET /index.html - 80 - 10.0.0.8 Mozilla/5.0 200 0 0 123"
)
RUNTIME = (
    '{"ts":"2024-01-15T10:00:01.000Z","level":"info","msg":"started","service":"api"}'
)
KONG = (
    '{"latencies":{"request":12},"started_at":1705312801000,"client_ip":"10.0.0.8",'
    '"request":{"method":"GET","uri":"/api"},"response":{"status":200},'
    '"service":{"name":"user-service"}}'
)


def test_combined_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        COMBINED, "web_access", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_iis_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        IIS, "web_access", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999


def test_app_runtime_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        RUNTIME, "app_runtime", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999


def test_kong_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        KONG, "api_gateway", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
