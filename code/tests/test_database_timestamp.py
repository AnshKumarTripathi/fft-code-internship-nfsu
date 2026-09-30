"""Database timestamps do not mutate syslog year-carry state (Phase 26)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

POSTGRES = (
    "2024-01-15 10:00:01.123 UTC [12345] alice@appdb LOG:  statement: SELECT 1"
)
MONGO = (
    '{"t":{"$date":"2024-01-15T10:00:01.000Z"},"s":"I","c":"NETWORK","id":22943,'
    '"ctx":"listener","msg":"Connection accepted",'
    '"attr":{"remote":"10.0.0.8:54321","connectionId":1}}'
)
REDIS = "12345:M 15 Jan 2024 10:00:01.123 * Ready to accept connections"


def test_postgres_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        POSTGRES, "db_postgres", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_mongo_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        MONGO, "db_mongodb", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_redis_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        REDIS, "db_redis", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
