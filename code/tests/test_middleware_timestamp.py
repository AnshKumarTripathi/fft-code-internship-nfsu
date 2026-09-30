"""Middleware JSON no-carry vs syslog-shaped kafka year-carry (Phase 31)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

KAFKA = (
    "[2024-01-15 10:00:01,123] INFO [KafkaServer id=0] started (kafka.server.KafkaServer)"
)
RABBIT = (
    "2024-01-15 10:00:01.123 [info] <0.123.0> connection <0.456.0> "
    "(10.0.0.8:54321 -> 10.0.0.1:5672): user 'alice' authenticated "
    "and granted access to vhost '/'"
)
AIRFLOW = (
    "[2024-01-15 10:00:01,123] {taskinstance.py:1159} INFO - DAG: etl_daily Task: extract"
)
ESB = (
    '{"tx_id":"tx-1","route":"/orders","user":"alice","ts":"2024-01-15T10:00:01Z"}'
)
KAFKA_DEC = (
    "Dec 31 23:59:00 kafka1 kafka[12]: [KafkaServer id=0] shutting down "
    "(kafka.server.KafkaServer)"
)
KAFKA_JAN = (
    "Jan  1 00:00:01 kafka1 kafka[12]: [KafkaServer id=0] started "
    "(kafka.server.KafkaServer)"
)


def test_kafka_bracket_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        KAFKA, "kafka", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_rabbit_space_iso_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        RABBIT, "rabbitmq", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999


def test_airflow_bracket_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        AIRFLOW, "airflow", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999


def test_esb_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        ESB, "esb", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_kafka_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        KAFKA_DEC, "kafka", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        KAFKA_JAN, "kafka", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024
