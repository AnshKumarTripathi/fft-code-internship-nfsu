"""Physical syslog year-carry vs CCTV/IoT JSON no-carry (Phase 33)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

BADGE_DEC = (
    "Dec 31 23:59:00 acs1 accessd[12]: badge_id=B-1001 door=lobby result=allow"
)
BADGE_JAN = (
    "Jan  1 00:00:01 acs1 accessd[12]: badge_id=B-1002 door=lab result=deny"
)
ICS_DEC = "Dec 31 23:59:00 scada1 icsd[9]: plc=PLC01 tag=TI101 value=72.5"
ICS_JAN = "Jan  1 00:00:01 scada1 icsd[9]: plc=PLC01 tag=TI101 value=68.0"
CCTV = '{"camera_id":"cam-lobby","event":"motion","ts":"2024-01-15T10:00:01Z"}'
IOT = (
    '{"device_id":"sensor-01","fw_version":"1.2.0","event":"telemetry",'
    '"ts":"2024-01-15T10:00:01Z"}'
)


def test_badge_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        BADGE_DEC, "badge", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        BADGE_JAN, "badge", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_ics_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        ICS_DEC, "ics", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        ICS_JAN, "ics", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_cctv_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        CCTV, "cctv", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_iot_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        IOT, "iot", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
