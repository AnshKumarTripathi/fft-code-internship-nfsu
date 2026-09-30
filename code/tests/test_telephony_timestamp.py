"""Telephony syslog year-carry vs JSON no-carry (Phase 34)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

VOIP_DEC = (
    "Dec 31 23:59:00 sip1 kamailio[9]: REGISTER sip:alice@example.com "
    "from 10.0.0.8 - 200 OK"
)
VOIP_JAN = (
    "Jan  1 00:00:01 sip1 kamailio[9]: REGISTER sip:bob@example.com "
    "from 10.0.0.9 - 401 Unauthorized"
)
VIDEO = (
    '{"meeting_id":"m-1001","organizer":"alice","join":true,'
    '"ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
)
IVR = '{"call_id":"c-1001","menu":"billing","agent":"alice","ts":"2024-01-15T10:00:01Z"}'


def test_voip_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        VOIP_DEC, "voip", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        VOIP_JAN, "voip", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_video_conf_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        VIDEO, "video_conf", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_ivr_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        IVR, "ivr", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
