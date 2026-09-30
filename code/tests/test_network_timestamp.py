"""Network syslog carry vs Squid/nfdump no-carry timestamps (Phase 23)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

PFSENSE_DEC = (
    "Dec 31 23:59:00 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)
PFSENSE_JAN = (
    "Jan  1 00:00:01 fw1 filterlog[219]: 9,,,1000000104,em0,match,pass,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.9,8.8.8.8,53100,443,0,S,112,,65535,,"
)
CISCO_DEC = (
    "Dec 31 23:59:00 router1 101: %LINEPROTO-5-UPDOWN: Line protocol on Interface "
    "GigabitEthernet0/1, changed state to down"
)
CISCO_JAN = (
    "Jan  1 00:00:01 router1 102: %LINEPROTO-5-UPDOWN: Line protocol on Interface "
    "GigabitEthernet0/1, changed state to up"
)
SQUID = (
    "1705312801.123    312 10.0.0.8 TCP_MISS/200 1234 GET http://example.com/ "
    "alice HIER_DIRECT/1.2.3.4 text/html"
)
NFDUMP = "2024-01-15 10:00:01.012   1.234 TCP     10.0.0.8:54321 ->      1.2.3.4:443        10     800     1"


def test_pfsense_syslog_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        PFSENSE_DEC, "firewall", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        PFSENSE_JAN, "firewall", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_cisco_syslog_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        CISCO_DEC, "network_device", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        CISCO_JAN, "network_device", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_squid_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        SQUID, "proxy", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_nfdump_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        NFDUMP, "netflow", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
