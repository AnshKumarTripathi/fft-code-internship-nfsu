"""Security JSON no-carry vs ClamAV syslog year-carry (Phase 24)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

CLAM_DEC = (
    "Dec 31 23:59:00 scanhost clamd[221]: /tmp/eicar.com: Eicar-Test-Signature FOUND"
)
CLAM_JAN = (
    "Jan  1 00:00:01 scanhost clamd[221]: /tmp/ransom.exe: Win.Ransomware.Locky FOUND"
)
EVE = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
    '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
    '"alert":{"action":"allowed","severity":2}}'
)
WAF = (
    '{"timestamp":"2024-01-15T10:00:01.000Z","transaction":{"client_ip":"10.0.0.8",'
    '"host_ip":"10.0.0.1","request":{"method":"GET","uri":"/"},'
    '"response":{"http_code":200},"action":"allow"}}'
)


def test_clamav_syslog_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        CLAM_DEC, "antivirus", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        CLAM_JAN, "antivirus", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_suricata_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        EVE, "ids_ips", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_waf_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        WAF, "waf", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
