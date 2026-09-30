"""PKI syslog year-carry vs JSON no-carry (Phase 35)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

CA_DEC = "Dec 31 23:59:00 ca1 cfssl[9]: issued cn=web.example.com serial=1"
CA_JAN = "Jan  1 00:00:01 ca1 cfssl[9]: revoked cn=api.example.com serial=2"
HSM_DEC = "Dec 31 23:59:00 hsm1 pkcs11[9]: slot=0 op=sign user=alice"
HSM_JAN = "Jan  1 00:00:01 hsm1 pkcs11[9]: slot=0 op=verify user=bob"
CT = (
    '{"domain":"web.example.com","issuer":"Lets Encrypt","event":"seen",'
    '"ts":"2024-01-15T10:00:01Z"}'
)
SIGN = '{"hash":"aaa111","signer":"alice","result":"success","ts":"2024-01-15T10:00:01Z"}'


def test_ca_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        CA_DEC, "pki_ca", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        CA_JAN, "pki_ca", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_hsm_syslog_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        HSM_DEC, "hsm", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        HSM_JAN, "hsm", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_ct_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        CT, "ct_log", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_code_signing_json_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        SIGN, "code_signing", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
