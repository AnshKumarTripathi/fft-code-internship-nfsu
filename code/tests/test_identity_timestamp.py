"""Identity syslog carry vs JSON no-carry timestamps (Phase 22)."""

from __future__ import annotations

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.syslog_time import SyslogYearState

SLAPD_DEC = (
    'Dec 31 23:59:00 ldap1 slapd[123]: conn=1 op=0 BIND '
    'dn="uid=alice,ou=people,dc=example,dc=com" method=128'
)
SLAPD_JAN = (
    'Jan  1 00:00:01 ldap1 slapd[123]: conn=1 op=0 RESULT tag=97 err=0 text='
)
KDC_DEC = (
    "Dec 31 23:59:00 kdc krb5kdc[123]: AS_REQ 10.0.0.8: ISSUE: alice@EXAMPLE.COM "
    "for krbtgt/EXAMPLE.COM@EXAMPLE.COM"
)
KDC_JAN = (
    "Jan  1 00:00:01 kdc krb5kdc[123]: TGS_REQ 10.0.0.8: ISSUE: alice@EXAMPLE.COM "
    "for HTTP/web.example.com@EXAMPLE.COM"
)
OKTA = (
    '{"uuid":"a1","published":"2024-01-15T10:00:01.000Z",'
    '"eventType":"user.session.start",'
    '"actor":{"alternateId":"alice@example.com"},'
    '"client":{"ipAddress":"10.0.0.8"},'
    '"outcome":{"result":"SUCCESS"}}'
)
VAULT = (
    '{"time":"2024-01-15T10:00:01.123Z","type":"request",'
    '"auth":{"display_name":"token","metadata":{"username":"alice"}},'
    '"request":{"operation":"read","path":"secret/data/foo","remote_address":"10.0.0.8"}}'
)


def test_slapd_syslog_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        SLAPD_DEC, "ldap", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        SLAPD_JAN, "ldap", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_kdc_syslog_still_year_carries() -> None:
    state = SyslogYearState(year=2023)
    first = extract_entity_and_timestamp(
        KDC_DEC, "kerberos_kdc", default_year=2023, year_state=state
    )
    second = extract_entity_and_timestamp(
        KDC_JAN, "kerberos_kdc", default_year=2023, year_state=state
    )
    assert first.event_timestamp is not None
    assert first.event_timestamp.year == 2023
    assert second.event_timestamp is not None
    assert second.event_timestamp.year == 2024


def test_okta_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        OKTA, "idp", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_vault_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        VAULT, "vault", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12
