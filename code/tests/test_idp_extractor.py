"""Okta / generic eventType IdP extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "idp.txt"

OKTA = (
    '{"uuid":"a1","published":"2024-01-15T10:00:01.000Z",'
    '"eventType":"user.session.start",'
    '"actor":{"alternateId":"alice@example.com","displayName":"Alice"},'
    '"client":{"ipAddress":"10.0.0.8"},'
    '"outcome":{"result":"SUCCESS"}}'
)
VAULT = (
    '{"time":"2024-01-15T10:00:01.123Z","type":"request",'
    '"auth":{"display_name":"token","metadata":{"username":"alice"}},'
    '"request":{"operation":"read","path":"secret/data/foo","remote_address":"10.0.0.8"}}'
)


def test_okta_published_year_and_outcome() -> None:
    assert resolve_log_source(Path("okta.json"), OKTA) == "idp"
    result = extract_entity_and_timestamp(OKTA, "idp", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice@example.com"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert result.raw_fields["auth_result"] == "success"
    assert result.raw_fields["event_type"] == "user.session.start"
    assert result.raw_fields["protocol"] == "saml"


def test_idp_is_not_vault() -> None:
    assert resolve_log_source(Path("idp.txt"), OKTA) == "idp"
    assert resolve_log_source(Path("idp.txt"), VAULT) == "vault"


def test_idp_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "idp", default_year=2024).extraction_ok
        for line in lines
    )
