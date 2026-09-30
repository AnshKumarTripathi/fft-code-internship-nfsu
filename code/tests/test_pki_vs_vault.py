"""PKI CA vs Vault isolation and issued/revoked action (Phase 35)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

VAULT = (
    '{"time":"2024-01-15T10:00:01.123Z","type":"request",'
    '"auth":{"display_name":"token","metadata":{"username":"alice"}},'
    '"request":{"operation":"read","path":"secret/data/foo","remote_address":"10.0.0.8"}}'
)
ISSUED = (
    '{"cn":"web.example.com","action":"issued","user":"alice","ts":"2024-01-15T10:00:01Z"}'
)
REVOKED = '{"cn":"api.example.com","action":"revoked","ts":"2024-01-15T10:00:02Z"}'
SYSLOG_CA = "Jan 15 10:00:01 ca1 cfssl[9]: issued cn=web.example.com serial=1"


def test_vault_json_stays_vault() -> None:
    assert detect_log_source_from_line(VAULT) == "vault"
    assert resolve_log_source(Path("pki_ca.json"), VAULT) == "vault"
    assert resolve_log_source(Path("hsm.json"), VAULT) == "vault"


def test_ca_json_is_pki_ca_even_in_vault_file() -> None:
    assert detect_log_source_from_line(ISSUED) == "pki_ca"
    assert resolve_log_source(Path("vault.json"), ISSUED) == "pki_ca"
    assert detect_log_source_from_line(SYSLOG_CA) == "pki_ca"


def test_issued_sets_action_and_auth_result() -> None:
    result = extract_entity_and_timestamp(ISSUED, "pki_ca", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "user"
    assert result.entity_id == "alice"
    assert result.raw_fields.get("action") == "issued"
    assert result.raw_fields.get("auth_result") == "success"
    assert result.raw_fields.get("cn") == "web.example.com"


def test_revoked_sets_action() -> None:
    result = extract_entity_and_timestamp(REVOKED, "pki_ca", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "service"
    assert result.entity_id == "api.example.com"
    assert result.raw_fields.get("action") == "revoked"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("pki_ca.json")) == "pki_ca"
    assert detect_log_source(Path("vault.json")) == "vault"
