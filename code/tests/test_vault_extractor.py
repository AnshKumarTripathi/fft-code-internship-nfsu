"""HashiCorp Vault audit extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source
from src.ingestion.syslog_time import SyslogYearState

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "vault.txt"

VAULT = (
    '{"time":"2024-01-15T10:00:01.123Z","type":"request",'
    '"auth":{"display_name":"token","metadata":{"username":"alice"}},'
    '"request":{"operation":"read","path":"secret/data/foo","remote_address":"10.0.0.8"}}'
)
VAULT_ERR = (
    '{"time":"2024-01-15T10:00:03.123Z","type":"request",'
    '"auth":{"display_name":"token","metadata":{"username":"mallory"}},'
    '"request":{"operation":"read","path":"secret/data/denied","remote_address":"10.0.0.9"},'
    '"error":"permission denied"}'
)


def test_vault_extracts_path_user_ip() -> None:
    assert resolve_log_source(Path("app.log"), VAULT) == "vault"
    result = extract_entity_and_timestamp(VAULT, "vault", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["path"] == "secret/data/foo"
    assert result.raw_fields["src_ip"] == "10.0.0.8"
    assert result.raw_fields["protocol"] == "vault"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_vault_error_is_failure() -> None:
    result = extract_entity_and_timestamp(VAULT_ERR, "vault", default_year=1999)
    assert result.raw_fields["auth_result"] == "failure"


def test_vault_does_not_mutate_year_state() -> None:
    state = SyslogYearState(year=1999, prev_month=12)
    result = extract_entity_and_timestamp(
        VAULT, "vault", default_year=1999, year_state=state
    )
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024
    assert state.year == 1999
    assert state.prev_month == 12


def test_vault_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "vault", default_year=2024).extraction_ok
        for line in lines
    )
