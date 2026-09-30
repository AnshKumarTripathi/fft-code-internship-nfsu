"""PostgreSQL stderr extractor tests (Phase 26)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "database" / "postgres.txt"

QUERY = (
    "2024-01-15 10:00:01.123 UTC [12345] alice@appdb LOG:  statement: SELECT 1"
)
SESSION = (
    "2024-01-15 10:00:08.123 UTC [12351] LOG:  connection received: host=10.0.0.8 port=54321"
)


def test_query_extracts_user_and_database() -> None:
    assert resolve_log_source(Path("syslog"), QUERY) == "db_postgres"
    result = extract_entity_and_timestamp(QUERY, "db_postgres", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.entity_type == "user"
    assert result.raw_fields["event_class"] == "query"
    assert result.raw_fields["database"] == "appdb"


def test_session_uses_service_when_no_user() -> None:
    result = extract_entity_and_timestamp(SESSION, "db_postgres", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "service"
    assert result.entity_id == "postgres"
    assert result.raw_fields["event_class"] == "session"
