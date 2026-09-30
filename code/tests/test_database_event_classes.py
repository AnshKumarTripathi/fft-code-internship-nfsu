"""Every engine fixture covers all nine event_class values (Phase 26)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.database.common import EVENT_CLASSES

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "database"

_FILE_FOR_SOURCE = {
    "db_postgres": "postgres.txt",
    "db_mysql": "mysql.txt",
    "db_mssql": "mssql.txt",
    "db_oracle": "oracle.txt",
    "db_mongodb": "mongodb.json",
    "db_cassandra": "cassandra.txt",
    "db_redis": "redis.txt",
}


@pytest.mark.parametrize("log_source", sorted(_FILE_FOR_SOURCE))
@pytest.mark.parametrize("event_class", sorted(EVENT_CLASSES))
def test_engine_fixture_covers_event_class(log_source: str, event_class: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    classes = set()
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=2024)
        if result.extraction_ok:
            classes.add(result.raw_fields.get("event_class"))
    assert event_class in classes
