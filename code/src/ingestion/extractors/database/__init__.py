"""Database engine family extractors (Phase 26)."""

from src.ingestion.extractors.database.cassandra import extract_cassandra
from src.ingestion.extractors.database.mongodb import extract_mongodb
from src.ingestion.extractors.database.mssql import extract_mssql
from src.ingestion.extractors.database.mysql import extract_mysql
from src.ingestion.extractors.database.oracle import extract_oracle
from src.ingestion.extractors.database.postgres import extract_postgres
from src.ingestion.extractors.database.redis import extract_redis
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

DATABASE_LOG_SOURCES = frozenset(
    {
        "db_postgres",
        "db_mysql",
        "db_mssql",
        "db_oracle",
        "db_mongodb",
        "db_cassandra",
        "db_redis",
    }
)

_EXTRACTORS = {
    "db_postgres": extract_postgres,
    "db_mysql": extract_mysql,
    "db_mssql": extract_mssql,
    "db_oracle": extract_oracle,
    "db_mongodb": extract_mongodb,
    "db_cassandra": extract_cassandra,
    "db_redis": extract_redis,
}

__all__ = [
    "DATABASE_LOG_SOURCES",
    "extract_database_family",
]


def extract_database_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a database ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported database log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
