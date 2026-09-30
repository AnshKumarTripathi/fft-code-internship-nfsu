"""Middleware family extractors (Phase 31)."""

from src.ingestion.extractors.middleware.airflow import extract_airflow
from src.ingestion.extractors.middleware.cache import extract_cache
from src.ingestion.extractors.middleware.esb import extract_esb
from src.ingestion.extractors.middleware.kafka import extract_kafka
from src.ingestion.extractors.middleware.rabbitmq import extract_rabbitmq
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

MIDDLEWARE_LOG_SOURCES = frozenset(
    {
        "kafka",
        "rabbitmq",
        "esb",
        "cache",
        "airflow",
    }
)

_EXTRACTORS = {
    "kafka": extract_kafka,
    "rabbitmq": extract_rabbitmq,
    "esb": extract_esb,
    "cache": extract_cache,
    "airflow": extract_airflow,
}

__all__ = [
    "MIDDLEWARE_LOG_SOURCES",
    "extract_middleware_family",
]


def extract_middleware_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a middleware ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported middleware log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
