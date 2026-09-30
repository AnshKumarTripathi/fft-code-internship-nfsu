"""Application and web-server family extractors (Phase 25)."""

from src.ingestion.extractors.application.api_audit import extract_api_audit
from src.ingestion.extractors.application.api_gateway import extract_api_gateway
from src.ingestion.extractors.application.apm import extract_apm
from src.ingestion.extractors.application.app_exception import extract_app_exception
from src.ingestion.extractors.application.app_runtime import extract_app_runtime
from src.ingestion.extractors.application.feature_flag import extract_feature_flag
from src.ingestion.extractors.application.web_access import extract_web_access
from src.ingestion.extractors.application.web_error import extract_web_error
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

APPLICATION_LOG_SOURCES = frozenset(
    {
        "web_access",
        "web_error",
        "app_runtime",
        "app_exception",
        "api_gateway",
        "api_audit",
        "feature_flag",
        "apm",
    }
)

_EXTRACTORS = {
    "web_access": extract_web_access,
    "web_error": extract_web_error,
    "app_runtime": extract_app_runtime,
    "app_exception": extract_app_exception,
    "api_gateway": extract_api_gateway,
    "api_audit": extract_api_audit,
    "feature_flag": extract_feature_flag,
    "apm": extract_apm,
}

__all__ = [
    "APPLICATION_LOG_SOURCES",
    "extract_application_family",
]


def extract_application_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch an application ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported application log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
