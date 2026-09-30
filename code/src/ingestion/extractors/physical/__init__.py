"""Physical-security / IoT family extractors (Phase 33)."""

from src.ingestion.extractors.physical.badge import extract_badge
from src.ingestion.extractors.physical.bms import extract_bms
from src.ingestion.extractors.physical.cctv import extract_cctv
from src.ingestion.extractors.physical.ics import extract_ics
from src.ingestion.extractors.physical.iot import extract_iot
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

PHYSICAL_LOG_SOURCES = frozenset(
    {
        "badge",
        "cctv",
        "bms",
        "iot",
        "ics",
    }
)

_EXTRACTORS = {
    "badge": extract_badge,
    "cctv": extract_cctv,
    "bms": extract_bms,
    "iot": extract_iot,
    "ics": extract_ics,
}

__all__ = [
    "PHYSICAL_LOG_SOURCES",
    "extract_physical_family",
]


def extract_physical_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a physical ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported physical log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
