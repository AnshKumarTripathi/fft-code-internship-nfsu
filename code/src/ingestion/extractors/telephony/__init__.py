"""Telephony family extractors (Phase 34)."""

from src.ingestion.extractors.telephony.ivr import extract_ivr
from src.ingestion.extractors.telephony.pbx import extract_pbx
from src.ingestion.extractors.telephony.video_conf import extract_video_conf
from src.ingestion.extractors.telephony.voip import extract_voip
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

TELEPHONY_LOG_SOURCES = frozenset(
    {
        "voip",
        "pbx",
        "video_conf",
        "ivr",
    }
)

_EXTRACTORS = {
    "voip": extract_voip,
    "pbx": extract_pbx,
    "video_conf": extract_video_conf,
    "ivr": extract_ivr,
}

__all__ = [
    "TELEPHONY_LOG_SOURCES",
    "extract_telephony_family",
]


def extract_telephony_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a telephony ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported telephony log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
