"""Zeek / Bro TSV family extractors (Phase 83)."""

from __future__ import annotations

from src.ingestion.extractors.zeek.conn import extract_zeek_conn
from src.ingestion.extractors.zeek.dns import extract_zeek_dns
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ZEEK_LOG_SOURCES = frozenset({"zeek_conn", "zeek_dns"})

_EXTRACTORS = {
    "zeek_conn": extract_zeek_conn,
    "zeek_dns": extract_zeek_dns,
}

__all__ = [
    "ZEEK_LOG_SOURCES",
    "extract_zeek_family",
]


def extract_zeek_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a Zeek ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported zeek log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
