"""PBX CDR extraction (``pbx``)."""

from __future__ import annotations

import csv
import io

from src.ingestion.extractors.telephony.common import (
    YEAR_POLICY_CARRY,
    build_telephony_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_pbx(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src extension as user from a PBX CSV CDR row."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    lower = stripped.lower()
    if lower.startswith("src,") or lower.startswith("ts,src,"):
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="pbx CSV header",
        )
    return _extract_csv(stripped)


def _extract_csv(line: str) -> ExtractionResult:
    reader = csv.reader(io.StringIO(line))
    try:
        row = next(reader)
    except csv.Error:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no pbx CSV entity extracted",
        )
    ts_raw = ""
    if len(row) >= 5 and "T" in row[0]:
        ts_raw, src, dst, duration, disposition = row[0], row[1], row[2], row[3], row[4]
    elif len(row) >= 4:
        src, dst, duration, disposition = row[0], row[1], row[2], row[3]
    else:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no pbx CSV entity extracted",
        )
    extra: dict[str, str] = {}
    if dst:
        extra["dst"] = dst
    if duration:
        extra["duration"] = duration
    if disposition:
        extra["disposition"] = disposition
    event_timestamp = parse_iso_datetime(ts_raw) if ts_raw else None
    return build_telephony_extraction_result(
        username=src,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no pbx CSV entity extracted",
    )
