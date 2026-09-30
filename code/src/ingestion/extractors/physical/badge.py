"""Badge / access-control extraction (``badge``)."""

from __future__ import annotations

import csv
import io
import re

from src.ingestion.extractors.physical.common import (
    YEAR_POLICY_CARRY,
    build_physical_extraction_result,
    extract_syslog_physical_line,
    normalize_auth_result,
    parse_iso_datetime,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

BADGE_ID = re.compile(r"\bbadge_id=(?P<id>\S+)", re.IGNORECASE)
DOOR = re.compile(r"\bdoor=(?P<door>\S+)", re.IGNORECASE)
RESULT = re.compile(r"\b(?:result|action)=(?P<result>\S+)", re.IGNORECASE)


def extract_badge(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract badge_id as user; map allow/deny to auth_result."""
    stripped = line.strip()
    if stripped.lower().startswith("ts,") and "badge_id" in stripped.lower():
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="badge CSV header",
        )
    if "," in stripped and not stripped.startswith("{") and "badge_id=" not in stripped:
        return _extract_csv(stripped)
    badge_match = BADGE_ID.search(line)
    username = badge_match.group("id").rstrip(",;") if badge_match else ""
    extra: dict[str, str] = {}
    door = DOOR.search(line)
    if door:
        extra["door"] = door.group("door").rstrip(",;")
    result_match = RESULT.search(line)
    if result_match:
        extra["auth_result"] = normalize_auth_result(result_match.group("result"))
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_physical_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no badge entity extracted",
        )
    return build_physical_extraction_result(
        username=username,
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no badge entity extracted",
    )


def _extract_csv(line: str) -> ExtractionResult:
    reader = csv.reader(io.StringIO(line))
    try:
        row = next(reader)
    except csv.Error:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no badge CSV entity extracted",
        )
    if len(row) < 4:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no badge CSV entity extracted",
        )
    ts_raw, badge_id, door, result = row[0], row[1], row[2], row[3]
    extra: dict[str, str] = {}
    if door:
        extra["door"] = door
    if result:
        extra["auth_result"] = normalize_auth_result(result)
    event_timestamp = parse_iso_datetime(ts_raw)
    return build_physical_extraction_result(
        username=badge_id,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no badge CSV entity extracted",
    )
