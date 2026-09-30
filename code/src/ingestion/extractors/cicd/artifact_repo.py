"""Artifact repository request extraction (``artifact_repo``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.cicd.common import (
    ARTIFACTORY_PIPE,
    COMBINED,
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    extract_syslog_cicd_line,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

_BRACKET_TIME = re.compile(
    r"(?P<day>\d{2})/(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/"
    r"(?P<year>\d{4}):(?P<hms>\d{2}:\d{2}:\d{2})"
)
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def extract_artifact_repo(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user and client IP from Nexus/Artifactory request lines."""
    combined = COMBINED.match(line.strip())
    if combined:
        ts = _parse_bracket_time(combined.group("ts"))
        extra = {"path": combined.group("path"), "method": combined.group("method")}
        return build_cicd_extraction_result(
            username=normalize_username(combined.group("user")),
            src_ip=combined.group("ip"),
            extra_fields=extra,
            event_timestamp=ts,
            ts_ok=ts is not None,
            no_match_reason="no artifact_repo combined entity extracted",
        )
    pipe = ARTIFACTORY_PIPE.match(line.strip())
    if pipe:
        ts = parse_iso_datetime(pipe.group("ts"))
        extra = {"path": pipe.group("path"), "method": pipe.group("method")}
        return build_cicd_extraction_result(
            username=normalize_username(pipe.group("user")),
            src_ip=pipe.group("ip"),
            extra_fields=extra,
            event_timestamp=ts,
            ts_ok=ts is not None,
            no_match_reason="no artifact_repo pipe entity extracted",
        )
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_cicd_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            service="nexus",
            extra_fields={},
            no_match_reason="no artifact_repo entity extracted",
        )
    return build_cicd_extraction_result(
        service="artifact-repo",
        extra_fields={},
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no artifact_repo entity extracted",
    )


def _parse_bracket_time(raw: str) -> datetime | None:
    match = _BRACKET_TIME.search(raw)
    if match is None:
        return None
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("hms").split(":"))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
