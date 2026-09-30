"""ClamAV scan-line extraction (``antivirus``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.security.common import build_security_extraction_result
from src.ingestion.extractors.unix_os.common import (
    is_rfc3164,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_FOUND = re.compile(
    r"(?P<path>\S+):\s+(?P<signature>.+)\s+FOUND\s*$",
    re.IGNORECASE,
)
_CTIME = re.compile(
    r"^(?P<ctime>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
)


def _parse_ctime(line: str) -> datetime | None:
    match = _CTIME.match(line.strip())
    if match is None:
        return None
    try:
        parsed = datetime.strptime(match.group("ctime"), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def extract_antivirus(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host and signature from ClamAV FOUND lines."""
    found = _FOUND.search(line.strip())
    extra: dict[str, str] = {}
    if found:
        extra["path"] = found.group("path")
        extra["signature"] = found.group("signature").strip()
        extra["action"] = "found"
    hostname = ""
    event_timestamp: datetime | None = None
    ts_ok = False
    if is_rfc3164(line):
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
        hostname, program, pid = parse_syslog_fields(line)
        if program:
            extra["program"] = program
        if pid:
            extra["pid"] = pid
    else:
        event_timestamp = _parse_ctime(line)
        ts_ok = event_timestamp is not None
        if not hostname:
            hostname = "clamav"
    action = "found" if found else ""
    return build_security_extraction_result(
        hostname=hostname,
        action=action,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no antivirus entity extracted",
    )
