"""boot.log extraction (``linux_boot``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    mtime_year_timestamp,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

STARTED = re.compile(
    r"(?:Started|Starting)\s+(?P<unit>.+?)(?:\.service)?\.?\s*$",
    re.IGNORECASE,
)


def extract_linux_boot(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract boot service start/fail lines. File-mtime year if no syslog ts."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    unit = ""
    started = STARTED.search(line)
    if started:
        unit = started.group("unit").strip().rstrip(".")
        extra["unit"] = unit
    if not ts_ok:
        event_timestamp = mtime_year_timestamp(default_year)
        extra["timestamp_from_file_mtime_year"] = "true"
        ts_ok = True
    return build_unix_extraction_result(
        unit=unit,
        hostname=hostname,
        program=program or "boot",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_boot entity extracted",
    )
