"""macOS Installer / DiagnosticReports extraction (``macos_install``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_iso_datetime,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

DATE_TIME = re.compile(
    r"Date/Time:\s*(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*[+-]\d{4})?)"
)
PROCESS = re.compile(r"Process:\s*(?P<name>\S+)")


def extract_macos_install(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from Installer/PackageKit or crash-header lines."""
    date_match = DATE_TIME.search(line)
    event_timestamp = None
    ts_ok = False
    if date_match:
        event_timestamp = parse_iso_datetime(date_match.group("ts"))
        ts_ok = event_timestamp is not None
    else:
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
    proc = PROCESS.search(line)
    if proc and not program:
        program = proc.group("name")
        extra["process"] = program
    return build_unix_extraction_result(
        hostname=hostname,
        program=program or "installd",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no macos_install entity extracted",
    )
