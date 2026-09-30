"""macOS unified logging extraction (``macos_unified``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

UNIFIED = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\s+"
    r"(?P<thread>0x[0-9a-fA-F]+)"
)
PROGRAM = re.compile(r"\s(?P<program>[A-Za-z0-9._-]+):\s")
USER_IN_MSG = re.compile(r"\buser[:\s]+(?P<user>[A-Za-z0-9._-]+)", re.IGNORECASE)


def extract_macos_unified(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from ``log show`` default text. No syslog month-carry."""
    del default_year, year_state, year_policy
    match = UNIFIED.match(line.strip())
    event_timestamp = None
    ts_ok = False
    program = ""
    extra: dict[str, str] = {}
    if match:
        event_timestamp = parse_iso_datetime(match.group("ts"))
        ts_ok = event_timestamp is not None
        extra["thread"] = match.group("thread")
    prog_match = PROGRAM.search(line)
    program = prog_match.group("program") if prog_match else ""
    user_match = USER_IN_MSG.search(line)
    username = user_match.group("user") if user_match else ""
    hostname = ""
    return build_unix_extraction_result(
        username=username,
        hostname=hostname,
        program=program or "log",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no macos_unified entity extracted",
    )
