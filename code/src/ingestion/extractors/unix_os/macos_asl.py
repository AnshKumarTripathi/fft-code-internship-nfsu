"""macOS ASL text extraction (``macos_asl``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ASL_TIME = re.compile(r"\[Time\s+(?P<ts>[^\]]+)\]", re.IGNORECASE)
ASL_SENDER = re.compile(r"\[Sender\s+(?P<sender>[^\]]+)\]", re.IGNORECASE)
ASL_PID = re.compile(r"\[PID\s+(?P<pid>\d+)\]", re.IGNORECASE)
ASL_HOST = re.compile(r"\[Host\s+(?P<host>[^\]]+)\]", re.IGNORECASE)


def extract_macos_asl(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from ASL text export. No syslog month-carry."""
    del default_year, year_state, year_policy
    extra: dict[str, str] = {}
    time_match = ASL_TIME.search(line)
    event_timestamp = None
    ts_ok = False
    if time_match:
        raw_ts = time_match.group("ts").strip()
        raw_ts = re.sub(r"\s+GMT$", "", raw_ts)
        event_timestamp = parse_iso_datetime(raw_ts)
        ts_ok = event_timestamp is not None
    sender = ASL_SENDER.search(line)
    program = sender.group("sender").strip() if sender else "asl"
    pid = ASL_PID.search(line)
    if pid:
        extra["pid"] = pid.group("pid")
    host = ASL_HOST.search(line)
    hostname = host.group("host").strip() if host else ""
    return build_unix_extraction_result(
        hostname=hostname,
        program=program,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no macos_asl entity extracted",
    )
