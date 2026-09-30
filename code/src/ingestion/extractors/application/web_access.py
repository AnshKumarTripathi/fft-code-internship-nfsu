"""Apache combined / Nginx combined / IIS W3C access extraction (``web_access``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_combined_log_time,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/\d(?:\.\d)?" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)
W3C = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<s_ip>\S+) (?P<method>[A-Z]+) (?P<path>\S+) (?P<query>\S+) "
    r"(?P<port>\S+) (?P<user>\S+) (?P<c_ip>\S+) (?P<agent>\S+) (?P<status>\d{3})"
)


def extract_web_access(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP, method, path, and status from access-log lines."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    if stripped.startswith("#"):
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="iis w3c comment line",
        )
    combined = COMBINED.match(stripped)
    if combined:
        extra = {
            "method": combined.group("method"),
            "path": combined.group("path"),
            "status": combined.group("status"),
            "bytes": combined.group("size"),
        }
        event_timestamp = parse_combined_log_time(combined.group("time"))
        return build_application_extraction_result(
            username=combined.group("user"),
            src_ip=combined.group("ip"),
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no web_access entity extracted",
        )
    w3c = W3C.match(stripped)
    if w3c:
        extra = {
            "method": w3c.group("method"),
            "path": w3c.group("path"),
            "status": w3c.group("status"),
            "server_ip": w3c.group("s_ip"),
        }
        event_timestamp = parse_iso_datetime(f"{w3c.group('date')} {w3c.group('time')}")
        return build_application_extraction_result(
            username=w3c.group("user"),
            src_ip=w3c.group("c_ip"),
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no web_access entity extracted",
        )
    return build_application_extraction_result(
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no web_access entity extracted",
    )
