"""Nginx / Apache error_log extraction (``web_error``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_apache_error_time,
    parse_nginx_error_time,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_CLIENT = re.compile(
    r"\bclient[:\s]+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)",
    re.IGNORECASE,
)
_SERVER = re.compile(r"\bserver:\s*(?P<host>\S+)", re.IGNORECASE)


def extract_web_error(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP or server host from web error lines."""
    del default_year, year_state, year_policy
    extra: dict[str, str] = {}
    client = _CLIENT.search(line)
    src_ip = client.group("ip") if client else ""
    server = _SERVER.search(line)
    hostname = server.group("host").rstrip(",") if server else ""
    if "[error]" in line or " [error] " in line:
        extra["level"] = "error"
    event_timestamp = parse_nginx_error_time(line) or parse_apache_error_time(line)
    return build_application_extraction_result(
        src_ip=src_ip,
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no web_error entity extracted",
    )
