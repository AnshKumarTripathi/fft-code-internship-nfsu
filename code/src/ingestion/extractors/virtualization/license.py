"""License server extraction (``license``) — FlexLM-like OUT/IN/DENIED."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    build_virt_extraction_result,
    extract_syslog_virt_line,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

ACTION = re.compile(r"\b(?P<action>OUT|IN|DENIED):\s+\"(?P<feature>[^\"]+)\"", re.IGNORECASE)
USER_HOST = re.compile(r"\"[^\"]+\"\s+(?P<user>[\w.-]+)@(?P<host>[\w.-]+)")
ISO_LEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def extract_license(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/host from FlexLM-like checkout lines."""
    extra: dict[str, str] = {}
    action = ACTION.search(line)
    if action:
        extra["action"] = action.group("action").upper()
        extra["feature"] = action.group("feature")
    pair = USER_HOST.search(line)
    username = normalize_username(pair.group("user") if pair else "")
    pair_host = pair.group("host") if pair else ""
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_virt_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no license entity extracted",
        )
    iso = ISO_LEAD.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    return build_virt_extraction_result(
        username=username,
        hostname=pair_host,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no license entity extracted",
    )
