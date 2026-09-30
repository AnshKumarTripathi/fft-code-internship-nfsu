"""STIX/JSON threat-intel indicator extraction (``threat_intel``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    looks_like_ip,
    parse_iso_datetime,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_IPV4_IN_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def extract_threat_intel(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract IP/host and accepted/rejected verdict from STIX JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no threat_intel JSON object",
        )
    extra: dict[str, str] = {}
    pattern = str(obj.get("pattern") or "")
    if pattern:
        extra["pattern"] = pattern
    indicator_id = str(obj.get("id") or "")
    if indicator_id:
        extra["indicator_id"] = indicator_id
    verdict = str(obj.get("verdict") or obj.get("action") or "")
    if verdict:
        extra["verdict"] = verdict
    src_ip = str(obj.get("src_ip") or obj.get("ip") or "")
    if not src_ip and pattern:
        match = _IPV4_IN_PATTERN.search(pattern)
        if match and looks_like_ip(match.group(1)):
            src_ip = match.group(1)
    hostname = str(obj.get("host") or obj.get("hostname") or "")
    event_timestamp = parse_security_json_timestamp(obj)
    if event_timestamp is None:
        valid_from = str(obj.get("valid_from") or "")
        event_timestamp = parse_iso_datetime(valid_from) if valid_from else None
    return build_security_extraction_result(
        src_ip=src_ip,
        hostname=hostname,
        action=verdict,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no threat_intel entity extracted",
    )
