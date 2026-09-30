"""Generic SIEM correlated-event JSON extraction (``siem``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_siem(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip/host from a SIEM correlation export JSON line."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no siem JSON object",
        )
    extra: dict[str, str] = {}
    rule_name = str(obj.get("rule_name") or "")
    if rule_name:
        extra["rule_name"] = rule_name
    correlation_id = str(obj.get("correlation_id") or "")
    if correlation_id:
        extra["correlation_id"] = correlation_id
    vendor = str(obj.get("siem") or "")
    if vendor:
        extra["siem"] = vendor
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        username=str(obj.get("user") or obj.get("username") or ""),
        src_ip=str(obj.get("src_ip") or obj.get("ip") or ""),
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        action=str(obj.get("action") or "correlated"),
        severity=str(obj.get("severity") or ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no siem entity extracted",
    )
