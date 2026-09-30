"""JSON vulnerability-finding extraction (``vuln_scanner``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    looks_like_ip,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_vuln_scanner(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host and severity from a one-line JSON scanner finding."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no vuln_scanner JSON object",
        )
    extra: dict[str, str] = {}
    plugin = str(obj.get("pluginID") or obj.get("plugin_id") or "")
    if plugin:
        extra["plugin_id"] = plugin
    name = str(obj.get("pluginName") or obj.get("name") or "")
    if name:
        extra["plugin_name"] = name
    host = str(obj.get("host") or obj.get("hostname") or "")
    src_ip = host if looks_like_ip(host) else str(obj.get("ip") or obj.get("src_ip") or "")
    hostname = "" if looks_like_ip(host) else host
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        src_ip=src_ip,
        hostname=hostname,
        action=str(obj.get("action") or ""),
        severity=str(obj.get("severity") or obj.get("risk") or ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no vuln_scanner entity extracted",
    )
