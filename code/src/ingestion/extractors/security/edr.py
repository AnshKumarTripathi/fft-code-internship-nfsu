"""CrowdStrike-like EDR JSON extraction (``edr``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    nested_str,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_edr(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from CrowdStrike-like process JSON. No year-carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no edr JSON object",
        )
    extra: dict[str, str] = {}
    event_name = str(obj.get("event_simpleName") or "")
    if event_name:
        extra["event_simpleName"] = event_name
    command = str(obj.get("CommandLine") or obj.get("command_line") or "")
    if command:
        extra["command_line"] = command
    image = str(obj.get("ImageFileName") or obj.get("Image") or "")
    if image:
        extra["image"] = image
    hostname = (
        str(obj.get("ComputerName") or "")
        or nested_str(obj, "device", "hostname")
        or str(obj.get("hostname") or obj.get("host") or "")
    )
    username = str(obj.get("UserName") or obj.get("user") or obj.get("username") or "")
    src_ip = str(obj.get("LocalAddressIP4") or obj.get("src_ip") or obj.get("ip") or "")
    action = str(obj.get("action") or event_name or "")
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        action=action,
        severity=str(obj.get("severity") or ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no edr entity extracted",
    )
