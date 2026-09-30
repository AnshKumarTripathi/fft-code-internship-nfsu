"""Generic DLP JSON extraction (``dlp``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_dlp(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/host and policy action from generic DLP JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no dlp JSON object",
        )
    extra: dict[str, str] = {}
    policy = str(obj.get("policy") or "")
    if policy:
        extra["policy"] = policy
    file_name = str(obj.get("file") or obj.get("filename") or "")
    if file_name:
        extra["file"] = file_name
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        username=str(obj.get("user") or obj.get("username") or ""),
        src_ip=str(obj.get("src_ip") or obj.get("ip") or ""),
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        action=str(obj.get("action") or ""),
        severity=str(obj.get("severity") or ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no dlp entity extracted",
    )
