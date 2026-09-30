"""Azure AD sign-in / audit extraction (``azure_ad``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_azure_ad(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract UPN and IP from Azure AD sign-in / audit JSON."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no azure_ad JSON object",
        )
    username = (
        nested_str(obj, "properties", "userPrincipalName")
        or str(obj.get("userPrincipalName") or "")
    )
    src_ip = nested_str(obj, "properties", "ipAddress") or str(obj.get("ipAddress") or "")
    extra: dict[str, str] = {}
    category = str(obj.get("category") or "")
    if category:
        extra["category"] = category
    result = nested_str(obj, "properties", "status", "errorCode")
    if result == "0" or result == "":
        extra["auth_result"] = "success" if username else "unknown"
    elif result:
        extra["auth_result"] = "failure"
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no azure_ad entity extracted",
    )
