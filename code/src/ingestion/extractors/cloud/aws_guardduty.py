"""AWS GuardDuty finding extraction (``aws_guardduty``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_aws_guardduty(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract IP/host from a GuardDuty finding JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no guardduty JSON object",
        )
    extra: dict[str, str] = {}
    finding_type = str(obj.get("type") or "")
    if finding_type:
        extra["finding_type"] = finding_type
    src_ip = nested_str(obj, "service", "action", "networkConnectionAction", "remoteIpDetails", "ipAddressV4")
    if not src_ip:
        src_ip = nested_str(obj, "service", "action", "awsApiCallAction", "remoteIpDetails", "ipAddressV4")
    hostname = nested_str(obj, "resource", "instanceDetails", "instanceId")
    service = str(obj.get("id") or "")
    ts = str(obj.get("updatedAt") or obj.get("createdAt") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_cloud_extraction_result(
        src_ip=src_ip,
        hostname=hostname,
        service=service or "guardduty",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no guardduty entity extracted",
    )
