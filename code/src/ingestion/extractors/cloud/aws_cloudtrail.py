"""AWS CloudTrail JSON extraction (``aws_cloudtrail``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    arn_tail,
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_aws_cloudtrail(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract IAM user/role and source IP from a CloudTrail JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no cloudtrail JSON object",
        )
    identity = obj.get("userIdentity") if isinstance(obj.get("userIdentity"), dict) else {}
    identity_type = str(identity.get("type") or "")
    username = str(identity.get("userName") or "")
    arn = str(identity.get("arn") or "")
    service = ""
    if not username:
        if identity_type in {"AssumedRole", "Role", "AWSService"}:
            service = arn_tail(arn) or str(identity.get("invokedBy") or identity_type)
        else:
            username = arn_tail(arn) or str(identity.get("principalId") or "")
    extra: dict[str, str] = {}
    if arn:
        extra["arn"] = arn
    if identity_type:
        extra["identity_type"] = identity_type
    event_name = str(obj.get("eventName") or "")
    if event_name:
        extra["event_name"] = event_name
    event_source = str(obj.get("eventSource") or "")
    if event_source:
        extra["event_source"] = event_source
    src_ip = str(obj.get("sourceIPAddress") or "")
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cloudtrail entity extracted",
        prefer_service=bool(service),
    )
