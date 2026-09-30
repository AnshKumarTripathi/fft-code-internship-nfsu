"""GCP Cloud Audit log extraction (``gcp_audit``)."""

from __future__ import annotations

from typing import Any

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def parse_gcp_audit_fields(obj: dict[str, Any]) -> dict[str, str]:
    """Pull principal, method, and service from a Cloud Audit JSON object."""
    username = nested_str(obj, "protoPayload", "authenticationInfo", "principalEmail")
    method = nested_str(obj, "protoPayload", "methodName")
    service = nested_str(obj, "protoPayload", "serviceName")
    src_ip = nested_str(obj, "protoPayload", "requestMetadata", "callerIp")
    extra: dict[str, str] = {}
    if method:
        extra["method_name"] = method
    if service:
        extra["service_name"] = service
    return {
        "username": username,
        "src_ip": src_ip,
        "service": service,
        **extra,
    }


def extract_gcp_audit(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
    event_class: str = "",
) -> ExtractionResult:
    """Extract principal and caller IP from a GCP Cloud Audit JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no gcp audit JSON object",
        )
    fields = parse_gcp_audit_fields(obj)
    extra = {k: v for k, v in fields.items() if k not in {"username", "src_ip", "service"} and v}
    if event_class:
        extra["event_class"] = event_class
    event_timestamp = parse_cloud_json_timestamp(obj)
    if event_timestamp is None:
        event_timestamp = parse_cloud_json_timestamp({"timestamp": str(obj.get("timestamp") or "")})
    return build_cloud_extraction_result(
        username=fields["username"],
        src_ip=fields["src_ip"],
        service=fields["service"] if not fields["username"] else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no gcp audit entity extracted",
    )
