"""Azure Key Vault diagnostic extraction (``azure_keyvault``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_azure_keyvault(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract caller IP/user from Key Vault diagnostic JSON."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no keyvault JSON object",
        )
    username = (
        nested_str(obj, "identity", "claim", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
        or str(obj.get("caller") or nested_str(obj, "properties", "id") or "")
    )
    src_ip = str(obj.get("callerIpAddress") or nested_str(obj, "properties", "clientInfo") or "")
    extra: dict[str, str] = {}
    operation = str(obj.get("operationName") or "")
    if operation:
        extra["operation"] = operation
    resource = str(obj.get("resourceId") or "")
    if resource:
        extra["resource_id"] = resource
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        service=resource.rsplit("/", 1)[-1] if resource and not username and not src_ip else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no keyvault entity extracted",
    )
