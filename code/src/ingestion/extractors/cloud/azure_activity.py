"""Azure Activity Log extraction (``azure_activity``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_azure_activity(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract caller / resource from an Azure Activity Log JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no azure activity JSON object",
        )
    username = str(obj.get("caller") or nested_str(obj, "identity", "claims", "name") or "")
    extra: dict[str, str] = {}
    operation = str(obj.get("operationName") or "")
    if operation:
        extra["operation"] = operation
    resource = str(obj.get("resourceId") or "")
    if resource:
        extra["resource_id"] = resource
    service = resource.rsplit("/", 1)[-1] if resource else ""
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        username=username,
        service=service if not username else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no azure activity entity extracted",
    )
