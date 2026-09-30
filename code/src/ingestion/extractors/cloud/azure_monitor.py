"""Azure Monitor diagnostic extraction (``azure_monitor``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_azure_monitor(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract resource/service from an Azure Monitor diagnostic JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no azure monitor JSON object",
        )
    extra: dict[str, str] = {}
    category = str(obj.get("category") or "")
    if category:
        extra["category"] = category
    resource = str(obj.get("resourceId") or "")
    if resource:
        extra["resource_id"] = resource
    hostname = resource.rsplit("/", 1)[-1] if resource else ""
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        hostname=hostname,
        service=hostname or category or "azure_monitor",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no azure monitor entity extracted",
    )
