"""AWS Config item extraction (``aws_config``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_aws_config(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract resource identity from an AWS Config JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no config JSON object",
        )
    item = obj.get("configurationItem") if isinstance(obj.get("configurationItem"), dict) else obj
    extra: dict[str, str] = {}
    resource_type = str(item.get("resourceType") or "")
    if resource_type:
        extra["resource_type"] = resource_type
    hostname = str(item.get("resourceId") or item.get("resourceName") or "")
    service = resource_type or "aws_config"
    ts = str(
        item.get("configurationItemCaptureTime")
        or obj.get("configurationItemCaptureTime")
        or ""
    )
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_cloud_extraction_result(
        hostname=hostname,
        service=service if not hostname else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no config entity extracted",
    )
