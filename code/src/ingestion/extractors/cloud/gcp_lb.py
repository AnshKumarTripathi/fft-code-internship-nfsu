"""GCP HTTP(S) load balancer log extraction (``gcp_lb``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_gcp_lb(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP from a GCP HTTP(S) LB JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no gcp lb JSON object",
        )
    src_ip = nested_str(obj, "httpRequest", "remoteIp")
    extra: dict[str, str] = {}
    method = nested_str(obj, "httpRequest", "requestMethod")
    if method:
        extra["method"] = method
    status = nested_str(obj, "httpRequest", "status")
    if status:
        extra["status"] = status
    url = nested_str(obj, "httpRequest", "requestUrl")
    if url:
        extra["path"] = url
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no gcp lb entity extracted",
    )
