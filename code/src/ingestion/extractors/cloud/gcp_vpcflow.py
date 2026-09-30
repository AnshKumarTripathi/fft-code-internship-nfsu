"""GCP VPC Flow log extraction (``gcp_vpcflow``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_gcp_vpcflow(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst IP from a GCP VPC flow JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no gcp vpcflow JSON object",
        )
    src_ip = nested_str(obj, "jsonPayload", "connection", "src_ip")
    dst_ip = nested_str(obj, "jsonPayload", "connection", "dest_ip")
    extra: dict[str, str] = {}
    if dst_ip:
        extra["dst_ip"] = dst_ip
    reporter = nested_str(obj, "jsonPayload", "reporter")
    if reporter:
        extra["reporter"] = reporter
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no gcp vpcflow entity extracted",
    )
