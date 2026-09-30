"""Microsoft 365 Unified Audit Log extraction (``saas_m365``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_saas_m365(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract UserId and ClientIP from a M365 UAL JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no m365 JSON object",
        )
    username = str(obj.get("UserId") or "")
    src_ip = str(obj.get("ClientIP") or obj.get("ClientIPAddress") or "")
    extra: dict[str, str] = {}
    workload = str(obj.get("Workload") or "")
    if workload:
        extra["workload"] = workload
    operation = str(obj.get("Operation") or "")
    if operation:
        extra["operation"] = operation
    ts = str(obj.get("CreationTime") or obj.get("time") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no m365 entity extracted",
    )
