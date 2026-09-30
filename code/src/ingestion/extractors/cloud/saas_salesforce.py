"""Salesforce Event Monitoring extraction (``saas_salesforce``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_saas_salesforce(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract USER_ID_DERIVED and CLIENT_IP from EventLogFile-like JSON."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no salesforce JSON object",
        )
    username = str(obj.get("USER_ID_DERIVED") or obj.get("USER_ID") or "")
    src_ip = str(obj.get("CLIENT_IP") or obj.get("SOURCE_IP") or "")
    extra: dict[str, str] = {}
    event_type = str(obj.get("EVENT_TYPE") or "")
    if event_type:
        extra["event_type"] = event_type
    ts = str(obj.get("TIMESTAMP_DERIVED") or obj.get("TIMESTAMP") or obj.get("time") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no salesforce entity extracted",
    )
