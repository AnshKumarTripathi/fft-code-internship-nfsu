"""Google Workspace Admin SDK activity extraction (``saas_workspace``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    nested_str,
    parse_cloud_json_line,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_saas_workspace(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract actor email and IP from Workspace activity JSON."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no workspace JSON object",
        )
    username = nested_str(obj, "actor", "email") or str(obj.get("user") or "")
    src_ip = nested_str(obj, "ipAddress") or str(obj.get("ipAddress") or "")
    extra: dict[str, str] = {}
    app = nested_str(obj, "id", "applicationName")
    if app:
        extra["application"] = app
    ts = nested_str(obj, "id", "time") or str(obj.get("time") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no workspace entity extracted",
    )
