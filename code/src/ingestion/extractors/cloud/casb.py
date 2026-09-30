"""CASB audit extraction (``casb``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_casb(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/app/action from a generic CASB JSON line."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    if obj is None:
        return build_cloud_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no casb JSON object",
        )
    username = str(obj.get("user") or obj.get("username") or obj.get("actor") or "")
    src_ip = str(obj.get("ip") or obj.get("src_ip") or obj.get("ipAddress") or "")
    extra: dict[str, str] = {}
    app = str(obj.get("app") or "")
    if app:
        extra["app"] = app
    action = str(obj.get("action") or "")
    if action:
        extra["action"] = action
    event_timestamp = parse_cloud_json_timestamp(obj)
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no casb entity extracted",
    )
