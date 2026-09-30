"""JSON API request/response audit extraction (``api_audit``)."""

from __future__ import annotations

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_application_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_api_audit(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract actor and request metadata from JSON API audit lines."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no api_audit JSON object",
        )
    extra: dict[str, str] = {}
    method = str(obj.get("method") or "")
    path = str(obj.get("path") or "")
    status = str(obj.get("status") or "")
    if method:
        extra["method"] = method
    if path:
        extra["path"] = path
    if status:
        extra["status"] = status
    service = str(obj.get("service") or "")
    event_timestamp = parse_application_json_timestamp(obj)
    return build_application_extraction_result(
        username=str(obj.get("actor") or obj.get("user") or ""),
        src_ip=str(obj.get("src_ip") or obj.get("ip") or ""),
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no api_audit entity extracted",
    )
