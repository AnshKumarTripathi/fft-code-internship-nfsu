"""Kong file-log JSON extraction (``api_gateway``)."""

from __future__ import annotations

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    nested_str,
    parse_application_json_timestamp,
    parse_epoch_millis,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_api_gateway(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP / consumer / service from Kong file-log JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no api_gateway JSON object",
        )
    extra: dict[str, str] = {}
    method = nested_str(obj, "request", "method")
    path = nested_str(obj, "request", "uri") or nested_str(obj, "request", "url")
    status = nested_str(obj, "response", "status")
    if method:
        extra["method"] = method
    if path:
        extra["path"] = path
    if status:
        extra["status"] = status
    service = nested_str(obj, "service", "name") or str(obj.get("service") or "")
    username = nested_str(obj, "consumer", "username") or str(obj.get("user") or "")
    src_ip = str(obj.get("client_ip") or "")
    event_timestamp = parse_application_json_timestamp(obj)
    if event_timestamp is None and obj.get("started_at") is not None:
        event_timestamp = parse_epoch_millis(obj.get("started_at"))
    return build_application_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no api_gateway entity extracted",
    )
