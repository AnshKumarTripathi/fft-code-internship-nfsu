"""APM span JSON extraction (``apm``)."""

from __future__ import annotations

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_application_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_apm(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract service/host from span JSON with ``traceId`` and ``duration``."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no apm JSON object",
        )
    extra: dict[str, str] = {}
    trace_id = str(obj.get("traceId") or obj.get("trace_id") or "")
    if trace_id:
        extra["trace_id"] = trace_id
    span_id = str(obj.get("spanId") or obj.get("span_id") or "")
    if span_id:
        extra["span_id"] = span_id
    duration = obj.get("duration")
    if duration is not None:
        extra["duration"] = str(duration)
    service = str(obj.get("service") or obj.get("name") or "")
    event_timestamp = parse_application_json_timestamp(obj)
    return build_application_extraction_result(
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no apm entity extracted",
    )
