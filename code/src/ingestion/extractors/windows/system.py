"""System Event Log extraction (``windows_system``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

EVENTLOG_STARTED_ID = 6005
EVENTLOG_STOPPED_ID = 6006
SERVICE_STATE_ID = 7036
SERVICE_INSTALL_ID = 7045

EVENT_CLASS = {
    EVENTLOG_STARTED_ID: "startup",
    EVENTLOG_STOPPED_ID: "shutdown",
    SERVICE_STATE_ID: "service",
    SERVICE_INSTALL_ID: "service",
}


def extract_windows_system(line: str) -> ExtractionResult:
    """Extract host from a System Event Log line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    service = record.fields.get("ServiceName") or record.fields.get("param1") or ""
    if service:
        extra["service"] = service
    return build_windows_extraction_result(
        record,
        event_class=EVENT_CLASS.get(record.event_id or -1, "system"),
        extra_fields=extra,
        no_match_reason="no windows_system entity extracted",
    )
