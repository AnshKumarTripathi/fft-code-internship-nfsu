"""PowerShell operational / transcription extraction (``windows_powershell``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

MODULE_LOGGING_ID = 4103
SCRIPT_BLOCK_ID = 4104

EVENT_CLASS = {
    MODULE_LOGGING_ID: "script",
    SCRIPT_BLOCK_ID: "script",
}


def extract_windows_powershell(line: str) -> ExtractionResult:
    """Extract user/host from a PowerShell operational or transcription line."""
    record = parse_windows_record(line)
    event_class = EVENT_CLASS.get(record.event_id or -1, "script")
    extra: dict[str, str] = {}
    script_name = record.fields.get("ScriptName") or record.fields.get("HostApplication") or ""
    if script_name:
        extra["script_name"] = script_name
    return build_windows_extraction_result(
        record,
        event_class=event_class,
        extra_fields=extra,
        no_match_reason="no windows_powershell entity extracted",
    )
