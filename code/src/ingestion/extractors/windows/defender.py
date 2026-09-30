"""Windows Defender operational extraction (``windows_defender``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

MALWARE_DETECT_ID = 1116
MALWARE_ACTION_ID = 1117
REALTIME_DISABLED_ID = 5001

EVENT_CLASS = {
    MALWARE_DETECT_ID: "malware",
    MALWARE_ACTION_ID: "malware",
    REALTIME_DISABLED_ID: "defender_config",
}


def extract_windows_defender(line: str) -> ExtractionResult:
    """Extract host/user from a Windows Defender event line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    threat = record.fields.get("ThreatName") or record.fields.get("Threat") or ""
    if threat:
        extra["threat_name"] = threat
    return build_windows_extraction_result(
        record,
        event_class=EVENT_CLASS.get(record.event_id or -1, "defender"),
        extra_fields=extra,
        no_match_reason="no windows_defender entity extracted",
    )
