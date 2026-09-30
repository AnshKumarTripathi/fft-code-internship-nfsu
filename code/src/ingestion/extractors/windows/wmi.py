"""WMI activity extraction (``windows_wmi``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Microsoft-Windows-WMI-Activity/Operational
WMI_QUERY_ID = 5857
WMI_TEMP_EVENT_ID = 5858
WMI_PERM_EVENT_ID = 5859
WMI_TEMP_CONSUMER_ID = 5860
WMI_PERM_CONSUMER_ID = 5861

PARSED_EVENT_IDS = frozenset(
    {WMI_QUERY_ID, WMI_TEMP_EVENT_ID, WMI_PERM_EVENT_ID, WMI_TEMP_CONSUMER_ID, WMI_PERM_CONSUMER_ID}
)


def extract_windows_wmi(line: str) -> ExtractionResult:
    """Extract user/host from a WMI activity line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    query = record.fields.get("Query") or record.fields.get("Operation") or ""
    if query:
        extra["wmi_operation"] = query
    return build_windows_extraction_result(
        record,
        event_class="wmi",
        extra_fields=extra,
        no_match_reason="no windows_wmi entity extracted",
    )
