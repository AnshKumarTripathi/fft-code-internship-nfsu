"""Windows Filtering Platform / Windows Firewall extraction (``windows_firewall``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    looks_like_ip,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

ALLOW_ID = 5156
BLOCK_ID = 5157
RULE_ADDED_ID = 2004
RULE_REMOVED_ID = 2006

EVENT_CLASS = {
    ALLOW_ID: "firewall_allow",
    BLOCK_ID: "firewall_block",
    RULE_ADDED_ID: "firewall_rule",
    RULE_REMOVED_ID: "firewall_rule",
}


def extract_windows_firewall(line: str) -> ExtractionResult:
    """Extract ip/host from a WFP / Windows Firewall event line."""
    record = parse_windows_record(line)
    dest = record.fields.get("DestAddress") or record.fields.get("DestinationAddress") or ""
    extra: dict[str, str] = {}
    if dest and looks_like_ip(dest):
        extra["dst_ip"] = dest
    application = record.fields.get("Application") or record.fields.get("ApplicationName") or ""
    if application:
        extra["application"] = application
    auth_result = ""
    if record.event_id == ALLOW_ID:
        auth_result = "success"
    elif record.event_id == BLOCK_ID:
        auth_result = "failure"
    return build_windows_extraction_result(
        record,
        event_class=EVENT_CLASS.get(record.event_id or -1, "firewall"),
        auth_result=auth_result,
        extra_fields=extra,
        no_match_reason="no windows_firewall entity extracted",
    )
