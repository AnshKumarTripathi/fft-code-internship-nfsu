"""RDP / Terminal Services connection extraction (``windows_rdp``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Microsoft-Windows-TerminalServices-LocalSessionManager / RemoteConnectionManager
SESSION_LOGON_ID = 21
SESSION_DISCONNECT_ID = 24
SESSION_RECONNECT_ID = 25
USER_AUTH_ID = 1149

EVENT_CLASS = {
    SESSION_LOGON_ID: "rdp_logon",
    SESSION_DISCONNECT_ID: "rdp_disconnect",
    SESSION_RECONNECT_ID: "rdp_reconnect",
    USER_AUTH_ID: "rdp_auth",
}


def extract_windows_rdp(line: str) -> ExtractionResult:
    """Extract entity and fields from a Terminal Services RDP line."""
    record = parse_windows_record(line)
    event_class = EVENT_CLASS.get(record.event_id or -1, "rdp")
    auth_result = "success" if record.event_id in {SESSION_LOGON_ID, USER_AUTH_ID} else ""
    extra: dict[str, str] = {}
    session_id = record.fields.get("SessionID") or record.fields.get("SessionId") or ""
    if session_id:
        extra["session_id"] = session_id
    return build_windows_extraction_result(
        record,
        event_class=event_class,
        auth_result=auth_result,
        extra_fields=extra,
        no_match_reason="no windows_rdp entity extracted",
    )
