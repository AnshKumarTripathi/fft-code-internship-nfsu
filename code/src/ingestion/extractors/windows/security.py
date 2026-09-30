"""Security Event Log extraction, including Kerberos and NTLM Event IDs."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    WindowsRecord,
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Auth / identity Event IDs documented for this module.
LOGON_SUCCESS_ID = 4624
LOGON_FAILURE_ID = 4625
LOGOFF_ID = 4634
EXPLICIT_CREDS_ID = 4648
SPECIAL_PRIV_ID = 4672
PROCESS_CREATE_ID = 4688
KERBEROS_TGT_ID = 4768
KERBEROS_SERVICE_TICKET_ID = 4769
KERBEROS_PREAUTH_FAIL_ID = 4771
NTLM_AUTH_ID = 4776

KERBEROS_IDS = frozenset(
    {KERBEROS_TGT_ID, KERBEROS_SERVICE_TICKET_ID, KERBEROS_PREAUTH_FAIL_ID}
)


def extract_windows_security(line: str) -> ExtractionResult:
    """Extract entity and fields from a Security Event Log line."""
    record = parse_windows_record(line)
    event_class, auth_result = _classify_security(record)
    extra: dict[str, str] = {}
    if record.auth_package:
        extra["auth_package"] = record.auth_package
    return build_windows_extraction_result(
        record,
        event_class=event_class,
        auth_result=auth_result,
        extra_fields=extra,
        no_match_reason="no windows_security entity extracted",
    )


def _classify_security(record: WindowsRecord) -> tuple[str, str]:
    event_id = record.event_id
    package = (record.auth_package or "").upper()
    if event_id in KERBEROS_IDS:
        auth_result = "failure" if event_id == KERBEROS_PREAUTH_FAIL_ID else "success"
        return "kerberos", auth_result
    if event_id == NTLM_AUTH_ID:
        return "ntlm", _status_auth_result(record)
    if event_id == LOGON_SUCCESS_ID and record.logon_type == "3" and "NTLM" in package:
        return "ntlm", "success"
    if event_id == LOGON_SUCCESS_ID:
        return "logon", "success"
    if event_id == LOGON_FAILURE_ID:
        return "logon", "failure"
    if event_id == LOGOFF_ID:
        return "logoff", "success"
    if event_id == EXPLICIT_CREDS_ID:
        return "logon", "success"
    if event_id == SPECIAL_PRIV_ID:
        return "privilege", "success"
    if event_id == PROCESS_CREATE_ID:
        return "process", ""
    return "security", ""


def _status_auth_result(record: WindowsRecord) -> str:
    status = (record.fields.get("Status") or record.fields.get("ErrorCode") or "").lower()
    if not status or status in {"0x0", "0x00000000", "0"}:
        return "success"
    if status.startswith("0x") and status not in {"0x0", "0x00000000"}:
        return "failure"
    if "fail" in status:
        return "failure"
    return "success"
