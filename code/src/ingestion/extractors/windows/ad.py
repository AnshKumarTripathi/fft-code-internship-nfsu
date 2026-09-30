"""Dedicated AD Directory Service / AD FS extraction (``windows_ad``).

Use only for exports that are not already Security Event ID lines (4624, 4768, …).
Those stay ``windows_security`` with ``event_class`` kerberos/ntlm/logon.
"""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Directory Service / AD FS — not Security 4624/4768/4776.
LDAP_SIGNING_ID = 2889
LDAP_EXPENSIVE_SEARCH_ID = 1644
ADFS_AUDIT_SUCCESS_ID = 1200
ADFS_AUDIT_FAILURE_ID = 1201
ADFS_TOKEN_ID = 501
ADFS_APPTOKEN_ID = 510

PARSED_EVENT_IDS = frozenset(
    {
        LDAP_SIGNING_ID,
        LDAP_EXPENSIVE_SEARCH_ID,
        ADFS_AUDIT_SUCCESS_ID,
        ADFS_AUDIT_FAILURE_ID,
        ADFS_TOKEN_ID,
        ADFS_APPTOKEN_ID,
    }
)


def extract_windows_ad(line: str) -> ExtractionResult:
    """Extract user/host from Directory Service or AD FS text."""
    record = parse_windows_record(line)
    auth_result = ""
    if record.event_id == ADFS_AUDIT_SUCCESS_ID:
        auth_result = "success"
    elif record.event_id == ADFS_AUDIT_FAILURE_ID:
        auth_result = "failure"
    extra: dict[str, str] = {}
    client = record.fields.get("ClientIP") or record.fields.get("IpAddress") or ""
    if client:
        extra["client_ip"] = client
    return build_windows_extraction_result(
        record,
        event_class="ad",
        auth_result=auth_result,
        extra_fields=extra,
        no_match_reason="no windows_ad entity extracted",
    )
