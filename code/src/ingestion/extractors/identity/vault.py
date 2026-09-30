"""HashiCorp Vault JSON audit extraction (``vault``)."""

from __future__ import annotations

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    nested_str,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_SKIP_DISPLAY = frozenset({"token", "hmac", "none", "-"})


def extract_vault(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip/path from Vault JSON audit. No syslog month-carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_identity_extraction_result(
            protocol="vault",
            auth_result="unknown",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no vault JSON object",
        )
    username = nested_str(obj, "auth", "metadata", "username")
    if not username:
        display = nested_str(obj, "auth", "display_name")
        if display.lower() not in _SKIP_DISPLAY:
            username = display
    src_ip = nested_str(obj, "request", "remote_address")
    path = nested_str(obj, "request", "path")
    operation = nested_str(obj, "request", "operation")
    extra: dict[str, str] = {}
    if path:
        extra["path"] = path
    if operation:
        extra["operation"] = operation
    kind = str(obj.get("type") or "")
    if kind:
        extra["vault_type"] = kind
    error = obj.get("error")
    if error:
        extra["error"] = str(error)
        auth_result = "failure"
    else:
        auth_result = "success"
    ts = str(obj.get("time") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        service=path,
        protocol="vault",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no vault entity extracted",
    )
