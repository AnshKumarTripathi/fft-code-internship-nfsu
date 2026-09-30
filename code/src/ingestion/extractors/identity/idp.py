"""Okta System Log / generic eventType IdP extraction (``idp``)."""

from __future__ import annotations

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    nested_str,
    normalize_auth_result,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def _protocol_from_event_type(event_type: str) -> str:
    lowered = event_type.lower()
    if "oauth2" in lowered or "oauth" in lowered:
        return "oauth"
    if "oidc" in lowered:
        return "oidc"
    return "saml"


def extract_idp(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip from Okta System Log JSON. No syslog month-carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_identity_extraction_result(
            protocol="saml",
            auth_result="unknown",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no idp JSON object",
        )
    event_type = str(obj.get("eventType") or "")
    extra: dict[str, str] = {}
    if event_type:
        extra["event_type"] = event_type
    username = (
        nested_str(obj, "actor", "alternateId")
        or nested_str(obj, "actor", "displayName")
        or str(obj.get("user") or obj.get("username") or "")
    )
    src_ip = (
        nested_str(obj, "client", "ipAddress")
        or nested_str(obj, "client", "ip")
        or str(obj.get("ip") or obj.get("src_ip") or "")
    )
    outcome = nested_str(obj, "outcome", "result") or str(obj.get("result") or "")
    auth_result = normalize_auth_result(outcome)
    ts = str(obj.get("published") or obj.get("time") or obj.get("timestamp") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=str(obj.get("hostname") or ""),
        protocol=_protocol_from_event_type(event_type),
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no idp entity extracted",
    )
