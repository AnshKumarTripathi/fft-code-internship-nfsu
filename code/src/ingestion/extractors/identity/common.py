"""Shared JSON, syslog, entity, and auth_result helpers for identity families."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from src.ingestion.extractors.unix_os.common import (
    looks_like_ip,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult

_SUCCESS_TOKENS = frozenset({"success", "successful", "ok", "allow", "allowed", "accept", "accepted"})
_FAILURE_TOKENS = frozenset(
    {
        "failure",
        "failed",
        "fail",
        "deny",
        "denied",
        "reject",
        "rejected",
        "incorrect",
        "fraud",
        "error",
    }
)


def parse_json_object(line: str) -> dict[str, Any] | None:
    """Parse a one-line JSON object; return None on any failure."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict):
        return parsed
    return None


def normalize_auth_result(raw: str) -> str:
    """Map dialect tokens to success / failure / unknown."""
    token = (raw or "").strip().lower()
    if token in _SUCCESS_TOKENS:
        return "success"
    if token in _FAILURE_TOKENS:
        return "failure"
    return "unknown"


def nested_str(obj: dict[str, Any], *keys: str) -> str:
    """Walk nested dicts and return a string value, else empty."""
    current: Any = obj
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    if current is None or isinstance(current, (dict, list)):
        return ""
    return str(current).strip()


def assign_identity_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
) -> tuple[str, str]:
    """Apply user → ip → host → service entity policy."""
    user = normalize_username(username)
    if user:
        return user, "user"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname:
        return hostname, "host"
    if service:
        return service, "service"
    return "", "host"


def build_identity_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    protocol: str,
    auth_result: str,
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with identity raw_fields (auth_result + protocol)."""
    user = normalize_username(username)
    result = auth_result if auth_result in {"success", "failure", "unknown"} else "unknown"
    raw_fields: dict[str, Any] = {
        "auth_result": result,
        "protocol": protocol,
    }
    if user:
        raw_fields["username"] = user
    if src_ip:
        raw_fields["src_ip"] = src_ip
    if hostname:
        raw_fields["hostname"] = hostname
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_identity_entity(user, src_ip, hostname, service)
    if not entity_id:
        return ExtractionResult(
            event_timestamp=event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason=no_match_reason,
        )
    return ExtractionResult(
        entity_id=entity_id,
        entity_type=entity_type,  # type: ignore[arg-type]
        event_timestamp=event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if ts_ok else "timestamp parse failed",
    )


__all__ = [
    "assign_identity_entity",
    "build_identity_extraction_result",
    "looks_like_ip",
    "nested_str",
    "normalize_auth_result",
    "normalize_username",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
]
