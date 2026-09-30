"""Shared JSON timestamp, entity, and raw_fields helpers for security families."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.ingestion.extractors.identity.common import (
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult

_TS_KEYS = ("timestamp", "event_time", "time", "ts", "time_stamp")


def parse_security_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from common security JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    return None


def assign_security_entity(
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


def build_security_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    hostname: str = "",
    service: str = "",
    action: str = "",
    severity: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical security raw_fields."""
    user = normalize_username(username)
    src = src_ip if src_ip and looks_like_ip(src_ip) else ""
    dst = dst_ip if dst_ip and looks_like_ip(dst_ip) else ""
    raw_fields: dict[str, Any] = {}
    if user:
        raw_fields["username"] = user
    if src:
        raw_fields["src_ip"] = src
    if dst:
        raw_fields["dst_ip"] = dst
    if hostname:
        raw_fields["hostname"] = hostname
    if action:
        raw_fields["action"] = str(action)
    if severity not in {None, ""}:
        raw_fields["severity"] = str(severity)
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_security_entity(user, src, hostname, service)
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
    "assign_security_entity",
    "build_security_extraction_result",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_security_json_timestamp",
]
