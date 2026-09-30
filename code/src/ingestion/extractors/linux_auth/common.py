"""Shared syslog hostname, field, and entity helpers for Linux auth families."""

from __future__ import annotations

import re
from datetime import datetime

from src.ingestion.models import ExtractionResult

_MASKED_USERNAME = re.compile(r"^\*+$")
_SYSLOG_HOST = re.compile(
    r"^(?:(?P<year>\d{4})\s+)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
)
_LOOKS_LIKE_IP = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:+[0-9a-fA-F:.]+)$"
)


def extract_syslog_hostname(line: str) -> str:
    """Return the syslog host token after the timestamp, if present."""
    match = _SYSLOG_HOST.match(line.strip())
    if not match:
        return ""
    return match.group("hostname")


def looks_like_ip(token: str) -> bool:
    """Return True when ``token`` looks like IPv4 or IPv6."""
    if not token or token in {":", "*", "-", "0.0.0.0", "::"}:
        return False
    return _LOOKS_LIKE_IP.fullmatch(token) is not None


def assign_entity(
    username: str,
    src_ip: str,
    hostname: str,
) -> tuple[str, str]:
    """Apply user → ip → host entity policy (same as v2 SSH)."""
    entity_id = username
    entity_type = "user"
    if entity_id and _MASKED_USERNAME.fullmatch(entity_id):
        if src_ip:
            return src_ip, "ip"
        entity_id = ""
        entity_type = "user"
    elif not entity_id and src_ip:
        return src_ip, "ip"
    if not entity_id and hostname:
        return hostname, "host"
    return entity_id, entity_type


def build_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    auth_result: str = "",
    extra_fields: dict | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical raw_fields and entity policy."""
    raw_fields: dict = {}
    if username:
        raw_fields["username"] = username
    if src_ip:
        raw_fields["src_ip"] = src_ip
    if hostname:
        raw_fields["hostname"] = hostname
    if auth_result:
        raw_fields["auth_result"] = auth_result
    if extra_fields:
        for key, value in extra_fields.items():
            if value:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_entity(username, src_ip, hostname)
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
