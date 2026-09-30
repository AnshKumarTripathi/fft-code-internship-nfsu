"""Shared syslog, entity, and action helpers for network families."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.ingestion.extractors.unix_os.common import (
    looks_like_ip,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_ALLOW_TOKENS = frozenset({"allow", "allowed", "pass", "permit", "permitted", "accept", "accepted"})
_DENY_TOKENS = frozenset({"deny", "denied", "block", "blocked", "drop", "reject", "rejected"})


def normalize_action(raw: str) -> str:
    """Map dialect tokens to allow / deny / empty."""
    token = (raw or "").strip().lower()
    if token in _ALLOW_TOKENS:
        return "allow"
    if token in _DENY_TOKENS:
        return "deny"
    return ""


def action_to_auth_result(action: str) -> str:
    """Optional auth_result: allow→success, deny→failure."""
    if action == "allow":
        return "success"
    if action == "deny":
        return "failure"
    return "unknown"


def parse_epoch_timestamp(token: str) -> datetime | None:
    """Parse Unix epoch seconds (Squid). Does not touch syslog year-carry."""
    try:
        value = float(token)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def parse_network_syslog(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> tuple[datetime | None, bool, str, str, str]:
    """Return timestamp, ok flag, hostname, program, pid."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname, program, pid = parse_syslog_fields(line)
    return event_timestamp, ts_ok, hostname, program, pid


def syslog_extra(program: str = "", pid: str = "") -> dict[str, str]:
    """Program/pid extras for raw_fields."""
    extra: dict[str, str] = {}
    if program:
        extra["program"] = program
    if pid:
        extra["pid"] = pid
    return extra


def assign_network_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
) -> tuple[str, str]:
    """Apply user → ip → host entity policy."""
    user = normalize_username(username)
    if user:
        return user, "user"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname:
        return hostname, "host"
    return "", "host"


def build_network_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    src_port: str = "",
    dst_port: str = "",
    action: str = "",
    protocol: str = "",
    hostname: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
    prefer_ip_entity: bool = False,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical network raw_fields."""
    user = "" if prefer_ip_entity else normalize_username(username)
    src = src_ip if src_ip and looks_like_ip(src_ip) else ""
    dst = dst_ip if dst_ip and looks_like_ip(dst_ip) else ""
    normalized_action = normalize_action(action) if action else ""
    raw_fields: dict[str, Any] = {}
    if user:
        raw_fields["username"] = user
    if src:
        raw_fields["src_ip"] = src
    if dst:
        raw_fields["dst_ip"] = dst
    if src_port:
        raw_fields["src_port"] = str(src_port)
    if dst_port:
        raw_fields["dst_port"] = str(dst_port)
    if normalized_action:
        raw_fields["action"] = normalized_action
        raw_fields["auth_result"] = action_to_auth_result(normalized_action)
    if protocol:
        raw_fields["protocol"] = protocol
    if hostname:
        raw_fields["hostname"] = hostname
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    if prefer_ip_entity:
        entity_id, entity_type = assign_network_entity("", src, hostname)
    else:
        entity_id, entity_type = assign_network_entity(user, src, hostname)
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
    "action_to_auth_result",
    "assign_network_entity",
    "build_network_extraction_result",
    "looks_like_ip",
    "normalize_action",
    "normalize_username",
    "parse_epoch_timestamp",
    "parse_iso_datetime",
    "parse_network_syslog",
    "syslog_extra",
]
