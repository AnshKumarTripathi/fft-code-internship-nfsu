"""Shared timestamp, entity, and raw_fields helpers for middleware families."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from src.ingestion.extractors.identity.common import (
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.extractors.unix_os.common import (
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

BRACKET_TS = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.](?P<ms>\d+)\]"
)
SPACE_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"
)
_TS_KEYS = ("ts", "timestamp", "time", "created", "event_time")
BARE_IPV4 = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def canonical_src_ip(raw: str) -> str:
    """Return an IP string, dropping placeholders."""
    token = (raw or "").strip().strip("[]")
    if not token or token in {"-", "localhost", "unknown"}:
        return ""
    if looks_like_ip(token):
        return token
    return ""


def parse_middleware_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from middleware JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    return None


def parse_bracket_or_space_timestamp(line: str) -> datetime | None:
    """Parse Kafka/Airflow ``[YYYY-MM-DD HH:MM:SS,ms]`` or Rabbit space ISO."""
    stripped = line.strip()
    match = BRACKET_TS.match(stripped)
    if match:
        token = f"{match.group('ts')}.{match.group('ms')[:6]}"
        return parse_iso_datetime(token)
    match = SPACE_TS.match(stripped)
    if match:
        token = match.group("ts").replace(",", ".")
        return parse_iso_datetime(token)
    return None


def json_username(obj: dict[str, Any]) -> str:
    """Return a username from common middleware JSON fields."""
    user = obj.get("user")
    if isinstance(user, dict):
        return normalize_username(
            str(user.get("username") or user.get("name") or user.get("login") or "")
        )
    for key in ("user", "username", "actor"):
        value = normalize_username(str(obj.get(key) or ""))
        if value:
            return value
    return normalize_username(nested_str(obj, "user", "username"))


def assign_middleware_entity(
    username: str = "",
    src_ip: str = "",
    service: str = "",
    hostname: str = "",
) -> tuple[str, str]:
    """Apply user → ip → service → host entity policy."""
    user = normalize_username(username)
    if user and user not in {"-"}:
        return user, "user"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if service and service not in {"-"}:
        return service, "service"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    return "", "host"


def build_middleware_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    service: str = "",
    hostname: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical middleware raw_fields."""
    user = normalize_username(username)
    if user in {"-"}:
        user = ""
    src = canonical_src_ip(src_ip)
    host = hostname if hostname not in {"", "-"} else ""
    svc = service if service not in {"", "-"} else ""
    raw_fields: dict[str, Any] = {}
    if user:
        raw_fields["username"] = user
    if src:
        raw_fields["src_ip"] = src
    if host:
        raw_fields["hostname"] = host
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_middleware_entity(user, src, svc, host)
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


def extract_syslog_middleware_line(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None,
    year_policy: str,
    username: str = "",
    src_ip: str = "",
    service: str = "",
    extra_fields: dict[str, Any] | None = None,
    no_match_reason: str,
) -> ExtractionResult:
    """Extract hostname/program and syslog timestamp from a middleware syslog line."""
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, Any] = dict(extra_fields or {})
    if program:
        extra["program"] = program
    if pid:
        extra["pid"] = pid
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    return build_middleware_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason=no_match_reason,
    )


__all__ = [
    "BARE_IPV4",
    "BRACKET_TS",
    "SPACE_TS",
    "YEAR_POLICY_CARRY",
    "assign_middleware_entity",
    "build_middleware_extraction_result",
    "canonical_src_ip",
    "extract_syslog_middleware_line",
    "json_username",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_bracket_or_space_timestamp",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_middleware_json_timestamp",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
]
