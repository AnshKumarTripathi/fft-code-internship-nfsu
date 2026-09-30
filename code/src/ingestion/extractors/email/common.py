"""Shared timestamp, entity, and raw_fields helpers for email families."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from src.ingestion.extractors.identity.common import (
    looks_like_ip,
    nested_str,
    normalize_auth_result,
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

CLIENT_IP = re.compile(
    r"(?:client=|connect from |from )\S*?\[(?P<ip>[^\]]+)\]",
    re.IGNORECASE,
)
BRACKET_IP = re.compile(r"\[(?P<ip>[0-9a-fA-F:.]+)\]")
RELAY_IP = re.compile(
    r"relay=\S+\s*\[(?P<ip>[^\]]+)\]",
    re.IGNORECASE,
)
IP_FIELD = re.compile(r"\bip[=:]\s*(?P<ip>[0-9a-fA-F:.]+)", re.IGNORECASE)
CLIENT_IP_FIELD = re.compile(
    r"\bclient-ip=(?P<ip>[0-9a-fA-F:.]+)",
    re.IGNORECASE,
)
SASL_USER = re.compile(r"sasl_username=(?P<user>[^\s,;]+)", re.IGNORECASE)
SASL_FAIL = re.compile(r"authentication failed", re.IGNORECASE)
FROM_ANGLE = re.compile(r"from:?\s*<([^>]*)>", re.IGNORECASE)
TO_ANGLE = re.compile(r"to=<([^>]*)>", re.IGNORECASE)
USER_FIELD = re.compile(r"\buser[=:]\s*(?P<user>[^\s,;]+)", re.IGNORECASE)
ACTION_FIELD = re.compile(r"\baction[=:]\s*(?P<action>[^,;]+)", re.IGNORECASE)
SCORE_FIELD = re.compile(r"\bscore[=:]\s*(?P<score>-?[\d.]+)", re.IGNORECASE)
QUEUE_ID = re.compile(
    r"\]:\s*(?:warning:\s+)?(?P<qid>[0-9A-Fa-f]{5,12}):\s",
)
EMAIL_ADDR = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
CHECK_RESULT = re.compile(
    r"\b(?P<result>pass|fail(?:ed)?|none|temperror|permerror|neutral|softfail)\b",
    re.IGNORECASE,
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


def first_bracket_ip(line: str) -> str:
    """Return the first bracketed IP in a syslog-shaped mail line."""
    match = CLIENT_IP.search(line)
    if match:
        parsed = canonical_src_ip(match.group("ip"))
        if parsed:
            return parsed
    match = RELAY_IP.search(line)
    if match:
        parsed = canonical_src_ip(match.group("ip"))
        if parsed:
            return parsed
    match = IP_FIELD.search(line)
    if match:
        parsed = canonical_src_ip(match.group("ip"))
        if parsed:
            return parsed
    match = CLIENT_IP_FIELD.search(line)
    if match:
        parsed = canonical_src_ip(match.group("ip"))
        if parsed:
            return parsed
    match = BRACKET_IP.search(line)
    if match:
        parsed = canonical_src_ip(match.group("ip"))
        if parsed:
            return parsed
    match = BARE_IPV4.search(line)
    if match:
        return canonical_src_ip(match.group("ip"))
    return ""


def envelope_address(line: str, pattern: re.Pattern[str]) -> str:
    """Return a from=/to= address, skipping empty placeholders."""
    match = pattern.search(line)
    if match is None:
        return ""
    return normalize_username(match.group(1))


def parse_email_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from email JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    return None


def assign_email_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
) -> tuple[str, str]:
    """Apply user → ip → host entity policy."""
    user = normalize_username(username)
    if user and user not in {"-"}:
        return user, "user"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    return "", "host"


def build_email_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical email raw_fields."""
    user = normalize_username(username)
    if user in {"-"}:
        user = ""
    src = canonical_src_ip(src_ip)
    host = hostname if hostname not in {"", "-"} else ""
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

    entity_id, entity_type = assign_email_entity(user, src, host)
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


def extract_syslog_mail_line(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None,
    year_policy: str,
    username: str = "",
    src_ip: str = "",
    extra_fields: dict[str, Any] | None = None,
    no_match_reason: str,
) -> ExtractionResult:
    """Extract hostname/program and syslog timestamp from a mail syslog line."""
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
    return build_email_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason=no_match_reason,
    )


__all__ = [
    "ACTION_FIELD",
    "BRACKET_IP",
    "CHECK_RESULT",
    "CLIENT_IP",
    "CLIENT_IP_FIELD",
    "EMAIL_ADDR",
    "FROM_ANGLE",
    "IP_FIELD",
    "QUEUE_ID",
    "RELAY_IP",
    "SASL_FAIL",
    "SASL_USER",
    "SCORE_FIELD",
    "TO_ANGLE",
    "USER_FIELD",
    "YEAR_POLICY_CARRY",
    "assign_email_entity",
    "build_email_extraction_result",
    "canonical_src_ip",
    "envelope_address",
    "extract_syslog_mail_line",
    "first_bracket_ip",
    "looks_like_ip",
    "nested_str",
    "normalize_auth_result",
    "normalize_username",
    "parse_email_json_timestamp",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
]
