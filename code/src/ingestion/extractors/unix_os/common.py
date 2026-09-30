"""Shared syslog / entity helpers for Unix OS and macOS families."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import (
    MONTHS,
    YEAR_POLICY_CARRY,
    SyslogYearState,
    parse_syslog_timestamp,
)

_MASKED_USERNAME = re.compile(r"^\*+$")
_UNSET_AUID = frozenset({"4294967295", "-1", "unset"})
_RFC3164 = re.compile(
    r"^(?:(?P<year>\d{4})\s+)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
)
_RFC5424 = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+)\s+"
    r"(?P<pid>\S+)"
)
_LOOKS_LIKE_IP = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:+[0-9a-fA-F:.]+)$"
)
_ISO_OFFSET = re.compile(r"([+-])(\d{2})(\d{2})$")


def is_rfc3164(line: str) -> bool:
    """Return True when the line starts with a classic syslog timestamp + host."""
    return _RFC3164.match(line.strip()) is not None


def is_rfc5424(line: str) -> bool:
    """Return True when the line is RFC5424 syslog."""
    return _RFC5424.match(line.strip()) is not None


def parse_syslog_fields(line: str) -> tuple[str, str, str]:
    """Return hostname, program, pid from RFC3164 or RFC5424."""
    stripped = line.strip()
    match = _RFC3164.match(stripped)
    if match:
        return match.group("hostname"), match.group("program"), match.group("pid") or ""
    match = _RFC5424.match(stripped)
    if match:
        pid = match.group("pid")
        if pid == "-":
            pid = ""
        program = match.group("program")
        if program == "-":
            program = ""
        hostname = match.group("hostname")
        if hostname == "-":
            hostname = ""
        return hostname, program, pid
    return "", "", ""


def parse_syslog_or_rfc5424_timestamp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> tuple[datetime | None, bool]:
    """Parse RFC3164 (with year-carry) or RFC5424 ISO timestamps."""
    rfc5424 = _RFC5424.match(line.strip())
    if rfc5424:
        parsed = parse_iso_datetime(rfc5424.group("ts"))
        return parsed, parsed is not None
    return parse_syslog_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )


def parse_iso_datetime(text: str) -> datetime | None:
    """Parse ISO-8601 / space-separated datetimes; do not apply syslog carry."""
    token = text.strip().strip('"')
    if not token:
        return None
    if "T" not in token and re.match(r"\d{4}-\d{2}-\d{2} ", token):
        token = token.replace(" ", "T", 1)
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"
    token = re.sub(r"\s+([+-]\d{2}:?\d{2})$", r"\1", token)
    token = _ISO_OFFSET.sub(r"\1\2:\3", token)
    token = re.sub(r"(\.\d{6})\d+", r"\1", token)
    try:
        parsed = datetime.fromisoformat(token)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_dmesg_t_timestamp(line: str) -> tuple[datetime | None, bool]:
    """Parse ``dmesg -T`` ``[Mon Jan 15 10:00:01 2024]`` timestamps."""
    match = re.match(
        r"^\[\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<year>\d{4})\]",
        line.strip(),
    )
    if not match:
        iso = re.match(
            r"^\[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]",
            line.strip(),
        )
        if iso:
            parsed = parse_iso_datetime(iso.group("ts"))
            return parsed, parsed is not None
        return None, False
    month = MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc), True
    except ValueError:
        return None, False


def looks_like_ip(token: str) -> bool:
    """Return True when ``token`` looks like IPv4 or IPv6."""
    if not token or token in {":", "*", "-", "0.0.0.0", "::"}:
        return False
    return _LOOKS_LIKE_IP.fullmatch(token) is not None


def normalize_username(username: str) -> str:
    """Drop masked, unset, and placeholder usernames."""
    if not username:
        return ""
    stripped = username.strip().strip('"')
    if not stripped or stripped in {"-", "?"}:
        return ""
    if _MASKED_USERNAME.fullmatch(stripped):
        return ""
    if stripped in _UNSET_AUID:
        return ""
    return stripped


def assign_unix_entity(
    username: str = "",
    src_ip: str = "",
    unit: str = "",
    hostname: str = "",
    program: str = "",
) -> tuple[str, str]:
    """Apply user → ip → service(unit) → host → program-as-service policy."""
    user = normalize_username(username)
    if user:
        return user, "user"
    if src_ip:
        return src_ip, "ip"
    if unit:
        return unit, "service"
    if hostname:
        return hostname, "host"
    if program:
        return program, "service"
    return "", "host"


def mtime_year_timestamp(default_year: int) -> datetime:
    """Last-resort timestamp when a dialect has no wall clock (file mtime year)."""
    return datetime(default_year, 1, 1, tzinfo=timezone.utc)


def build_unix_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    unit: str = "",
    hostname: str = "",
    program: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical Unix OS raw_fields."""
    user = normalize_username(username)
    raw_fields: dict[str, Any] = {}
    if user:
        raw_fields["username"] = user
    if src_ip:
        raw_fields["src_ip"] = src_ip
    if hostname:
        raw_fields["hostname"] = hostname
    if program:
        raw_fields["program"] = program
    if unit:
        raw_fields["unit"] = unit
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_unix_entity(
        user, src_ip, unit, hostname, program
    )
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
