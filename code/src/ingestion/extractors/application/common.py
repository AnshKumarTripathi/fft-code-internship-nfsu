"""Shared timestamp, entity, and raw_fields helpers for application families."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.ingestion.extractors.identity.common import (
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult

_TS_KEYS = ("timestamp", "event_time", "time", "ts")
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_application_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from common app JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    return None


def parse_combined_log_time(token: str) -> datetime | None:
    """Parse Apache/Nginx bracket time ``10/Oct/2000:13:55:36 -0700``."""
    stripped = token.strip().strip("[]")
    try:
        parsed = datetime.strptime(stripped, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        try:
            parsed = datetime.strptime(stripped, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_apache_error_time(line: str) -> datetime | None:
    """Parse ``[Wed Jan 15 10:00:01.123456 2024]`` without syslog carry."""
    match = re.match(
        r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
        r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?\s+"
        r"(?P<year>\d{4})\]",
        line.strip(),
    )
    if match is None:
        return None
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("hms").split(":"))
    micro = 0
    frac = match.group("frac")
    if frac:
        micro = int(frac[:6].ljust(6, "0"))
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_nginx_error_time(line: str) -> datetime | None:
    """Parse ``2024/01/15 10:00:01`` at the start of an Nginx error line."""
    match = re.match(r"^(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})", line.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_epoch_millis(value: Any) -> datetime | None:
    """Parse Kong ``started_at`` millisecond epoch. Does not touch year-carry."""
    try:
        millis = float(value)
    except (TypeError, ValueError):
        return None
    if millis <= 0:
        return None
    seconds = millis / 1000.0 if millis > 10_000_000_000 else millis
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def assign_application_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
) -> tuple[str, str]:
    """Apply user → ip → host → service entity policy."""
    user = normalize_username(username)
    if user and user not in {"-"}:
        return user, "user"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    if service and service not in {"-"}:
        return service, "service"
    return "", "host"


def build_application_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical application raw_fields."""
    user = normalize_username(username)
    if user in {"-"}:
        user = ""
    src = src_ip if src_ip and looks_like_ip(src_ip) else ""
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

    entity_id, entity_type = assign_application_entity(user, src, host, service)
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
    "assign_application_entity",
    "build_application_extraction_result",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_apache_error_time",
    "parse_application_json_timestamp",
    "parse_combined_log_time",
    "parse_epoch_millis",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_nginx_error_time",
]
