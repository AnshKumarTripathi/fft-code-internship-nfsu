"""Shared event_class, entity, and timestamp helpers for database engines."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.ingestion.extractors.identity.common import parse_json_object
from src.ingestion.extractors.unix_os.common import (
    looks_like_ip,
    normalize_username,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult

EVENT_CLASSES = frozenset(
    {
        "query",
        "slow",
        "audit",
        "wal",
        "replication",
        "session",
        "ddl",
        "backup",
        "procedure",
    }
)

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
_REDIS_TS = re.compile(
    r"(?P<day>\d{1,2})\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<year>\d{4})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?"
)
_ORACLE_TS = re.compile(
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<year>\d{4})"
)
_CASSANDRA_TS = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(?P<ms>\d+)"
)


def normalize_event_class(raw: str) -> str:
    """Return a canonical event_class or empty if unknown."""
    token = (raw or "").strip().lower()
    if token in EVENT_CLASSES:
        return token
    return ""


def parse_epoch_timestamp(token: str) -> datetime | None:
    """Parse Unix epoch seconds (Redis MONITOR). Does not touch year-carry."""
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


def parse_space_iso_timestamp(text: str) -> datetime | None:
    """Parse ``YYYY-MM-DD HH:MM:SS[.frac]`` without syslog year-carry."""
    token = (text or "").strip()
    if not token:
        return None
    token = token.replace(",", ".")
    return parse_iso_datetime(token)


def parse_redis_timestamp(line: str) -> datetime | None:
    """Parse ``15 Jan 2024 10:00:01.123`` from a Redis server log line."""
    match = _REDIS_TS.search(line)
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


def parse_oracle_alert_timestamp(line: str) -> datetime | None:
    """Parse ``Tue Jan 15 10:00:01 2024`` from an Oracle alert line."""
    match = _ORACLE_TS.search(line)
    if match is None:
        return None
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("hms").split(":"))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_cassandra_timestamp(line: str) -> datetime | None:
    """Parse ``2024-01-15 10:00:01,123`` from Cassandra system.log text."""
    match = _CASSANDRA_TS.search(line)
    if match is None:
        return None
    return parse_iso_datetime(f"{match.group('ts')}.{match.group('ms')}")


def parse_mongo_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse MongoDB JSON ``t.$date`` or string ``t``."""
    raw = obj.get("t")
    if isinstance(raw, dict):
        raw = raw.get("$date")
    if raw in {None, ""}:
        return None
    return parse_iso_datetime(str(raw))


def assign_database_entity(
    username: str = "",
    service: str = "",
    hostname: str = "",
) -> tuple[str, str]:
    """Apply user → service (db/cluster) → host entity policy."""
    user = normalize_username(username)
    if user:
        return user, "user"
    if service and service not in {"-"}:
        return service, "service"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    return "", "host"


def build_database_extraction_result(
    *,
    event_class: str,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical database raw_fields."""
    user = normalize_username(username)
    klass = normalize_event_class(event_class) or "query"
    src = src_ip if src_ip and looks_like_ip(src_ip) else ""
    host = hostname if hostname not in {"", "-"} else ""
    db_service = service if service not in {"", "-"} else ""
    raw_fields: dict[str, Any] = {"event_class": klass}
    if user:
        raw_fields["username"] = user
    if db_service:
        raw_fields["database"] = db_service
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

    entity_id, entity_type = assign_database_entity(user, db_service, host)
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
    "EVENT_CLASSES",
    "assign_database_entity",
    "build_database_extraction_result",
    "looks_like_ip",
    "normalize_event_class",
    "normalize_username",
    "parse_cassandra_timestamp",
    "parse_epoch_timestamp",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_mongo_timestamp",
    "parse_oracle_alert_timestamp",
    "parse_redis_timestamp",
    "parse_space_iso_timestamp",
]
