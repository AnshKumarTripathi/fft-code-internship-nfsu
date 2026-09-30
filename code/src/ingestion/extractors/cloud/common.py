"""Shared JSON timestamp, entity, and raw_fields helpers for cloud families."""

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

_TS_KEYS = (
    "eventTime",
    "event_time",
    "time",
    "timestamp",
    "TimeGenerated",
    "published",
    "configurationItemCaptureTime",
    "insertId",
)
_S3_BRACKET = re.compile(
    r"\[(?P<day>\d{2})/(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/"
    r"(?P<year>\d{4}):(?P<hms>\d{2}:\d{2}:\d{2}) (?P<tz>[+-]\d{4})\]"
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
_AWS_INTERNAL = frozenset({"aws internal", "lambda", "-"})


def unwrap_json_record(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a CloudTrail-style inner record when wrapped in ``Records``."""
    if obj is None:
        return None
    records = obj.get("Records")
    if isinstance(records, list) and records and isinstance(records[0], dict):
        return records[0]
    return obj


def parse_cloud_json_line(line: str) -> dict[str, Any] | None:
    """Parse one JSON object, unwrapping a compact ``Records`` wrapper."""
    return unwrap_json_record(parse_json_object(line))


def parse_cloud_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from common cloud JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        if key == "insertId":
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    nested = nested_str(obj, "properties", "createdDateTime")
    if nested:
        parsed = parse_iso_datetime(nested)
        if parsed is not None:
            return parsed
    return parse_iso_datetime(str(obj.get("timestamp") or ""))


def parse_s3_bracket_time(line: str) -> datetime | None:
    """Parse S3 ``[06/Feb/2019:00:00:38 +0000]`` without syslog carry."""
    match = _S3_BRACKET.search(line)
    if match is None:
        return None
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("hms").split(":"))
    tz_raw = match.group("tz")
    sign = 1 if tz_raw[0] == "+" else -1
    offset_hours = int(tz_raw[1:3])
    offset_mins = int(tz_raw[3:5])
    from datetime import timedelta

    tzinfo = timezone(sign * timedelta(hours=offset_hours, minutes=offset_mins))
    try:
        parsed = datetime(year, month, day, hour, minute, second, tzinfo=tzinfo)
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def parse_epoch_seconds(token: str) -> datetime | None:
    """Parse Unix epoch seconds (VPC Flow start/end). No syslog carry."""
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


def arn_tail(arn: str) -> str:
    """Return the last path segment of an ARN, else empty."""
    token = (arn or "").strip()
    if not token:
        return ""
    if "/" in token:
        return token.rsplit("/", 1)[-1]
    if ":" in token:
        return token.rsplit(":", 1)[-1]
    return token


def canonical_src_ip(raw: str) -> str:
    """Return an IP string, dropping AWS Internal and non-IP tokens."""
    token = (raw or "").strip()
    if not token or token.lower() in _AWS_INTERNAL:
        return ""
    if looks_like_ip(token):
        return token
    return ""


def assign_cloud_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    *,
    prefer_service: bool = False,
) -> tuple[str, str]:
    """Apply user → ip → host → service entity policy.

    CloudTrail assumed-role / service principals map to ``service`` even when a
    source IP is present (ARN stays in ``raw_fields``).
    """
    user = normalize_username(username)
    if user and user not in {"-"}:
        return user, "user"
    if prefer_service and service and service not in {"-"}:
        return service, "service"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    if service and service not in {"-"}:
        return service, "service"
    return "", "host"


def build_cloud_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
    prefer_service: bool = False,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical cloud raw_fields."""
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

    entity_id, entity_type = assign_cloud_entity(
        user, src, host, svc, prefer_service=prefer_service
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


__all__ = [
    "arn_tail",
    "assign_cloud_entity",
    "build_cloud_extraction_result",
    "canonical_src_ip",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_cloud_json_line",
    "parse_cloud_json_timestamp",
    "parse_epoch_seconds",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_s3_bracket_time",
    "unwrap_json_record",
]
