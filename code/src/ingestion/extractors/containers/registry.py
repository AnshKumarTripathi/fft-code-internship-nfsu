"""Container registry pull/push extraction (``container_registry``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    parse_container_json_timestamp,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

COMBINED = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>/v2/\S+) HTTP/'
)
_S3ISH = re.compile(
    r"(?P<day>\d{2})/(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/"
    r"(?P<year>\d{4}):(?P<hms>\d{2}:\d{2}:\d{2})"
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


def _parse_bracket_time(raw: str):
    match = _S3ISH.search(raw)
    if match is None:
        return parse_iso_datetime(raw)
    from datetime import datetime, timezone

    try:
        hour, minute, second = (int(part) for part in match.group("hms").split(":"))
        return datetime(
            int(match.group("year")),
            _MONTHS[match.group("month")],
            int(match.group("day")),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None


def extract_container_registry(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/IP/repo from registry JSON or nginx-on-registry combined."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is not None:
        username = str(obj.get("user") or obj.get("username") or obj.get("actor") or "")
        src_ip = str(obj.get("ip") or obj.get("src_ip") or obj.get("remote_ip") or "")
        repo = str(obj.get("repository") or obj.get("repo") or "")
        extra: dict[str, str] = {}
        action = str(obj.get("action") or obj.get("operation") or "")
        if action:
            extra["action"] = action
        if repo:
            extra["repository"] = repo
        event_timestamp = parse_container_json_timestamp(obj)
        return build_container_extraction_result(
            username=username,
            src_ip=src_ip,
            service=repo,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no container_registry entity extracted",
        )
    match = COMBINED.match(line.strip())
    extra = {}
    username = ""
    src_ip = ""
    service = ""
    event_timestamp = None
    if match:
        src_ip = match.group("ip")
        username = match.group("user")
        extra["method"] = match.group("method")
        extra["path"] = match.group("path")
        path = match.group("path")
        parts = path.strip("/").split("/")
        if len(parts) >= 3:
            service = "/".join(parts[1:3])
            extra["repository"] = service
        event_timestamp = _parse_bracket_time(match.group("ts"))
    return build_container_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no container_registry entity extracted",
    )
