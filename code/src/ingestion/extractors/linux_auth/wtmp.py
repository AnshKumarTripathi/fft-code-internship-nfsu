"""wtmp / utmp / btmp text-export extraction (``linux_wtmp``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.linux_auth.common import (
    build_extraction_result,
    looks_like_ip,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

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

_UTMPDUMP = re.compile(
    r"^\[(?P<type>\d+)\]\s+"
    r"\[(?P<pid>[^\]]*)\]\s+"
    r"\[(?P<tty>[^\]]*)\]\s+"
    r"\[(?P<user>[^\]]*)\]\s+"
    r"\[(?P<host>[^\]]*)\]\s+"
    r"\[(?P<addr>[^\]]*)\]\s+"
    r"\[(?P<when>[^\]]+)\]"
)

_LAST = re.compile(
    r"^(?P<user>\S+)\s+"
    r"(?P<tty>pts/\S+|tty\S+|console|:0)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2})(?::(?P<sec>\d{2}))?"
    r"(?:\s+(?P<year>\d{4}))?"
)

_LAST_BOOT = re.compile(
    r"^(?P<user>reboot|shutdown)\s+system\s+boot\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2})(?::(?P<sec>\d{2}))?"
    r"(?:\s+(?P<year>\d{4}))?"
)

_UTMPDUMP_WHEN = (
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S %Y %Z",
)


def extract_linux_wtmp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract entity and timestamp from ``last`` or ``utmpdump`` text.

    Does not apply syslog Dec→Jan carry. ``year_state`` / ``year_policy`` are
    accepted for the extractor protocol and ignored.
    """
    del year_state, year_policy
    stripped = line.strip()
    dump = _UTMPDUMP.match(stripped)
    if dump:
        return _from_utmpdump(dump, default_year=default_year)
    boot = _LAST_BOOT.match(stripped)
    if boot:
        return _from_last(boot, default_year=default_year, is_boot=True)
    last = _LAST.match(stripped)
    if last:
        return _from_last(last, default_year=default_year, is_boot=False)
    return ExtractionResult(
        extraction_ok=False,
        failure_reason="no wtmp/last pattern matched",
    )


def _from_utmpdump(match: re.Match[str], *, default_year: int) -> ExtractionResult:
    username = (match.group("user") or "").strip()
    tty = (match.group("tty") or "").strip()
    host = (match.group("host") or "").strip()
    addr = (match.group("addr") or "").strip()
    src_ip = ""
    hostname = ""
    if looks_like_ip(host):
        src_ip = host
    elif looks_like_ip(addr):
        src_ip = addr
    if host and not looks_like_ip(host):
        hostname = host
    event_timestamp, ts_ok = _parse_utmpdump_when(match.group("when"), default_year)
    extra = {"tty": tty, "service": "wtmp"}
    return build_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        auth_result="login",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no wtmp entity extracted",
    )


def _from_last(
    match: re.Match[str], *, default_year: int, is_boot: bool
) -> ExtractionResult:
    username = match.group("user")
    host = match.group("host")
    src_ip = host if looks_like_ip(host) else ""
    hostname = "" if src_ip else host
    extra = {"service": "wtmp"}
    if is_boot:
        extra["tty"] = "system"
        auth_result = "session_opened"
    else:
        extra["tty"] = match.group("tty")
        auth_result = "login"
    event_timestamp, ts_ok = _timestamp_from_last_groups(match, default_year)
    return build_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no wtmp entity extracted",
    )


def _timestamp_from_last_groups(
    match: re.Match[str], default_year: int
) -> tuple[datetime | None, bool]:
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    hour, minute = (int(part) for part in match.group("time").split(":"))
    second = int(match.group("sec") or 0)
    year = int(match.group("year") or default_year)
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc), True
    except ValueError:
        return None, False


def _parse_utmpdump_when(when: str, default_year: int) -> tuple[datetime | None, bool]:
    text = when.strip()
    for fmt in _UTMPDUMP_WHEN:
        try:
            parsed = datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed, True
        except ValueError:
            continue
    match = re.search(
        r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\s+(?P<year>\d{4}))?",
        text,
    )
    if not match:
        return None, False
    month = _MONTHS[match.group("month")]
    day = int(match.group("day"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    year = int(match.group("year") or default_year)
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc), True
    except ValueError:
        return None, False
