"""Snort fast-alert text dialect for ``ids_ips`` (Phase 82).

Locked fixture dialect (classic fast alert)::

    01/15-10:00:01.123456  [**] [1:2001219:1] ET SCAN something [**]
    [Classification: Attempted Information Leak] [Priority: 2]
    {TCP} 10.0.0.1:54321 -> 10.0.0.2:22

Timestamps omit the year; ``default_year`` (file mtime year) and optional
``carry`` Dec→Jan via ``SyslogYearState`` apply — same spirit as syslog.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    looks_like_ip,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import (
    YEAR_POLICY_CARRY,
    YEAR_POLICY_FILE_MTIME,
    SyslogYearState,
    advance_syslog_year,
)

# Snort/Barnyard fast alert (one line). Classification/Priority optional.
SNORT_FAST = re.compile(
    r"^(?P<month>\d{2})/(?P<day>\d{2})-"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<frac>\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+"
    r"\[\*\*\]"
    r"(?:\s+\[Classification:\s*(?P<classification>[^\]]+)\])?"
    r"(?:\s+\[Priority:\s*(?P<priority>\d+)\])?"
    r"\s+\{(?P<proto>[A-Za-z0-9]+)\}\s+"
    r"(?P<src>\S+)\s*->\s*(?P<dst>\S+)\s*$"
)

# Strong content markers (avoid weak "alert" / filterlog steal)
_SNORT_MARKERS = re.compile(
    r"\[\*\*\].*\[\d+:\d+:\d+\].*\[\*\*\].*\{(?:TCP|UDP|ICMP|IP)\}",
    re.IGNORECASE,
)


def looks_like_snort_fast(line: str) -> bool:
    """True when the line matches Snort fast-alert shape (not Suricata JSON)."""
    stripped = line.strip()
    if not stripped or stripped.startswith("{"):
        return False
    if SNORT_FAST.match(stripped):
        return True
    return bool(_SNORT_MARKERS.search(stripped) and "->" in stripped)


def _split_endpoint(token: str) -> tuple[str, str]:
    """Return (ip, port) from ``ip:port`` or bare IP."""
    raw = token.strip().rstrip(",")
    if raw.startswith("[") and "]:" in raw:
        host, _, port = raw[1:].partition("]:")
        return host, port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        return host, port
    return raw, ""


def parse_snort_fast_timestamp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> tuple[datetime | None, bool]:
    """Parse leading ``MM/DD-HH:MM:SS.µs`` as UTC using ``default_year`` / carry."""
    match = SNORT_FAST.match(line.strip())
    if not match:
        return None, False
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    frac = match.group("frac")
    micro = int((frac + "000000")[:6])

    year = default_year
    if year_policy == YEAR_POLICY_CARRY and year_state is not None:
        year = advance_syslog_year(year_state.prev_month, month, year_state.year)
        year_state.year = year
        year_state.prev_month = month
    elif year_policy == YEAR_POLICY_FILE_MTIME and year_state is not None:
        year_state.prev_month = month

    try:
        return (
            datetime(year, month, day, hour, minute, second, micro, tzinfo=timezone.utc),
            True,
        )
    except ValueError:
        return None, False


def extract_snort_fast(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst IP, SID, and priority from a Snort fast-alert line.

    Entity prefers **src IP**, then **dst IP**. ``raw_fields.dialect`` is
    ``snort_fast``.
    """
    match = SNORT_FAST.match(line.strip())
    if not match:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no snort_fast match",
        )

    event_timestamp, ts_ok = parse_snort_fast_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )

    src_raw, src_port = _split_endpoint(match.group("src"))
    dst_raw, dst_port = _split_endpoint(match.group("dst"))
    src_ip = src_raw if looks_like_ip(src_raw) else ""
    dst_ip = dst_raw if looks_like_ip(dst_raw) else ""
    entity_ip = src_ip or dst_ip

    extra: dict[str, str] = {
        "dialect": "snort_fast",
        "sid": match.group("sid"),
        "gid": match.group("gid"),
        "rev": match.group("rev"),
        "signature": match.group("msg").strip(),
        "protocol": match.group("proto").upper(),
    }
    if src_port:
        extra["src_port"] = src_port
    if dst_port:
        extra["dst_port"] = dst_port
    classification = match.group("classification")
    if classification:
        extra["classification"] = classification.strip()
    priority = match.group("priority")
    if priority:
        extra["priority"] = priority

    result = build_security_extraction_result(
        src_ip=entity_ip,
        dst_ip=dst_ip,
        severity=priority or "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no snort_fast entity extracted",
    )
    if not result.extraction_ok:
        return result

    # Correct IP fields when entity fell back to dst (builder stamped dst as src_ip).
    fields = dict(result.raw_fields)
    if src_ip:
        fields["src_ip"] = src_ip
    else:
        fields.pop("src_ip", None)
    if dst_ip:
        fields["dst_ip"] = dst_ip
    return result.model_copy(update={"raw_fields": fields})
