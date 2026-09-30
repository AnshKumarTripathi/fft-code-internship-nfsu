"""MTA tracking extraction (``mta``) — Postfix qmgr/cleanup or Exchange."""

from __future__ import annotations

from src.ingestion.extractors.email.common import (
    EMAIL_ADDR,
    FROM_ANGLE,
    QUEUE_ID,
    TO_ANGLE,
    YEAR_POLICY_CARRY,
    build_email_extraction_result,
    canonical_src_ip,
    envelope_address,
    extract_syslog_mail_line,
    first_bracket_ip,
    looks_like_ip,
    normalize_username,
    parse_iso_datetime,
)
from src.ingestion.extractors.email.markers import EXCHANGE_TRACKING, MTA_PROG
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

_EXCHANGE_EVENT = (
    "RECEIVE",
    "SEND",
    "DELIVER",
    "FAIL",
    "DSN",
    "EXPAND",
    "TRANSFER",
)


def extract_mta(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract envelope sender from Postfix MTA syslog or Exchange tracking."""
    stripped = line.strip()
    if EXCHANGE_TRACKING.search(stripped) and not MTA_PROG.search(stripped):
        return _extract_exchange_tracking(stripped)
    username = envelope_address(line, FROM_ANGLE)
    if not username:
        username = envelope_address(line, TO_ANGLE)
    extra: dict[str, str] = {}
    queue = QUEUE_ID.search(line)
    if queue:
        extra["queue_id"] = queue.group("qid")
    return extract_syslog_mail_line(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        username=username,
        src_ip=first_bracket_ip(line),
        extra_fields=extra,
        no_match_reason="no mta entity extracted",
    )


def _extract_exchange_tracking(line: str) -> ExtractionResult:
    """Parse ISO-prefixed Exchange message-tracking CSV. No syslog carry."""
    parts = [part.strip() for part in line.split(",")]
    event_timestamp = parse_iso_datetime(parts[0]) if parts else None
    hostname = ""
    if len(parts) > 1 and parts[1] and "@" not in parts[1] and not looks_like_ip(parts[1]):
        hostname = parts[1]
    username = ""
    src_ip = ""
    extra: dict[str, str] = {}
    for part in parts[1:]:
        upper = part.upper()
        if upper in _EXCHANGE_EVENT:
            extra["event_id"] = upper
            continue
        if looks_like_ip(part) and not src_ip:
            src_ip = canonical_src_ip(part)
            continue
        if not username:
            match = EMAIL_ADDR.search(part)
            if match:
                username = normalize_username(match.group(0))
    return build_email_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no mta exchange entity extracted",
    )
