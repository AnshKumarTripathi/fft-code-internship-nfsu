"""FreeRADIUS / TACACS+ extraction (``radius``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    looks_like_ip,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.extractors.unix_os.common import is_rfc3164, is_rfc5424
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import MONTHS, YEAR_POLICY_CARRY, SyslogYearState

LOGIN_OK = re.compile(r"Login OK", re.IGNORECASE)
LOGIN_BAD = re.compile(r"Login incorrect", re.IGNORECASE)
ACCESS_ACCEPT = re.compile(r"\bAccess-Accept\b", re.IGNORECASE)
ACCESS_REJECT = re.compile(r"\bAccess-Reject\b", re.IGNORECASE)
AUTH_USER = re.compile(
    r"(?:Login OK|Login incorrect|Access-Accept|Access-Reject):?\s*\[(?P<user>[^\]]+)\]",
    re.IGNORECASE,
)
CLI_IP = re.compile(r"\bcli\s+(?P<ip>[0-9a-fA-F:.]+)", re.IGNORECASE)
FROM_CLIENT = re.compile(r"from client\s+(?P<nas>\S+)", re.IGNORECASE)
TAC_USER = re.compile(r"login query for '(?P<user>[^']+)'", re.IGNORECASE)
TAC_FROM = re.compile(r"\bfrom\s+(?P<ip>\S+)", re.IGNORECASE)
TAC_OK = re.compile(r"\baccepted\b", re.IGNORECASE)
TAC_BAD = re.compile(r"\brejected\b", re.IGNORECASE)
FREERADIUS_TS = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<year>\d{4})"
)
USER_WORD = re.compile(r"\b(?:for|user)\s+(?P<user>[A-Za-z0-9._-]+)", re.IGNORECASE)
TAC_PROG = re.compile(r"\btac_plus\[", re.IGNORECASE)


def _parse_freeradius_ctime(line: str) -> tuple[datetime | None, bool]:
    match = FREERADIUS_TS.match(line.strip())
    if not match:
        return None, False
    month = MONTHS[match.group("month")]
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc), True
    except ValueError:
        return None, False


def extract_radius(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip from FreeRADIUS Auth lines or tac_plus syslog."""
    if is_rfc3164(line) or is_rfc5424(line):
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    else:
        event_timestamp, ts_ok = _parse_freeradius_ctime(line)

    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    if program:
        extra["program"] = program

    is_tacacs = bool(TAC_PROG.search(line))
    protocol = "tacacs" if is_tacacs else "radius"

    username = ""
    src_ip = ""
    auth_result = "unknown"

    if is_tacacs:
        user_match = TAC_USER.search(line)
        if user_match:
            username = user_match.group("user")
        ip_match = TAC_FROM.search(line)
        if ip_match:
            src_ip = ip_match.group("ip").rstrip(",")
        if TAC_OK.search(line):
            auth_result = "success"
        elif TAC_BAD.search(line):
            auth_result = "failure"
    else:
        user_match = AUTH_USER.search(line)
        if user_match:
            username = user_match.group("user")
        if not username:
            word = USER_WORD.search(line)
            if word:
                username = word.group("user")
        cli = CLI_IP.search(line)
        if cli:
            src_ip = cli.group("ip")
        nas_match = FROM_CLIENT.search(line)
        if nas_match:
            extra["nas"] = nas_match.group("nas")
        if LOGIN_OK.search(line) or ACCESS_ACCEPT.search(line):
            auth_result = "success"
        elif LOGIN_BAD.search(line) or ACCESS_REJECT.search(line):
            auth_result = "failure"

    if src_ip and not looks_like_ip(src_ip):
        src_ip = ""
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        protocol=protocol,
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no radius entity extracted",
    )
