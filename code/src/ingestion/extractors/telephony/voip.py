"""VoIP / SIP extraction (``voip``) — Asterisk / Kamailio / FreeSWITCH syslog."""

from __future__ import annotations

import re

from src.ingestion.extractors.telephony.common import (
    YEAR_POLICY_CARRY,
    build_telephony_extraction_result,
    canonical_src_ip,
    extract_syslog_telephony_line,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

FROM_SIP_USER = re.compile(
    r"from\s+(?:\"[^\"]*\"\s+)?<?sip:(?P<user>[^@;>\s]+)@",
    re.IGNORECASE,
)
SIP_USER = re.compile(r"sip:(?P<user>[^@;>\s]+)@", re.IGNORECASE)
FROM_IP = re.compile(
    r"\bfrom\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
FAILED_FOR_IP = re.compile(
    r"failed for\s+'?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
IS_REGISTER = re.compile(r"\b(?:REGISTER|Registration)\b", re.IGNORECASE)
SIP_FAIL = re.compile(
    r"\b(?:401|403|unauthorized|wrong password|failed to authenticate|"
    r"registration from .+ failed)\b",
    re.IGNORECASE,
)
SIP_OK = re.compile(r"\b200(?:\s+OK)?\b", re.IGNORECASE)


def extract_voip(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract SIP user or src IP; REGISTER fail sets auth_result=failure."""
    username = ""
    from_user = FROM_SIP_USER.search(line)
    if from_user:
        username = from_user.group("user")
    else:
        sip_user = SIP_USER.search(line)
        if sip_user:
            username = sip_user.group("user")
    ip_match = FROM_IP.search(line) or FAILED_FOR_IP.search(line)
    src_ip = canonical_src_ip(ip_match.group("ip") if ip_match else "")
    extra: dict[str, str] = {}
    if IS_REGISTER.search(line):
        if SIP_FAIL.search(line):
            extra["auth_result"] = "failure"
        elif SIP_OK.search(line):
            extra["auth_result"] = "success"
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_telephony_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            src_ip=src_ip,
            extra_fields=extra,
            no_match_reason="no voip entity extracted",
        )
    return build_telephony_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no voip entity extracted",
    )
