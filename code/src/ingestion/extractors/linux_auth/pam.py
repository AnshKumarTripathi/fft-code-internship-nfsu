"""Non-sshd PAM extraction (``linux_pam``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.linux_auth.common import (
    build_extraction_result,
    extract_syslog_hostname,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import (
    YEAR_POLICY_CARRY,
    SyslogYearState,
    parse_syslog_timestamp,
)

_PAM_SERVICE = re.compile(
    r"pam_(?:unix|sss)\((?P<service>[^:)\s]+):",
    re.IGNORECASE,
)
_SESSION_OPENED = re.compile(r"session opened for user (?P<user>\S+)")
_SESSION_CLOSED = re.compile(r"session closed for user (?P<user>\S+)")
_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
_PAM_RHOST = re.compile(r"\brhost=(?P<ip>\S+)")
_AUTH_FAILURE = re.compile(r"authentication failure", re.IGNORECASE)
_SSHD_SERVICE = re.compile(r"pam_(?:unix|sss)\(sshd:", re.IGNORECASE)


def extract_linux_pam(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract entity and fields from a non-sshd PAM syslog line."""
    event_timestamp, ts_ok = parse_syslog_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname = extract_syslog_hostname(line)
    service = ""
    service_match = _PAM_SERVICE.search(line)
    if service_match:
        service = service_match.group("service")

    username = ""
    src_ip = ""
    auth_result = "pam"
    opened = _SESSION_OPENED.search(line)
    closed = _SESSION_CLOSED.search(line)
    if opened:
        username = opened.group("user")
        auth_result = "session_opened"
    elif closed:
        username = closed.group("user")
        auth_result = "session_closed"
    else:
        pam_user = _PAM_USER.search(line)
        if pam_user:
            username = pam_user.group("user")
        if _AUTH_FAILURE.search(line):
            auth_result = "failed"

    rhost = _PAM_RHOST.search(line)
    if rhost:
        src_ip = rhost.group("ip").rstrip(";")

    if _SSHD_SERVICE.search(line):
        return build_extraction_result(
            username=username,
            src_ip=src_ip,
            hostname=hostname,
            auth_result=auth_result,
            extra_fields={"service": "sshd"},
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="sshd PAM belongs to ssh",
        )

    return build_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        auth_result=auth_result,
        extra_fields={"service": service},
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no pam user or host extracted",
    )
