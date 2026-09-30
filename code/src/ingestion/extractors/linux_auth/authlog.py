"""sudo / su / login syslog extraction (``linux_auth``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.linux_auth.common import (
    build_extraction_result,
    extract_syslog_hostname,
    looks_like_ip,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import (
    YEAR_POLICY_CARRY,
    SyslogYearState,
    parse_syslog_timestamp,
)

_SUDO = re.compile(r"\bsudo:\s+(?P<user>\S+)\s*:")
_SUDO_TTY = re.compile(r"TTY=(?P<tty>\S+)")
_SU = re.compile(
    r"\bsu\[\d+\]:\s+(?:\(to (?P<target>\S+)\)\s+)?(?P<user>\S+)"
    r"(?:\s+on\s+(?P<tty>\S+))?",
    re.IGNORECASE,
)
_LOGIN_FAIL = re.compile(
    r"FAILED LOGIN.*?FROM\s+(?P<src>\S+)\s+FOR\s+(?P<user>\S+)",
    re.IGNORECASE,
)
_LOGIN_PROG = re.compile(r"\blogin\[\d+\]:", re.IGNORECASE)
_AUTH_FAILURE = re.compile(r"authentication failure", re.IGNORECASE)


def extract_linux_authlog(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract entity and fields from sudo/su/login auth.log lines."""
    event_timestamp, ts_ok = parse_syslog_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname = extract_syslog_hostname(line)
    username = ""
    src_ip = ""
    auth_result = ""
    extra: dict[str, str] = {}

    sudo = _SUDO.search(line)
    if sudo:
        username = sudo.group("user")
        auth_result = "sudo"
        extra["service"] = "sudo"
        tty = _SUDO_TTY.search(line)
        if tty:
            extra["tty"] = tty.group("tty")
        return build_extraction_result(
            username=username,
            src_ip=src_ip,
            hostname=hostname,
            auth_result=auth_result,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no linux_auth entity extracted",
        )

    su_match = _SU.search(line)
    if su_match:
        username = su_match.group("user")
        auth_result = "su"
        extra["service"] = "su"
        if su_match.group("tty"):
            extra["tty"] = su_match.group("tty")
        return build_extraction_result(
            username=username,
            src_ip=src_ip,
            hostname=hostname,
            auth_result=auth_result,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no linux_auth entity extracted",
        )

    login_fail = _LOGIN_FAIL.search(line)
    if login_fail:
        username = login_fail.group("user").rstrip(",")
        src_token = login_fail.group("src")
        if looks_like_ip(src_token):
            src_ip = src_token
        return build_extraction_result(
            username=username,
            src_ip=src_ip,
            hostname=hostname,
            auth_result="login",
            extra_fields={"service": "login"},
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no linux_auth entity extracted",
        )

    if _LOGIN_PROG.search(line) and _AUTH_FAILURE.search(line):
        extra["service"] = "login"
        return build_extraction_result(
            username=username,
            src_ip=src_ip,
            hostname=hostname,
            auth_result="login",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no linux_auth entity extracted",
        )

    return build_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_auth pattern matched",
    )
