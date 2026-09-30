"""MIT / Heimdal KDC syslog extraction (``kerberos_kdc``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    looks_like_ip,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

REQ_TYPE = re.compile(r"\b(?P<req>AS_REQ|TGS_REQ)\b")
PRINCIPAL = re.compile(r"\b(?P<user>[A-Za-z0-9._/-]+)@(?P<realm>[A-Z0-9.-]+)\b")
CLIENT_IP = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):")
ISSUE = re.compile(r"\bISSUE\b")
FAIL = re.compile(r"\b(?:NEEDED_PREAUTH|CLIENT_NOT_FOUND|UNKNOWN_SERVER)\b")


def extract_kerberos_kdc(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract principal/host from MIT krb5kdc AS_REQ / TGS_REQ syslog."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    if program:
        extra["program"] = program
    req = REQ_TYPE.search(line)
    if req:
        extra["req_type"] = req.group("req")
    principal = PRINCIPAL.search(line)
    username = ""
    if principal:
        username = principal.group("user")
        extra["principal"] = f"{principal.group('user')}@{principal.group('realm')}"
    ip_match = CLIENT_IP.search(line)
    src_ip = ip_match.group("ip") if ip_match else ""
    if src_ip and not looks_like_ip(src_ip):
        src_ip = ""
    auth_result = "unknown"
    if ISSUE.search(line):
        auth_result = "success"
    elif FAIL.search(line):
        auth_result = "failure"
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        protocol="kerberos",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no kerberos_kdc entity extracted",
    )
