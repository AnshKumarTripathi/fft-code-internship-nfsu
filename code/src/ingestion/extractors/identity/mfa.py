"""Duo MFA JSON / syslog extraction (``mfa``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    looks_like_ip,
    normalize_auth_result,
    parse_iso_datetime,
    parse_json_object,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.extractors.unix_os.common import is_rfc3164, is_rfc5424
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

USER_EQ = re.compile(r"\buser=(?P<user>\S+)", re.IGNORECASE)
IP_EQ = re.compile(r"\bip=(?P<ip>\S+)", re.IGNORECASE)


def extract_mfa(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip from Duo Admin JSON or duo syslog."""
    obj = parse_json_object(line)
    if obj is not None:
        return _extract_json(obj)

    event_timestamp = None
    ts_ok = False
    if is_rfc3164(line) or is_rfc5424(line):
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
    user_match = USER_EQ.search(line)
    username = user_match.group("user").strip("',\"") if user_match else ""
    ip_match = IP_EQ.search(line)
    src_ip = ip_match.group("ip").strip("',\"") if ip_match else ""
    if src_ip and not looks_like_ip(src_ip):
        src_ip = ""
    lowered = line.lower()
    auth_result = "unknown"
    if "fraud" in lowered or "denied" in lowered or "failure" in lowered:
        auth_result = "failure"
    elif "success" in lowered or "allow" in lowered:
        auth_result = "success"
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        protocol="duo",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no mfa entity extracted",
    )


def _extract_json(obj: dict) -> ExtractionResult:
    username = str(obj.get("username") or obj.get("user") or "")
    src_ip = str(obj.get("ip") or obj.get("src_ip") or "")
    eventtype = str(obj.get("eventtype") or "")
    extra: dict[str, str] = {}
    if eventtype:
        extra["eventtype"] = eventtype
    auth_result = normalize_auth_result(str(obj.get("result") or ""))
    ts = str(obj.get("isotimestamp") or obj.get("timestamp") or obj.get("time") or "")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        protocol="duo",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no mfa entity extracted",
    )
