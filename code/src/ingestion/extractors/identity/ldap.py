"""OpenLDAP slapd / directory bind extraction (``ldap``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.identity.common import (
    build_identity_extraction_result,
    nested_str,
    parse_iso_datetime,
    parse_json_object,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.extractors.unix_os.common import is_rfc3164, is_rfc5424, looks_like_ip
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

BIND_DN = re.compile(r'BIND dn="(?P<dn>[^"]*)"', re.IGNORECASE)
ERR = re.compile(r"\berr=(?P<err>\d+)")
UID = re.compile(r"\buid=(?P<uid>[^,]+)", re.IGNORECASE)
CLIENT_IP = re.compile(r"IP=(?P<ip>[0-9a-fA-F:.]+)")


def _username_from_dn(dn: str) -> str:
    if not dn:
        return ""
    match = UID.search(dn)
    if match:
        return match.group("uid").strip()
    return dn.strip()


def extract_ldap(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip from slapd BIND/RESULT or one-line JSON bind logs."""
    obj = parse_json_object(line)
    if obj is not None:
        return _extract_json(obj)

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

    bind = BIND_DN.search(line)
    bind_dn = bind.group("dn") if bind else ""
    if bind_dn:
        extra["bind_dn"] = bind_dn
    username = _username_from_dn(bind_dn)

    err_match = ERR.search(line)
    auth_result = "unknown"
    if err_match:
        extra["ldap_err"] = err_match.group("err")
        auth_result = "success" if err_match.group("err") == "0" else "failure"

    ip_match = CLIENT_IP.search(line)
    src_ip = ip_match.group("ip") if ip_match else ""
    if src_ip and not looks_like_ip(src_ip):
        src_ip = ""

    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        protocol="ldap",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok or is_rfc3164(line) or is_rfc5424(line),
        no_match_reason="no ldap entity extracted",
    )


def _extract_json(obj: dict) -> ExtractionResult:
    bind_dn = str(obj.get("bindDN") or obj.get("bind_dn") or "")
    username = _username_from_dn(bind_dn)
    src_ip = str(obj.get("client") or obj.get("src_ip") or obj.get("ip") or "")
    result_raw = obj.get("result")
    auth_result = "unknown"
    extra: dict[str, str] = {}
    if bind_dn:
        extra["bind_dn"] = bind_dn
    if result_raw is not None:
        extra["ldap_err"] = str(result_raw)
        try:
            auth_result = "success" if int(result_raw) == 0 else "failure"
        except (TypeError, ValueError):
            auth_result = "unknown"
    ts = nested_str(obj, "time") or nested_str(obj, "timestamp")
    event_timestamp = parse_iso_datetime(ts) if ts else None
    return build_identity_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=str(obj.get("hostname") or ""),
        protocol="ldap",
        auth_result=auth_result,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no ldap entity extracted",
    )
