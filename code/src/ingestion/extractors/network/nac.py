"""Cisco ISE NAC extraction (``nac``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ISE_PASS = re.compile(r"\bCISE_Passed_Authentications\b")
ISE_FAIL = re.compile(r"\bCISE_Failed_Attempts\b")
USERNAME = re.compile(r"\bUserName=(?P<user>[^,]+)")
FRAMED_IP = re.compile(r"\bFramed-IP-Address=(?P<ip>[0-9a-fA-F:.]+)")
DEVICE_IP = re.compile(r"\bDevice IP Address=(?P<ip>[0-9a-fA-F:.]+)")


def extract_nac(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/IP from Cisco ISE passed/failed authentications."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    action = ""
    if ISE_PASS.search(line):
        action = "allow"
        extra["ise_event"] = "CISE_Passed_Authentications"
    elif ISE_FAIL.search(line):
        action = "deny"
        extra["ise_event"] = "CISE_Failed_Attempts"
    username = ""
    user = USERNAME.search(line)
    if user:
        username = user.group("user").strip()
    src_ip = ""
    framed = FRAMED_IP.search(line)
    if framed:
        src_ip = framed.group("ip")
    device = DEVICE_IP.search(line)
    if device:
        extra["nas_ip"] = device.group("ip")
    return build_network_extraction_result(
        username=username,
        src_ip=src_ip,
        action=action,
        protocol="nac",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no nac entity extracted",
    )
