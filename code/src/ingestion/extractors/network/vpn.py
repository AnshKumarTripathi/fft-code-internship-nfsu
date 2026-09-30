"""OpenVPN concentrator extraction (``vpn``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

TLS_AUTH = re.compile(
    r"TLS: Username/Password authentication (?P<result>succeeded|failed) "
    r"for username '(?P<user>[^']+)'",
    re.IGNORECASE,
)
CLIENT_IP = re.compile(
    r"(?:^|:\s)(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)",
)
USER_SLASH_IP = re.compile(
    r"(?P<user>[A-Za-z0-9._-]+)/(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)"
)
PEER_INIT = re.compile(r"Peer Connection Initiated", re.IGNORECASE)


def extract_vpn(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/IP from OpenVPN TLS auth and session lines."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    username = ""
    src_ip = ""
    src_port = ""
    action = ""

    tls = TLS_AUTH.search(line)
    if tls:
        username = tls.group("user")
        action = "allow" if tls.group("result").lower() == "succeeded" else "deny"
    slash = USER_SLASH_IP.search(line)
    if slash:
        if not username:
            username = slash.group("user")
        src_ip = slash.group("ip")
        src_port = slash.group("port")
    if not src_ip:
        client = CLIENT_IP.search(line)
        if client:
            src_ip = client.group("ip")
            src_port = client.group("port")
    if PEER_INIT.search(line) and not action:
        action = "allow"

    return build_network_extraction_result(
        username=username,
        src_ip=src_ip,
        src_port=src_port,
        action=action,
        protocol="openvpn",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no vpn entity extracted",
    )
