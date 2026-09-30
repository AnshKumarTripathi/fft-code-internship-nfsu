"""ISC dhcpd lease extraction (``dhcp``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

MESSAGE = re.compile(
    r"\b(?P<msg>DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK)\b"
)
LEASE_IP = re.compile(
    r"\b(?:on|for)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
MAC = re.compile(
    r"\b(?:from|to)\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b",
    re.IGNORECASE,
)


def extract_dhcp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract lease IP / host from ISC dhcpd syslog; MAC stays in fields."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    msg = MESSAGE.search(line)
    if msg:
        extra["dhcp_message"] = msg.group("msg")
    src_ip = ""
    lease = LEASE_IP.search(line)
    if lease:
        src_ip = lease.group("ip")
    mac = MAC.search(line)
    if mac:
        extra["mac"] = mac.group("mac").lower()
    action = ""
    if msg:
        token = msg.group("msg")
        if token == "DHCPNAK":
            action = "deny"
        elif token in {"DHCPACK", "DHCPOFFER"}:
            action = "allow"
    return build_network_extraction_result(
        src_ip=src_ip,
        action=action,
        protocol="dhcp",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no dhcp entity extracted",
    )
