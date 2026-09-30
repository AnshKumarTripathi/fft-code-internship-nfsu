"""hostapd wireless AP extraction (``wireless``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

MAC = re.compile(r"\b((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b")
CONNECTED = re.compile(r"AP-STA-CONNECTED", re.IGNORECASE)
DISCONNECTED = re.compile(r"AP-STA-DISCONNECTED", re.IGNORECASE)
DEAUTH = re.compile(r"deauthenticated|disassociated", re.IGNORECASE)
ASSOC = re.compile(r"associated", re.IGNORECASE)
STA_IP = re.compile(
    r"AP-STA-CONNECTED\s+(?:[0-9a-fA-F:]+)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
IFACE = re.compile(r":\s+(?P<iface>wlan\d+|ath\d+|wifi\d+):", re.IGNORECASE)


def extract_wireless(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/IP from hostapd association and deauth lines."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    mac = MAC.search(line)
    if mac:
        extra["mac"] = mac.group(1).lower()
    iface = IFACE.search(line)
    if iface:
        extra["interface"] = iface.group("iface")
    action = ""
    if DISCONNECTED.search(line) or DEAUTH.search(line):
        action = "deny"
    elif CONNECTED.search(line) or ASSOC.search(line):
        action = "allow"
    src_ip = ""
    sta_ip = STA_IP.search(line)
    if sta_ip:
        src_ip = sta_ip.group("ip")
    return build_network_extraction_result(
        src_ip=src_ip,
        action=action,
        protocol="hostapd",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no wireless entity extracted",
    )
