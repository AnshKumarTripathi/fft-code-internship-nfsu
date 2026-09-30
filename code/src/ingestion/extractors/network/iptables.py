"""Linux iptables / UFW / nftables-style syslog (``iptables``, Phase 85).

Locked UFW dialect::

    Jan 15 10:00:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=… SRC=10.0.0.1 DST=10.0.0.2 LEN=60 … PROTO=TCP SPT=443 DPT=22

pfSense ``filterlog`` stays ``firewall``. nftables stretch: same ``SRC=``/``DST=`` key=value shape.
"""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_UFW_TAG = re.compile(r"\[UFW\s+(?P<action>BLOCK|ALLOW|AUDIT|DENY)\]", re.IGNORECASE)
_SRC = re.compile(r"\bSRC=(?P<ip>\S+)")
_DST = re.compile(r"\bDST=(?P<ip>\S+)")
_PROTO = re.compile(r"\bPROTO=(?P<proto>\S+)")
_SPT = re.compile(r"\bSPT=(?P<port>\d+)")
_DPT = re.compile(r"\bDPT=(?P<port>\d+)")
_IN = re.compile(r"\bIN=(?P<iface>\S*)")
_OUT = re.compile(r"\bOUT=(?P<iface>\S*)")
# Classic iptables LOG without UFW tag still has SRC= DST= and IN=/OUT=/PROTO=
_IPTABLES_KEYS = re.compile(r"\bSRC=\S+.*\bDST=\S+")
_FILTERLOG = re.compile(r"\bfilterlog\[", re.IGNORECASE)
_NFT = re.compile(r"\bnft(?:ables)?\b", re.IGNORECASE)


def looks_like_iptables(line: str) -> bool:
    """True for UFW / iptables LOG / simple nftables syslog — not filterlog."""
    stripped = line.strip()
    if not stripped or _FILTERLOG.search(stripped):
        return False
    if _UFW_TAG.search(stripped):
        return True
    if _IPTABLES_KEYS.search(stripped) and (
        _IN.search(stripped) or _OUT.search(stripped) or _PROTO.search(stripped)
    ):
        return True
    if _NFT.search(stripped) and _IPTABLES_KEYS.search(stripped):
        return True
    return False


def _kv(pattern: re.Pattern[str], line: str, group: str) -> str:
    match = pattern.search(line)
    return match.group(group) if match else ""


def extract_iptables(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst IP, ports, and allow/deny from UFW / iptables syslog."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    extra["dialect"] = "iptables"

    ufw = _UFW_TAG.search(line)
    action = ""
    if ufw:
        action = ufw.group("action")
        extra["ufw_action"] = action
    elif re.search(r"\bDROP\b|\bREJECT\b|\bDENY\b", line, re.IGNORECASE):
        action = "block"
    elif re.search(r"\bACCEPT\b|\bALLOW\b", line, re.IGNORECASE):
        action = "allow"

    src = _kv(_SRC, line, "ip")
    dst = _kv(_DST, line, "ip")
    proto = _kv(_PROTO, line, "proto")
    spt = _kv(_SPT, line, "port")
    dpt = _kv(_DPT, line, "port")
    iface_in = _kv(_IN, line, "iface")
    iface_out = _kv(_OUT, line, "iface")
    if iface_in:
        extra["in"] = iface_in
    if iface_out:
        extra["out"] = iface_out
    if _NFT.search(line):
        extra["dialect"] = "nftables"

    return build_network_extraction_result(
        src_ip=src,
        dst_ip=dst,
        src_port=spt,
        dst_port=dpt,
        action=action,
        protocol=proto or "iptables",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no iptables entity extracted",
        prefer_ip_entity=True,
    )


__all__ = [
    "extract_iptables",
    "looks_like_iptables",
]
