"""Squid combined access-log extraction (``proxy``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_epoch_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

SQUID_LINE = re.compile(
    r"^(?P<epoch>\d+(?:\.\d+)?)\s+"
    r"(?P<elapsed>\d+)\s+"
    r"(?P<client>\S+)\s+"
    r"(?P<hier>\S+)/(?P<code>\d+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<peer>\S+)"
)
PEER_IP = re.compile(r"/(?P<ip>[0-9a-fA-F:.]+)$")


def extract_proxy(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP/user from Squid combined logs. Epoch, no year-carry."""
    del default_year, year_state, year_policy
    match = SQUID_LINE.match(line.strip())
    if match is None:
        return build_network_extraction_result(
            protocol="squid",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no proxy entity extracted",
        )
    extra = {
        "elapsed_ms": match.group("elapsed"),
        "status_code": match.group("code"),
        "method": match.group("method"),
        "url": match.group("url"),
        "hier_code": match.group("hier"),
    }
    peer = match.group("peer")
    dst_ip = ""
    peer_ip = PEER_IP.search(peer)
    if peer_ip and peer_ip.group("ip") not in {"-", ""}:
        dst_ip = peer_ip.group("ip")
    hier = match.group("hier").upper()
    action = "deny" if "DENIED" in hier else "allow"
    event_timestamp = parse_epoch_timestamp(match.group("epoch"))
    return build_network_extraction_result(
        username=match.group("user"),
        src_ip=match.group("client"),
        dst_ip=dst_ip,
        action=action,
        protocol="squid",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no proxy entity extracted",
    )
