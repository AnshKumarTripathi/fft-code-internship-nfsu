"""FRR bgpd neighbor extraction (``bgp``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ADJCHANGE = re.compile(
    r"%ADJCHANGE:\s+neighbor\s+(?P<ip>[0-9a-fA-F:.]+)"
    r"(?:\((?P<name>[^)]+)\))?"
    r".*?\b(?P<state>Up|Down)\b",
    re.IGNORECASE,
)


def extract_bgp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from FRR bgpd neighbor up/down lines."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    adj = ADJCHANGE.search(line)
    dst_ip = ""
    if adj:
        dst_ip = adj.group("ip")
        extra["neighbor_state"] = adj.group("state").lower()
        if adj.group("name"):
            extra["neighbor_name"] = adj.group("name")
    return build_network_extraction_result(
        dst_ip=dst_ip,
        protocol="bgp",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no bgp entity extracted",
    )
