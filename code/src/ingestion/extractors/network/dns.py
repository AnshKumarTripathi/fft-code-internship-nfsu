"""BIND query-log extraction (``dns``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

CLIENT = re.compile(
    r"client\s+(?:@\S+\s+)?(?P<ip>[0-9a-fA-F:.]+)#(?P<port>\d+)",
    re.IGNORECASE,
)
QUERY = re.compile(
    r"query:\s+(?P<qname>\S+)\s+IN\s+(?P<qtype>\S+)",
    re.IGNORECASE,
)
NXDOMAIN = re.compile(r"\bNXDOMAIN\b", re.IGNORECASE)


def extract_dns(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP/host from BIND named query logs."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    src_ip = ""
    src_port = ""
    client = CLIENT.search(line)
    if client:
        src_ip = client.group("ip")
        src_port = client.group("port")
    query = QUERY.search(line)
    if query:
        extra["qname"] = query.group("qname")
        extra["qtype"] = query.group("qtype")
    if NXDOMAIN.search(line):
        extra["rcode"] = "NXDOMAIN"
    return build_network_extraction_result(
        src_ip=src_ip,
        src_port=src_port,
        protocol="dns",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no dns entity extracted",
    )
