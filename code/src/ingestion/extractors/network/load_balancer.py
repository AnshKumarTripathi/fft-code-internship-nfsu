"""HAProxy HTTP log extraction (``load_balancer``)."""

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
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\s+"
    r"\[(?P<haproxy_ts>[^\]]+)\]\s+"
    r"(?P<frontend>\S+)\s+(?P<backend>[^/\s]+)/(?P<server>\S+)"
)
STATUS = re.compile(r"\s(?P<status>\d{3})\s+(?P<bytes>\d+)\s")


def extract_load_balancer(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP from HAProxy HTTP logs (syslog-shaped)."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    client = CLIENT.search(line)
    src_ip = ""
    src_port = ""
    if client:
        src_ip = client.group("ip")
        src_port = client.group("port")
        extra["frontend"] = client.group("frontend")
        extra["backend"] = client.group("backend")
        extra["server"] = client.group("server")
    status = STATUS.search(line)
    if status:
        extra["status_code"] = status.group("status")
        extra["bytes"] = status.group("bytes")
    return build_network_extraction_result(
        src_ip=src_ip,
        src_port=src_port,
        protocol="haproxy",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no load_balancer entity extracted",
    )
