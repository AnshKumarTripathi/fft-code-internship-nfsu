"""Cisco IOS router/switch syslog extraction (``network_device``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

SEC_ACL = re.compile(
    r"%SEC-6-IPACCESSLOGP:\s+list\s+\S+\s+(?P<action>denied|permitted)\s+"
    r"(?P<proto>\w+)\s+(?P<src>[0-9a-fA-F:.]+)\((?P<sport>\d+)\)\s+->\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\((?P<dport>\d+)\)",
    re.IGNORECASE,
)
LINEPROTO = re.compile(
    r"%LINEPROTO-\d+-UPDOWN: Line protocol on Interface (?P<iface>\S+), "
    r"changed state to (?P<state>up|down)",
    re.IGNORECASE,
)


def extract_network_device(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/IP from Cisco %LINEPROTO / %SEC-6-IPACCESSLOGP."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)

    acl = SEC_ACL.search(line)
    if acl:
        return build_network_extraction_result(
            src_ip=acl.group("src"),
            dst_ip=acl.group("dst"),
            src_port=acl.group("sport"),
            dst_port=acl.group("dport"),
            action=acl.group("action"),
            protocol=acl.group("proto").lower(),
            hostname=hostname,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no network_device entity extracted",
        )

    proto = LINEPROTO.search(line)
    if proto:
        extra["interface"] = proto.group("iface").rstrip(",")
        extra["link_state"] = proto.group("state").lower()
        return build_network_extraction_result(
            protocol="cisco_ios",
            hostname=hostname,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=ts_ok,
            no_match_reason="no network_device entity extracted",
        )

    return build_network_extraction_result(
        protocol="cisco_ios",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no network_device entity extracted",
    )
