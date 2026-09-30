"""nfdump text flow extraction (``netflow``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

FLOW = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<duration>\S+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<src>[0-9a-fA-F:.]+):(?P<sport>\d+)\s+->\s+"
    r"(?P<dst>[0-9a-fA-F:.]+):(?P<dport>\d+)"
)


def extract_netflow(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst from nfdump text. ISO date, no syslog year-carry."""
    del default_year, year_state, year_policy
    match = FLOW.match(line.strip())
    if match is None:
        return build_network_extraction_result(
            protocol="netflow",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no netflow entity extracted",
        )
    extra = {"duration": match.group("duration")}
    event_timestamp = parse_iso_datetime(match.group("ts"))
    return build_network_extraction_result(
        src_ip=match.group("src"),
        dst_ip=match.group("dst"),
        src_port=match.group("sport"),
        dst_port=match.group("dport"),
        protocol=match.group("proto").lower(),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no netflow entity extracted",
    )
