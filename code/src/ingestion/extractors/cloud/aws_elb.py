"""AWS ALB access log extraction (``aws_elb``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ALB = re.compile(
    r"^(?P<type>h2|http|https|grpcs|wss)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<elb>\S+)\s+"
    r"(?P<client>\S+):(?P<cport>\d+)\s+",
    re.IGNORECASE,
)


def extract_aws_elb(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP from an ALB access-log line."""
    del default_year, year_state, year_policy
    match = ALB.match(line.strip())
    extra: dict[str, str] = {}
    src_ip = ""
    event_timestamp = None
    if match:
        extra["elb_type"] = match.group("type")
        extra["elb"] = match.group("elb")
        extra["src_port"] = match.group("cport")
        src_ip = match.group("client")
        event_timestamp = parse_iso_datetime(match.group("ts"))
    return build_cloud_extraction_result(
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no alb entity extracted",
    )
