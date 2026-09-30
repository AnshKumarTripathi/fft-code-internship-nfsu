"""AWS RDS PostgreSQL log extraction (``aws_rds``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

RDS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+UTC:"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\((?P<port>\d+)\):"
    r"(?P<user>[^@]+)@(?P<db>[^:]+):\[(?P<pid>\d+)\]:"
    r"(?P<level>\w+):"
)


def extract_aws_rds(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from an RDS PostgreSQL log line."""
    del default_year, year_state, year_policy
    match = RDS.search(line.strip())
    extra: dict[str, str] = {}
    username = ""
    src_ip = ""
    service = ""
    event_timestamp = None
    if match:
        username = match.group("user")
        src_ip = match.group("ip")
        service = match.group("db")
        extra["pid"] = match.group("pid")
        extra["level"] = match.group("level")
        extra["src_port"] = match.group("port")
        extra["database"] = service
        event_timestamp = parse_iso_datetime(match.group("ts").replace(" ", "T") + "Z")
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no rds entity extracted",
    )
