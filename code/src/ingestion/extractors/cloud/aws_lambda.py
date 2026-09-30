"""AWS Lambda CloudWatch REPORT/START extraction (``aws_lambda``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

REQUEST = re.compile(r"RequestId:\s+(?P<rid>\S+)", re.IGNORECASE)
DURATION = re.compile(r"Duration:\s+(?P<ms>[\d.]+)\s+ms", re.IGNORECASE)
FUNCTION = re.compile(r"FunctionName[=:](?P<name>\S+)", re.IGNORECASE)
ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+")


def extract_aws_lambda(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract RequestId / function as the service entity from Lambda CW lines."""
    del default_year, year_state, year_policy
    extra: dict[str, str] = {}
    request = REQUEST.search(line)
    if request:
        extra["request_id"] = request.group("rid")
    duration = DURATION.search(line)
    if duration:
        extra["duration_ms"] = duration.group("ms")
    function = FUNCTION.search(line)
    service = function.group("name") if function else extra.get("request_id", "")
    iso = ISO_PREFIX.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    ts_ok = event_timestamp is not None
    if event_timestamp is None and service:
        ts_ok = False
    return build_cloud_extraction_result(
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok if service else False,
        no_match_reason="no lambda entity extracted",
    )
