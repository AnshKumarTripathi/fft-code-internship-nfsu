"""Kafka broker / consumer-group extraction (``kafka``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.middleware.common import (
    YEAR_POLICY_CARRY,
    build_middleware_extraction_result,
    extract_syslog_middleware_line,
    parse_bracket_or_space_timestamp,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

GROUP = re.compile(
    r"\bgroup(?:\s+id)?[=:\s]+(?P<group>[\w.-]+)",
    re.IGNORECASE,
)
BROKER = re.compile(r"\[KafkaServer id=(?P<id>\d+)\]", re.IGNORECASE)


def extract_kafka(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host or consumer-group from Kafka server/controller logs."""
    hostname, program, _pid = parse_syslog_fields(line)
    group_match = GROUP.search(line)
    group = group_match.group("group") if group_match else ""
    extra: dict[str, str] = {}
    if group:
        extra["group"] = group
    broker = BROKER.search(line)
    if broker:
        extra["broker_id"] = broker.group("id")
    service = group or "kafka"
    if hostname:
        return extract_syslog_middleware_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            service=service,
            extra_fields=extra,
            no_match_reason="no kafka entity extracted",
        )
    event_timestamp = parse_bracket_or_space_timestamp(line)
    if program:
        extra["program"] = program
    return build_middleware_extraction_result(
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no kafka entity extracted",
    )
