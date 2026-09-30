"""RabbitMQ connection / channel extraction (``rabbitmq``)."""

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

USER = re.compile(r"user '(?P<user>[^']+)'", re.IGNORECASE)
CONN_IP = re.compile(
    r"connection <[^>]+> \((?P<ip>\d{1,3}(?:\.\d{1,3}){3}):",
    re.IGNORECASE,
)
CHANNEL = re.compile(r"\bchannel (?P<ch><[^>]+>|\d+)", re.IGNORECASE)


def extract_rabbitmq(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/ip/host from RabbitMQ connection and channel lines."""
    user_match = USER.search(line)
    username = user_match.group("user") if user_match else ""
    ip_match = CONN_IP.search(line)
    src_ip = ip_match.group("ip") if ip_match else ""
    extra: dict[str, str] = {}
    channel = CHANNEL.search(line)
    if channel:
        extra["channel"] = channel.group("ch")
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_middleware_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            src_ip=src_ip,
            extra_fields=extra,
            no_match_reason="no rabbitmq entity extracted",
        )
    event_timestamp = parse_bracket_or_space_timestamp(line)
    return build_middleware_extraction_result(
        username=username,
        src_ip=src_ip,
        service="rabbitmq" if not (username or src_ip) else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no rabbitmq entity extracted",
    )
