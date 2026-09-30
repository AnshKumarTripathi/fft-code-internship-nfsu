"""Shared timestamp, entity, and raw_fields helpers for physical / IoT families."""

from __future__ import annotations

from src.ingestion.extractors.identity.common import normalize_auth_result
from src.ingestion.extractors.middleware.common import (
    YEAR_POLICY_CARRY,
    assign_middleware_entity,
    build_middleware_extraction_result,
    canonical_src_ip,
    extract_syslog_middleware_line,
    json_username,
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_iso_datetime,
    parse_json_object,
    parse_middleware_json_timestamp,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.syslog_time import SyslogYearState

assign_physical_entity = assign_middleware_entity
build_physical_extraction_result = build_middleware_extraction_result
extract_syslog_physical_line = extract_syslog_middleware_line
parse_physical_json_timestamp = parse_middleware_json_timestamp

__all__ = [
    "YEAR_POLICY_CARRY",
    "SyslogYearState",
    "assign_physical_entity",
    "build_physical_extraction_result",
    "canonical_src_ip",
    "extract_syslog_physical_line",
    "json_username",
    "looks_like_ip",
    "nested_str",
    "normalize_auth_result",
    "normalize_username",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_physical_json_timestamp",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
]
