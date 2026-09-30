"""Shared timestamp, entity, and raw_fields helpers for virtualization families."""

from __future__ import annotations

from src.ingestion.extractors.middleware.common import (
    BARE_IPV4,
    YEAR_POLICY_CARRY,
    assign_middleware_entity,
    build_middleware_extraction_result,
    canonical_src_ip,
    extract_syslog_middleware_line,
    json_username,
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_bracket_or_space_timestamp,
    parse_iso_datetime,
    parse_json_object,
    parse_middleware_json_timestamp,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.syslog_time import SyslogYearState

assign_virt_entity = assign_middleware_entity
build_virt_extraction_result = build_middleware_extraction_result
extract_syslog_virt_line = extract_syslog_middleware_line
parse_virt_json_timestamp = parse_middleware_json_timestamp

__all__ = [
    "BARE_IPV4",
    "YEAR_POLICY_CARRY",
    "SyslogYearState",
    "assign_virt_entity",
    "build_virt_extraction_result",
    "canonical_src_ip",
    "extract_syslog_virt_line",
    "json_username",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_bracket_or_space_timestamp",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
    "parse_virt_json_timestamp",
]
