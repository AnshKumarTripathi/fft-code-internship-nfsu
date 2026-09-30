"""Helm release / deploy stdout extraction (``helm``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    parse_iso_datetime,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

RELEASE = re.compile(r'Release "(?P<name>[^"]+)"')
USER = re.compile(r"\buser(?:name)?[=:](?P<user>\S+)", re.IGNORECASE)
ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\b")


def extract_helm(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract release name / user from a Helm stdout line."""
    hostname, _program, _pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    release = RELEASE.search(line)
    service = release.group("name") if release else "helm"
    if release:
        extra["release"] = release.group("name")
    user_match = USER.search(line)
    username = user_match.group("user") if user_match else ""
    event_timestamp = None
    ts_ok = False
    if hostname:
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if event_timestamp is None:
        iso = ISO.search(line)
        if iso:
            event_timestamp = parse_iso_datetime(iso.group(1))
            ts_ok = event_timestamp is not None
    return build_container_extraction_result(
        username=username,
        hostname=hostname,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no helm entity extracted",
        prefer_service=not (username or hostname),
    )
