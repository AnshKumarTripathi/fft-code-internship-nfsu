"""Backup software extraction (``backup``) — Veeam, Commvault, Bacula."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    build_virt_extraction_result,
    extract_syslog_virt_line,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

USER = re.compile(r"\buser[=:\s]+(?P<user>[\w.-]+)", re.IGNORECASE)
HOST = re.compile(r"\b(?:host|client)[=:\s]+(?P<host>[\w.-]+)", re.IGNORECASE)
JOB = re.compile(r"\bJob(?:Id)?\s+(?P<job>'[^']+'|\S+)", re.IGNORECASE)
ISO_LEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
PRODUCT = re.compile(r"\b(?P<product>Veeam|Commvault|bacula(?:-dir)?)\b", re.IGNORECASE)


def extract_backup(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from backup job-finished lines."""
    user_match = USER.search(line)
    username = normalize_username(user_match.group("user") if user_match else "")
    extra: dict[str, str] = {}
    product = PRODUCT.search(line)
    if product:
        extra["product"] = product.group("product").lower()
    job = JOB.search(line)
    if job:
        extra["job"] = job.group("job").strip("'")
    hostname, _program, _pid = parse_syslog_fields(line)
    host_match = HOST.search(line)
    if host_match:
        hostname = hostname or host_match.group("host")
    if hostname and re.match(
        r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s",
        line.strip(),
    ):
        return extract_syslog_virt_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no backup entity extracted",
        )
    iso = ISO_LEAD.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    return build_virt_extraction_result(
        username=username,
        hostname=hostname or extra.get("product") or "backup",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no backup entity extracted",
    )
