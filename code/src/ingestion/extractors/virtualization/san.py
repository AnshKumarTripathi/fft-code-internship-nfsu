"""Storage array / SAN extraction (``san``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    build_virt_extraction_result,
    extract_syslog_virt_line,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

LUN = re.compile(r"\bLUN\s+(?P<lun>\S+)", re.IGNORECASE)
VOLUME = re.compile(r"\bvolume\s+(?P<vol>\S+)", re.IGNORECASE)


def extract_san(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from array syslog with LUN/volume."""
    extra: dict[str, str] = {}
    lun = LUN.search(line)
    if lun:
        extra["lun"] = lun.group("lun").rstrip(",")
    volume = VOLUME.search(line)
    if volume:
        extra["volume"] = volume.group("vol").rstrip(",")
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_virt_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            extra_fields=extra,
            no_match_reason="no san entity extracted",
        )
    return build_virt_extraction_result(
        hostname="san",
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no san entity extracted",
    )
