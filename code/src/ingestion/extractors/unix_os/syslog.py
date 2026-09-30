"""General RFC3164 / RFC5424 syslog extraction (``linux_syslog``)."""

from __future__ import annotations

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_linux_syslog(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/program from a generic syslog line."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    return build_unix_extraction_result(
        hostname=hostname,
        program=program,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_syslog entity extracted",
    )
