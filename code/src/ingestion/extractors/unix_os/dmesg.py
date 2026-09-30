"""dmesg ring-buffer extraction (``linux_dmesg``)."""

from __future__ import annotations

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    mtime_year_timestamp,
    parse_dmesg_t_timestamp,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_linux_dmesg(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract kernel messages from dmesg -T / uptime-bracket text.

    Does not apply syslog year-carry. Raw ``[seconds.nsec]`` lines use the
    source file mtime year as a last-resort timestamp.
    """
    del year_state, year_policy
    event_timestamp, ts_ok = parse_dmesg_t_timestamp(line)
    extra: dict[str, str] = {"program": "kernel"}
    if not ts_ok:
        iso = parse_iso_datetime(line[:32])
        if iso is not None:
            event_timestamp, ts_ok = iso, True
    if not ts_ok:
        event_timestamp = mtime_year_timestamp(default_year)
        extra["timestamp_from_file_mtime_year"] = "true"
        ts_ok = True
    return build_unix_extraction_result(
        hostname="",
        program="kernel",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_dmesg entity extracted",
    )
