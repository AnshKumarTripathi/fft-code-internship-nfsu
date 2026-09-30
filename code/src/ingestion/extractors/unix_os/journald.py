"""journald / systemd unit extraction (``linux_journald``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_iso_datetime,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

UNIT_FIELD = re.compile(r"\b_SYSTEMD_UNIT=(?P<unit>\S+)")
COMM_FIELD = re.compile(r"\b_COMM=(?P<comm>\S+)")
STARTED = re.compile(r"Started (?P<unit>\S+?\.service)", re.IGNORECASE)


def extract_linux_journald(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/unit from journalctl short or export text."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    if not ts_ok:
        # journalctl -o short-iso prefixes ``2024-01-15T10:00:01+00:00 …``
        first_token = line.split(None, 1)[0] if line.strip() else ""
        parsed = parse_iso_datetime(first_token) or parse_iso_datetime(line[:40])
        if parsed is not None:
            event_timestamp, ts_ok = parsed, True
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    unit = ""
    unit_match = UNIT_FIELD.search(line)
    if unit_match:
        unit = unit_match.group("unit").strip('"')
    if not unit:
        started = STARTED.search(line)
        if started:
            unit = started.group("unit")
    comm = COMM_FIELD.search(line)
    if comm and not program:
        program = comm.group("comm").strip('"')
    if unit:
        extra["unit"] = unit
    return build_unix_extraction_result(
        unit=unit,
        hostname=hostname,
        program=program or "systemd",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_journald entity extracted",
    )
