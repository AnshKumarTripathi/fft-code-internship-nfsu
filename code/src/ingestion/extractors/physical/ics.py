"""ICS / SCADA extraction (``ics``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.physical.common import (
    YEAR_POLICY_CARRY,
    build_physical_extraction_result,
    parse_json_object,
    parse_physical_json_timestamp,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

PLC = re.compile(r"\bplc=(?P<plc>\S+)", re.IGNORECASE)
TAG = re.compile(r"\btag=(?P<tag>\S+)", re.IGNORECASE)
VALUE = re.compile(r"\bvalue=(?P<value>\S+)", re.IGNORECASE)


def extract_ics(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract PLC as host (else tag as service) from ICS syslog or JSON."""
    obj = parse_json_object(line)
    if obj is not None:
        plc = str(obj.get("plc") or "").strip()
        tag = str(obj.get("tag") or "").strip()
        extra: dict[str, str] = {}
        if plc:
            extra["plc"] = plc
        if tag:
            extra["tag"] = tag
        if obj.get("value") not in {None, ""}:
            extra["value"] = str(obj.get("value"))
        event_timestamp = parse_physical_json_timestamp(obj)
        return build_physical_extraction_result(
            hostname=plc,
            service="" if plc else tag,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no ics JSON entity extracted",
        )
    extra = {}
    plc_match = PLC.search(line)
    plc = plc_match.group("plc").rstrip(",;") if plc_match else ""
    tag_match = TAG.search(line)
    tag = tag_match.group("tag").rstrip(",;") if tag_match else ""
    if plc:
        extra["plc"] = plc
    if tag:
        extra["tag"] = tag
    value = VALUE.search(line)
    if value:
        extra["value"] = value.group("value").rstrip(",;")
    hostname, program, pid = parse_syslog_fields(line)
    extra_ts = dict(extra)
    if program:
        extra_ts["program"] = program
    if pid:
        extra_ts["pid"] = pid
    if hostname:
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    else:
        event_timestamp, ts_ok = None, False
    return build_physical_extraction_result(
        hostname=plc or hostname,
        service="" if (plc or hostname) else tag,
        extra_fields=extra_ts,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no ics entity extracted",
    )
