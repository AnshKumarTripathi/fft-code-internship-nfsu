"""Building-management extraction (``bms``) — HVAC / alarm panel."""

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

PANEL = re.compile(r"\bpanel=(?P<panel>\S+)", re.IGNORECASE)
ZONE = re.compile(r"\bzone=(?P<zone>\S+)", re.IGNORECASE)
ALARM = re.compile(r"\balarm=(?P<alarm>\S+)", re.IGNORECASE)
SETPOINT = re.compile(r"\bsetpoint=(?P<setpoint>\S+)", re.IGNORECASE)


def extract_bms(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract panel as host from BMS syslog or JSON."""
    obj = parse_json_object(line)
    if obj is not None:
        panel = str(obj.get("panel") or obj.get("zone") or "").strip()
        extra: dict[str, str] = {}
        for key in ("panel", "zone", "alarm", "hvac", "setpoint"):
            value = obj.get(key)
            if value not in {None, ""}:
                extra[key] = str(value)
        event_timestamp = parse_physical_json_timestamp(obj)
        return build_physical_extraction_result(
            hostname=panel,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no bms JSON entity extracted",
        )
    extra = {}
    panel_match = PANEL.search(line)
    panel = panel_match.group("panel").rstrip(",;") if panel_match else ""
    if panel:
        extra["panel"] = panel
    zone = ZONE.search(line)
    if zone:
        extra["zone"] = zone.group("zone").rstrip(",;")
    alarm = ALARM.search(line)
    if alarm:
        extra["alarm"] = alarm.group("alarm").rstrip(",;")
    setpoint = SETPOINT.search(line)
    if setpoint:
        extra["setpoint"] = setpoint.group("setpoint").rstrip(",;")
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
        hostname=panel or hostname,
        extra_fields=extra_ts,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no bms entity extracted",
    )
