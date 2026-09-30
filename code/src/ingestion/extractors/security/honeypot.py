"""Cowrie JSON honeypot extraction (``honeypot``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_honeypot(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src IP / username from cowrie JSON. No syslog year-carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no honeypot JSON object",
        )
    extra: dict[str, str] = {}
    eventid = str(obj.get("eventid") or "")
    if eventid:
        extra["eventid"] = eventid
    session = str(obj.get("session") or "")
    if session:
        extra["session"] = session
    message = str(obj.get("message") or "")
    if message:
        extra["message"] = message
    action = eventid.rsplit(".", 1)[-1] if eventid else str(obj.get("action") or "")
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        username=str(obj.get("username") or obj.get("user") or ""),
        src_ip=str(obj.get("src_ip") or ""),
        hostname=str(obj.get("sensor") or obj.get("hostname") or ""),
        action=action,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no honeypot entity extracted",
    )
