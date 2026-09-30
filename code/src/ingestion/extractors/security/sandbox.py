"""Cuckoo-like sandbox JSON extraction (``sandbox``)."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    nested_str,
    parse_iso_datetime,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_sandbox(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host or file hash (as service) from Cuckoo-like JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no sandbox JSON object",
        )
    extra: dict[str, str] = {}
    sha256 = nested_str(obj, "target", "file", "sha256") or str(obj.get("sha256") or "")
    if sha256:
        extra["sha256"] = sha256
    malscore = obj.get("malscore")
    if malscore is not None:
        extra["malscore"] = str(malscore)
    hostname = nested_str(obj, "info", "machine", "name") or str(
        obj.get("host") or obj.get("hostname") or ""
    )
    event_timestamp = parse_security_json_timestamp(obj)
    if event_timestamp is None:
        started = nested_str(obj, "info", "started")
        event_timestamp = parse_iso_datetime(started) if started else None
    return build_security_extraction_result(
        hostname=hostname,
        service=sha256,
        action=str(obj.get("action") or ""),
        severity=str(malscore) if malscore is not None else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no sandbox entity extracted",
    )
