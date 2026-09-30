"""Contact-center / IVR extraction (``ivr``)."""

from __future__ import annotations

from src.ingestion.extractors.telephony.common import (
    YEAR_POLICY_CARRY,
    build_telephony_extraction_result,
    parse_json_object,
    parse_telephony_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_ivr(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract agent as user, else menu/call_id as service."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no ivr JSON entity extracted",
        )
    agent = str(obj.get("agent") or "").strip()
    menu = str(obj.get("menu") or "").strip()
    call_id = str(obj.get("call_id") or "").strip()
    extra: dict[str, str] = {}
    if call_id:
        extra["call_id"] = call_id
    if menu:
        extra["menu"] = menu
    event_timestamp = parse_telephony_json_timestamp(obj)
    return build_telephony_extraction_result(
        username=agent,
        service="" if agent else (menu or call_id),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no ivr JSON entity extracted",
    )
