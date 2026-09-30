"""Feature-flag / config-change JSON audit extraction (``feature_flag``)."""

from __future__ import annotations

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_application_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_feature_flag(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/service and flag action from JSON audit lines."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no feature_flag JSON object",
        )
    extra: dict[str, str] = {}
    flag = str(obj.get("flag") or "")
    if flag:
        extra["flag"] = flag
    action = str(obj.get("action") or "")
    if action:
        extra["action"] = action
    service = str(obj.get("service") or "")
    event_timestamp = parse_application_json_timestamp(obj)
    return build_application_extraction_result(
        username=str(obj.get("user") or obj.get("username") or ""),
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no feature_flag entity extracted",
    )
