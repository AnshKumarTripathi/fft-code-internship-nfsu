"""ESB transaction extraction (``esb``)."""

from __future__ import annotations

from src.ingestion.extractors.middleware.common import (
    YEAR_POLICY_CARRY,
    build_middleware_extraction_result,
    json_username,
    parse_json_object,
    parse_middleware_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_esb(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/service from generic ESB JSON ``tx_id`` / ``route``."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no esb JSON entity extracted",
        )
    username = json_username(obj)
    route = str(obj.get("route") or "")
    service = str(obj.get("service") or route or "esb")
    extra: dict[str, str] = {}
    tx_id = str(obj.get("tx_id") or obj.get("txId") or "")
    if tx_id:
        extra["tx_id"] = tx_id
    if route:
        extra["route"] = route
    src_ip = str(obj.get("src_ip") or obj.get("ip") or obj.get("client_ip") or "")
    event_timestamp = parse_middleware_json_timestamp(obj)
    return build_middleware_extraction_result(
        username=username,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no esb JSON entity extracted",
    )
