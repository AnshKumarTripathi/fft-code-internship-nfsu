"""CCTV metadata / event extraction (``cctv``)."""

from __future__ import annotations

from src.ingestion.extractors.physical.common import (
    YEAR_POLICY_CARRY,
    build_physical_extraction_result,
    parse_json_object,
    parse_physical_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_cctv(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract camera_id as host from CCTV JSON events."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no cctv JSON entity extracted",
        )
    camera = str(obj.get("camera_id") or obj.get("camera") or "").strip()
    extra: dict[str, str] = {}
    event = str(obj.get("event") or "").strip().lower()
    if event:
        extra["event"] = event
    event_timestamp = parse_physical_json_timestamp(obj)
    return build_physical_extraction_result(
        hostname=camera,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cctv JSON entity extracted",
    )
