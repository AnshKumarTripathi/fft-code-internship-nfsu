"""Video-conferencing call-log extraction (``video_conf``)."""

from __future__ import annotations

from src.ingestion.extractors.telephony.common import (
    YEAR_POLICY_CARRY,
    build_telephony_extraction_result,
    canonical_src_ip,
    parse_json_object,
    parse_telephony_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_video_conf(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract organizer as user (else IP) from meeting join JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no video_conf JSON entity extracted",
        )
    username = str(obj.get("organizer") or "").strip()
    src_ip = canonical_src_ip(str(obj.get("ip") or obj.get("src_ip") or ""))
    extra: dict[str, str] = {}
    meeting_id = str(obj.get("meeting_id") or "").strip()
    if meeting_id:
        extra["meeting_id"] = meeting_id
    if "join" in obj and obj.get("join") not in {None, ""}:
        extra["join"] = str(obj.get("join")).lower()
    event_timestamp = parse_telephony_json_timestamp(obj)
    return build_telephony_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no video_conf JSON entity extracted",
    )
