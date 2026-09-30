"""Certificate-transparency log extraction (``ct_log``)."""

from __future__ import annotations

from src.ingestion.extractors.pki.common import (
    YEAR_POLICY_CARRY,
    build_pki_extraction_result,
    parse_json_object,
    parse_pki_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_ct_log(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract domain as host from CT seen/misissue JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no ct_log JSON entity extracted",
        )
    domain = str(obj.get("domain") or "").strip()
    extra: dict[str, str] = {}
    issuer = str(obj.get("issuer") or "").strip()
    if issuer:
        extra["issuer"] = issuer
    event = str(obj.get("event") or "").strip().lower()
    if event:
        extra["event"] = event
    event_timestamp = parse_pki_json_timestamp(obj)
    return build_pki_extraction_result(
        hostname=domain,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no ct_log JSON entity extracted",
    )
