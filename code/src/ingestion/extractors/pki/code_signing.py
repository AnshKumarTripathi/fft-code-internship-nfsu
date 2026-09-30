"""Code-signing extraction (``code_signing``)."""

from __future__ import annotations

from src.ingestion.extractors.pki.common import (
    YEAR_POLICY_CARRY,
    build_pki_extraction_result,
    normalize_auth_result,
    parse_json_object,
    parse_pki_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_code_signing(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract signer as user (else hash as service) from signing JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no code_signing JSON entity extracted",
        )
    signer = str(obj.get("signer") or "").strip()
    digest = str(obj.get("hash") or "").strip()
    extra: dict[str, str] = {}
    if digest:
        extra["hash"] = digest
    result = str(obj.get("result") or "").strip()
    if result:
        extra["auth_result"] = normalize_auth_result(result)
    event_timestamp = parse_pki_json_timestamp(obj)
    return build_pki_extraction_result(
        username=signer,
        service="" if signer else digest,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no code_signing JSON entity extracted",
    )
