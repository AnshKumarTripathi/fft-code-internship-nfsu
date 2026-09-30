"""Group Policy operational extraction (``windows_gpo``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Parsed subset of the 8001–8016 operational range.
GPO_APPLY_START_ID = 8001
GPO_APPLY_SUCCESS_ID = 8004
GPO_APPLY_COMPLETE_ID = 8016

PARSED_EVENT_IDS = frozenset({GPO_APPLY_START_ID, GPO_APPLY_SUCCESS_ID, GPO_APPLY_COMPLETE_ID})


def extract_windows_gpo(line: str) -> ExtractionResult:
    """Extract host/user from a Group Policy operational line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    gpo_name = record.fields.get("GPOName") or record.fields.get("PolicyName") or ""
    if gpo_name:
        extra["gpo_name"] = gpo_name
    return build_windows_extraction_result(
        record,
        event_class="gpo",
        extra_fields=extra,
        no_match_reason="no windows_gpo entity extracted",
    )
