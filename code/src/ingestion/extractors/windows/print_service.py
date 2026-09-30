"""Print Service extraction (``windows_print``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

PRINT_JOB_ID = 307
PRINT_RENDER_ID = 805

PARSED_EVENT_IDS = frozenset({PRINT_JOB_ID, PRINT_RENDER_ID})


def extract_windows_print(line: str) -> ExtractionResult:
    """Extract user/host from a Print Service line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    printer = record.fields.get("Param1") or record.fields.get("PrinterName") or ""
    if printer:
        extra["printer"] = printer
    return build_windows_extraction_result(
        record,
        event_class="print",
        extra_fields=extra,
        no_match_reason="no windows_print entity extracted",
    )
