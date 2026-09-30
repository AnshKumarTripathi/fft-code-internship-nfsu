"""Application Event Log extraction (``windows_application``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult


def extract_windows_application(line: str) -> ExtractionResult:
    """Extract host or provider-as-service from an Application Event Log line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    if record.provider:
        extra["service"] = record.provider
    return build_windows_extraction_result(
        record,
        event_class="application",
        extra_fields=extra,
        use_service=True,
        no_match_reason="no windows_application entity extracted",
    )
