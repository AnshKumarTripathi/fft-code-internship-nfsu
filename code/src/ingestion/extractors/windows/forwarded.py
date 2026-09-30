"""Forwarded Events extraction (``windows_forwarded``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult


def extract_windows_forwarded(line: str) -> ExtractionResult:
    """Extract the inner event; store inner channel as forwarded_channel."""
    record = parse_windows_record(line)
    inner = record.forwarded_channel or record.channel
    if inner.lower() in {"", "forwardedevents"}:
        inner = record.fields.get("ForwardedChannel") or record.channel
    if inner.lower() == "forwardedevents":
        inner = ""
    if inner:
        record.forwarded_channel = inner
    return build_windows_extraction_result(
        record,
        event_class="forwarded",
        extra_fields={"forwarded_channel": record.forwarded_channel} if record.forwarded_channel else None,
        no_match_reason="no windows_forwarded entity extracted",
    )
