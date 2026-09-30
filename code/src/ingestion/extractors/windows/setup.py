"""Setup Event Log extraction (``windows_setup``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Representative Windows Setup Event IDs.
SETUP_START_ID = 1
SETUP_SUCCESS_ID = 2
SETUP_REBOOT_ID = 3
SETUP_COMPLETE_ID = 4


def extract_windows_setup(line: str) -> ExtractionResult:
    """Extract host from a Setup Event Log line."""
    record = parse_windows_record(line)
    return build_windows_extraction_result(
        record,
        event_class="setup",
        no_match_reason="no windows_setup entity extracted",
    )
