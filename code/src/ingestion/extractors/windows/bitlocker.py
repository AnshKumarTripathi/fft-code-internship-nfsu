"""BitLocker / recovery extraction (``windows_bitlocker``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

# Parsed subset of Event IDs 768–780.
ENCRYPTION_STARTED_ID = 768
ENCRYPTION_COMPLETED_ID = 769
DECRYPTION_STARTED_ID = 770
PROTECTION_ENABLED_ID = 775
RECOVERY_KEY_ID = 780

PARSED_EVENT_IDS = frozenset(
    {
        ENCRYPTION_STARTED_ID,
        ENCRYPTION_COMPLETED_ID,
        DECRYPTION_STARTED_ID,
        PROTECTION_ENABLED_ID,
        RECOVERY_KEY_ID,
    }
)


def extract_windows_bitlocker(line: str) -> ExtractionResult:
    """Extract host/user from a BitLocker event line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    volume = record.fields.get("VolumeName") or record.fields.get("DriveLetter") or ""
    if volume:
        extra["volume"] = volume
    return build_windows_extraction_result(
        record,
        event_class="bitlocker",
        extra_fields=extra,
        no_match_reason="no windows_bitlocker entity extracted",
    )
