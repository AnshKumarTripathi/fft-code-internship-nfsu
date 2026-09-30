"""Task Scheduler operational extraction (``windows_task_scheduler``)."""

from __future__ import annotations

from src.ingestion.extractors.windows.common import (
    build_windows_extraction_result,
    parse_windows_record,
)
from src.ingestion.models import ExtractionResult

TASK_REGISTERED_ID = 106
TASK_STARTED_ID = 200
TASK_COMPLETED_ID = 201

EVENT_CLASS = {
    TASK_REGISTERED_ID: "task",
    TASK_STARTED_ID: "task",
    TASK_COMPLETED_ID: "task",
}


def extract_windows_task_scheduler(line: str) -> ExtractionResult:
    """Extract user/host from a Task Scheduler operational line."""
    record = parse_windows_record(line)
    extra: dict[str, str] = {}
    task_name = record.fields.get("TaskName") or record.fields.get("Task") or ""
    if task_name:
        extra["task_name"] = task_name
    return build_windows_extraction_result(
        record,
        event_class=EVENT_CLASS.get(record.event_id or -1, "task"),
        extra_fields=extra,
        no_match_reason="no windows_task_scheduler entity extracted",
    )
