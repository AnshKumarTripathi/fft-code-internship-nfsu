"""Pydantic models for Phase 3 parsing (SDD §5 / §6)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Shape of a Phase 2 staging row consumed as parse input."""

    raw_line: str
    entity_id: str | None = None
    event_timestamp: datetime | None = None
    log_source: str
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime
    ingest_row_id: str | None = None
    source_path: str | None = None
    content_hash: str | None = None
    entity_type: str | None = None
    extraction_ok: bool | None = None
    failure_reason: str | None = None
    line_number: int | None = None


class ParsedEvent(BaseModel):
    """Validated structured event written to parsed_events Parquet."""

    event_id: int
    entity_id: str
    template_id: str
    event_timestamp: datetime
    log_source: str
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime
    parser_snapshot_id: str | None = None


class Template(BaseModel):
    """Drain3 template aggregate for the templates table."""

    template_id: str
    template_string: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
