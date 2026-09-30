"""Pydantic models for Phase 2 ingest rows (internal staging contract)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EntityType = Literal["user", "host", "ip", "service"]


class IngestedLine(BaseModel):
    source_path: str
    log_source: str
    line_number: int
    raw_line: str
    content_hash: str
    ingested_at: datetime
    evidence_hash: str | None = None


class ExtractionResult(BaseModel):
    entity_id: str | None = None
    entity_type: EntityType | None = None
    event_timestamp: datetime | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    extraction_ok: bool = False
    failure_reason: str | None = None


class IngestStagingRow(BaseModel):
    ingest_row_id: str
    source_path: str
    log_source: str
    line_number: int
    raw_line: str
    content_hash: str
    entity_id: str | None = None
    entity_type: EntityType | None = None
    event_timestamp: datetime | None = None
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime
    extraction_ok: bool = False
    failure_reason: str | None = None
    evidence_hash: str | None = None
