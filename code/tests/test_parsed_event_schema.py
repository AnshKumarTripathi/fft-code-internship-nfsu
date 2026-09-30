"""Tests for Phase 3 ParsedEvent / Template pydantic models."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.parsing.schema import ParsedEvent, Template


def test_parsed_event_rejects_missing_entity_id() -> None:
    with pytest.raises(ValidationError):
        ParsedEvent(
            event_id=1,
            # entity_id intentionally omitted
            template_id="1",
            event_timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            log_source="ssh",
            raw_fields={},
            ingested_at=datetime.now(timezone.utc),
        )


def test_parsed_event_valid_roundtrip() -> None:
    event = ParsedEvent(
        event_id=1,
        entity_id="user:alice",
        template_id="3",
        event_timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        log_source="ssh",
        raw_fields={"src_ip": "192.168.1.10"},
        ingested_at=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
    )
    payload = event.model_dump()
    assert payload["entity_id"] == "user:alice"
    assert payload["template_id"] == "3"
    assert ParsedEvent.model_validate(payload).event_id == 1


def test_template_model() -> None:
    template = Template(
        template_id="1",
        template_string="Failed password for <*> from <*>",
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 2, tzinfo=timezone.utc),
        occurrence_count=5,
    )
    assert template.occurrence_count == 5
