"""Video-conferencing call JSON vs collab_audit isolation (Phase 34)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

COLLAB = (
    '{"platform":"zoom","actor":"eve","action":"meeting_started",'
    '"workspace":"acme","ip":"203.0.113.11","ts":"2024-01-15T10:00:05Z"}'
)
CALL = (
    '{"meeting_id":"m-1001","organizer":"alice","join":true,'
    '"ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
)


def test_zoom_audit_stays_collab_audit() -> None:
    assert detect_log_source_from_line(COLLAB) == "collab_audit"
    assert resolve_log_source(Path("video_conf.json"), COLLAB) == "collab_audit"


def test_call_json_is_video_conf_even_in_collab_file() -> None:
    assert detect_log_source_from_line(CALL) == "video_conf"
    assert resolve_log_source(Path("collab.json"), CALL) == "video_conf"


def test_call_json_entity_is_organizer() -> None:
    result = extract_entity_and_timestamp(CALL, "video_conf", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "user"
    assert result.entity_id == "alice"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("video_conf.json")) == "video_conf"
    assert detect_log_source(Path("collab.json")) == "collab_audit"
