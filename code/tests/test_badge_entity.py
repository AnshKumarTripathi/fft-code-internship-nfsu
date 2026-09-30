"""Badge ID entity policy and auth_result (Phase 33)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

ALLOW_CSV = "2024-01-15T10:00:01Z,B-1001,door-lobby,allow"
DENY_CSV = "2024-01-15T10:00:02Z,B-1002,door-lab,deny"
ALLOW_SYSLOG = (
    "Jan 15 10:00:01 acs1 accessd[12]: badge_id=B-1001 door=lobby result=allow"
)
DENY_SYSLOG = (
    "Jan 15 10:00:02 acs1 accessd[12]: badge_id=B-1002 door=lab result=deny"
)


def test_csv_allow_is_user_success() -> None:
    assert detect_log_source_from_line(ALLOW_CSV) == "badge"
    result = extract_entity_and_timestamp(ALLOW_CSV, "badge", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "user"
    assert result.entity_id == "B-1001"
    assert result.raw_fields.get("auth_result") == "success"
    assert result.raw_fields.get("door") == "door-lobby"


def test_csv_deny_is_user_failure() -> None:
    result = extract_entity_and_timestamp(DENY_CSV, "badge", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "B-1002"
    assert result.entity_type == "user"
    assert result.raw_fields.get("auth_result") == "failure"


def test_syslog_allow_deny() -> None:
    assert detect_log_source_from_line(ALLOW_SYSLOG) == "badge"
    allowed = extract_entity_and_timestamp(ALLOW_SYSLOG, "badge", default_year=2024)
    denied = extract_entity_and_timestamp(DENY_SYSLOG, "badge", default_year=2024)
    assert allowed.entity_type == "user"
    assert allowed.entity_id == "B-1001"
    assert allowed.raw_fields.get("auth_result") == "success"
    assert denied.raw_fields.get("auth_result") == "failure"


def test_badge_in_syslog_filename_stays_badge() -> None:
    assert resolve_log_source(Path("syslog.log"), ALLOW_SYSLOG) == "badge"
