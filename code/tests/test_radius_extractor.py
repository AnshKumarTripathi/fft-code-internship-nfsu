"""radius / TACACS+ extractor tests (Phase 22)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "identity" / "radius.txt"

OK = (
    "Jan 15 10:00:01 radius1 radiusd[100]: Auth: Login OK: [alice] "
    "(from client vpn port 0 cli 10.0.0.8)"
)
REJECT = "Access-Reject for frank from 10.0.0.14"
TAC = (
    "Jan 15 10:00:08 tacacs tac_plus[50]: login query for 'alice' tty0 "
    "from 10.0.0.8 accepted"
)


def test_login_ok_extracts_user() -> None:
    assert resolve_log_source(Path("messages"), OK) == "radius"
    result = extract_entity_and_timestamp(OK, "radius", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["auth_result"] == "success"
    assert result.raw_fields["protocol"] == "radius"
    assert result.raw_fields["src_ip"] == "10.0.0.8"


def test_access_reject_is_failure() -> None:
    assert resolve_log_source(Path("radius.log"), REJECT) == "radius"
    result = extract_entity_and_timestamp(REJECT, "radius", default_year=2024)
    assert result.extraction_ok is True
    assert result.raw_fields["auth_result"] == "failure"


def test_tac_plus_stays_radius() -> None:
    assert resolve_log_source(Path("syslog"), TAC) == "radius"
    result = extract_entity_and_timestamp(TAC, "radius", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "alice"
    assert result.raw_fields["protocol"] == "tacacs"
    assert result.raw_fields["auth_result"] == "success"


def test_radius_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "radius", default_year=2024).extraction_ok
        for line in lines
    )
