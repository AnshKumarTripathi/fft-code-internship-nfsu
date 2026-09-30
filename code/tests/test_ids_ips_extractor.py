"""Suricata EVE JSON extractor tests (Phase 24)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "security" / "ids_ips.json"

ALERT = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","flow_id":1,'
    '"event_type":"alert","src_ip":"10.0.0.8","src_port":54321,'
    '"dest_ip":"1.2.3.4","dest_port":22,"proto":"TCP",'
    '"alert":{"action":"allowed","signature":"ET SCAN SSH Brute Force","severity":2}}'
)


def test_suricata_alert_extracts_src_and_severity() -> None:
    assert resolve_log_source(Path("syslog"), ALERT) == "ids_ips"
    result = extract_entity_and_timestamp(ALERT, "ids_ips", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.entity_type == "ip"
    assert result.raw_fields["dst_ip"] == "1.2.3.4"
    assert result.raw_fields["action"] == "allowed"
    assert result.raw_fields["severity"] == "2"
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_ids_ips_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "ids_ips", default_year=2024).extraction_ok
        for line in lines
    )
