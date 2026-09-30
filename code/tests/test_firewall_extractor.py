"""pfSense filterlog extractor tests (Phase 23)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import resolve_log_source

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "network" / "pfsense.txt"

BLOCK = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)
PASS = (
    "Jan 15 10:00:02 fw1 filterlog[219]: 9,,,1000000104,em0,match,pass,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.9,8.8.8.8,53100,443,0,S,112,,65535,,"
)


def test_block_extracts_src_dst_deny() -> None:
    assert resolve_log_source(Path("syslog"), BLOCK) == "firewall"
    result = extract_entity_and_timestamp(BLOCK, "firewall", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.8"
    assert result.entity_type == "ip"
    assert result.raw_fields["dst_ip"] == "1.2.3.4"
    assert result.raw_fields["src_port"] == "54321"
    assert result.raw_fields["dst_port"] == "22"
    assert result.raw_fields["action"] == "deny"
    assert result.raw_fields["auth_result"] == "failure"
    assert result.raw_fields["protocol"] == "tcp"


def test_pass_extracts_allow() -> None:
    result = extract_entity_and_timestamp(PASS, "firewall", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_id == "10.0.0.9"
    assert result.raw_fields["dst_ip"] == "8.8.8.8"
    assert result.raw_fields["action"] == "allow"
    assert result.raw_fields["auth_result"] == "success"


def test_pfsense_fixture_has_extraction_ok() -> None:
    lines = [line for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) >= 10
    assert any(
        extract_entity_and_timestamp(line, "firewall", default_year=2024).extraction_ok
        for line in lines
    )
