"""Suricata IDS vs pfSense firewall isolation (Phase 24)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

PFSENSE = (
    "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,0x0,,"
    "64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
)
EVE = (
    '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
    '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
    '"alert":{"action":"blocked","severity":1,"signature":"ET SCAN"}}'
)
WEAK_ALERT = "alert from 10.0.0.8 to 1.2.3.4"


def test_pfsense_stays_firewall() -> None:
    assert detect_log_source_from_line(PFSENSE) == "firewall"
    assert resolve_log_source(Path("eve.json"), PFSENSE) == "firewall"
    assert detect_log_source_from_line(PFSENSE) != "ids_ips"


def test_suricata_is_ids_ips_not_firewall() -> None:
    assert detect_log_source_from_line(EVE) == "ids_ips"
    assert resolve_log_source(Path("pfsense.txt"), EVE) == "ids_ips"
    assert detect_log_source_from_line(EVE) != "firewall"


def test_weak_alert_does_not_steal() -> None:
    assert detect_log_source_from_line(WEAK_ALERT) is None
