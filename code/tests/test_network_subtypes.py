"""Parametrized network subtype extractors (Phase 23)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.extractors.network import NETWORK_LOG_SOURCES
from src.ingestion.loaders import resolve_log_source

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "logs" / "network"

_FILE_FOR_SOURCE = {
    "firewall": "pfsense.txt",
    "network_device": "device.txt",
    "vpn": "vpn.txt",
    "dns": "dns.txt",
    "dhcp": "dhcp.txt",
    "proxy": "proxy.txt",
    "netflow": "netflow.txt",
    "load_balancer": "load_balancer.txt",
    "nac": "nac.txt",
    "wireless": "wireless.txt",
    "bgp": "bgp.txt",
}


@pytest.mark.parametrize("log_source", sorted(_FILE_FOR_SOURCE))
def test_subtype_fixture_extracts(log_source: str) -> None:
    path = FIXTURE_DIR / _FILE_FOR_SOURCE[log_source]
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 10
    assert resolve_log_source(path, lines[0]) == log_source
    ok = 0
    for line in lines:
        result = extract_entity_and_timestamp(line, log_source, default_year=2024)
        if result.extraction_ok:
            ok += 1
    assert ok >= 1


def test_all_network_sources_have_fixtures() -> None:
    missing = [
        source
        for source in sorted(NETWORK_LOG_SOURCES)
        if not (FIXTURE_DIR / _FILE_FOR_SOURCE[source]).is_file()
    ]
    assert missing == []
