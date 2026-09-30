"""TLS handshake vs web_access isolation (Phase 35)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

ACCESS = (
    '10.0.0.8 - alice [15/Jan/2024:10:00:02 +0000] "GET /index.html HTTP/1.1" 200 1234 '
    '"-" "Mozilla/5.0"'
)
HANDSHAKE = "Jan 15 10:00:01 web1 nginx[12]: ssl_handshake TLSv1.3 from 10.0.0.8"


def test_combined_access_stays_web_access() -> None:
    assert detect_log_source_from_line(ACCESS) == "web_access"
    assert resolve_log_source(Path("tls.txt"), ACCESS) == "web_access"


def test_ssl_handshake_is_tls_even_in_access_log() -> None:
    assert detect_log_source_from_line(HANDSHAKE) == "tls"
    assert resolve_log_source(Path("access.log"), HANDSHAKE) == "tls"


def test_handshake_entity_is_ip() -> None:
    result = extract_entity_and_timestamp(HANDSHAKE, "tls", default_year=2024)
    assert result.extraction_ok is True
    assert result.entity_type == "ip"
    assert result.entity_id == "10.0.0.8"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("tls.txt")) == "tls"
    assert detect_log_source(Path("access.log")) == "web_access"
