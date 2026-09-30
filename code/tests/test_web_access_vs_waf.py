"""Web access vs WAF isolation (Phase 25)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source_from_line, resolve_log_source

WAF = (
    '{"timestamp":"2024-01-15T10:00:01.000Z","transaction":{"client_ip":"10.0.0.8",'
    '"host_ip":"10.0.0.1","request":{"method":"GET","uri":"/admin"},'
    '"response":{"http_code":403},"messages":[{"message":"Access denied",'
    '"details":{"ruleId":"949110","severity":"2","match":"block"}}]}}'
)
COMBINED = (
    '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
)


def test_modsecurity_json_stays_waf() -> None:
    assert detect_log_source_from_line(WAF) == "waf"
    assert resolve_log_source(Path("access.log"), WAF) == "waf"
    assert detect_log_source_from_line(WAF) != "web_access"


def test_combined_is_web_access_not_waf() -> None:
    assert detect_log_source_from_line(COMBINED) == "web_access"
    assert resolve_log_source(Path("waf.json"), COMBINED) == "web_access"
    assert detect_log_source_from_line(COMBINED) != "waf"
