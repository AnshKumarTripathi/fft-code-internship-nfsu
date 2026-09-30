"""Istio mesh vs Squid proxy isolation (Phase 28)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

ISTIO = (
    '[2024-01-15T10:00:01.123Z] "GET /productpage HTTP/1.1" 200 - 0 529 4 3 "-" '
    '"curl/7.68.0" "11111111-2222-3333-4444-555555555555" '
    '"productpage.default.svc.cluster.local" "10.0.0.2:9080" '
    "outbound|9080||productpage.default.svc.cluster.local "
    "10.0.0.8:54321 10.0.0.2:9080 10.0.0.8:41234 - default"
)
SQUID = (
    "1705312801.123    312 10.0.0.8 TCP_MISS/200 1234 GET http://example.com/ "
    "alice HIER_DIRECT/1.2.3.4 text/html"
)


def test_istio_is_service_mesh() -> None:
    assert detect_log_source_from_line(ISTIO) == "service_mesh"
    assert resolve_log_source(Path("squid.log"), ISTIO) == "service_mesh"


def test_squid_stays_proxy() -> None:
    assert detect_log_source_from_line(SQUID) == "proxy"
    assert resolve_log_source(Path("istio.log"), SQUID) == "proxy"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("istio.log")) == "service_mesh"
    assert detect_log_source(Path("squid.log")) == "proxy"
