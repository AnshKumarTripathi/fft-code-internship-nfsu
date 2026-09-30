"""CRI pod stdout vs Apache combined isolation (Phase 28)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

CRI = "2024-01-15T10:00:01.123456789Z stdout F starting nginx"
APACHE = (
    '127.0.0.1 - frank [15/Jan/2024:10:00:01 +0000] "GET /apache_pb.gif HTTP/1.0" '
    '200 2326 "http://example.com/start.html" "Mozilla/4.08"'
)
APP_JSON = '{"ts":"2024-01-15T10:00:01Z","level":"info","msg":"hello","service":"api"}'


def test_cri_is_k8s_pod() -> None:
    assert detect_log_source_from_line(CRI) == "k8s_pod"
    assert resolve_log_source(Path("access.log"), CRI) == "k8s_pod"


def test_apache_stays_web_access() -> None:
    assert detect_log_source_from_line(APACHE) == "web_access"
    assert resolve_log_source(Path("pod.log"), APACHE) == "web_access"


def test_app_runtime_json_stays_app_runtime() -> None:
    assert detect_log_source_from_line(APP_JSON) == "app_runtime"
    assert resolve_log_source(Path("pod.log"), APP_JSON) == "app_runtime"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("pod.log")) == "k8s_pod"
    assert detect_log_source(Path("access.log")) == "web_access"
