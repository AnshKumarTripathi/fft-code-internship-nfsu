"""ALB vs on-prem HAProxy isolation (Phase 27)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

ALB = (
    "h2 2024-01-15T10:00:01.000000Z app/my-loadbalancer/50dc6c495c0c9188 "
    "192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "
    '"GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0"'
)
HAPROXY = (
    "Jan 15 10:00:01 lb1 haproxy[55]: 10.0.0.8:54321 [15/Jan/2024:10:00:01.123] "
    'http-in app/srv1 0/0/1/2/3 200 1234 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"'
)


def test_alb_is_aws_elb() -> None:
    assert detect_log_source_from_line(ALB) == "aws_elb"
    assert resolve_log_source(Path("haproxy.log"), ALB) == "aws_elb"


def test_haproxy_stays_load_balancer() -> None:
    assert detect_log_source_from_line(HAPROXY) == "load_balancer"
    assert resolve_log_source(Path("alb.log"), HAPROXY) == "load_balancer"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("alb.log")) == "aws_elb"
    assert detect_log_source(Path("haproxy.log")) == "load_balancer"
