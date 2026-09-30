"""Physical family vs linux_syslog and app_runtime isolation (Phase 33)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
APP_RUNTIME = '{"level":"info","msg":"hello","ts":"2024-01-15T10:00:01Z"}'
BADGE = "2024-01-15T10:00:01Z,B-1001,door-lobby,allow"
CCTV = '{"camera_id":"cam-lobby","event":"motion","ts":"2024-01-15T10:00:01Z"}'
IOT = (
    '{"device_id":"sensor-01","fw_version":"1.2.0","event":"telemetry",'
    '"ts":"2024-01-15T10:00:01Z"}'
)


def test_generic_syslog_stays_linux_syslog() -> None:
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("badge.csv"), SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("cctv.json"), SYSLOG) == "linux_syslog"


def test_generic_json_stays_app_runtime() -> None:
    assert detect_log_source_from_line(APP_RUNTIME) == "app_runtime"
    assert resolve_log_source(Path("iot.json"), APP_RUNTIME) == "app_runtime"


def test_badge_and_cctv_are_physical() -> None:
    assert detect_log_source_from_line(BADGE) == "badge"
    assert detect_log_source_from_line(CCTV) == "cctv"
    assert detect_log_source_from_line(IOT) == "iot"


def test_filename_fallback() -> None:
    assert detect_log_source(Path("badge.csv")) == "badge"
    assert detect_log_source(Path("cctv.json")) == "cctv"
    assert detect_log_source(Path("iot.json")) == "iot"
    assert detect_log_source(Path("syslog.log")) == "linux_syslog"
