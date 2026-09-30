"""Docker daemon vs generic syslog isolation (Phase 28)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

DOCKER = (
    'Jan 15 10:00:01 worker1 dockerd[1200]: time="2024-01-15T10:00:01Z" '
    'level=info msg="starting container"'
)
SYSLOG = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
JSON_FILE = (
    '{"log":"hello\\n","stream":"stdout","time":"2024-01-15T10:00:01.123456789Z"}'
)


def test_dockerd_is_docker() -> None:
    assert detect_log_source_from_line(DOCKER) == "docker"
    assert resolve_log_source(Path("syslog.log"), DOCKER) == "docker"


def test_generic_syslog_stays_linux_syslog() -> None:
    assert detect_log_source_from_line(SYSLOG) == "linux_syslog"
    assert resolve_log_source(Path("docker.log"), SYSLOG) == "linux_syslog"


def test_json_file_is_docker() -> None:
    assert detect_log_source_from_line(JSON_FILE) == "docker"
    result = extract_entity_and_timestamp(JSON_FILE, "docker", default_year=1999)
    assert result.extraction_ok is True
    assert result.event_timestamp is not None
    assert result.event_timestamp.year == 2024


def test_filename_fallback() -> None:
    assert detect_log_source(Path("docker.log")) == "docker"
    assert detect_log_source(Path("syslog.log")) == "linux_syslog"
