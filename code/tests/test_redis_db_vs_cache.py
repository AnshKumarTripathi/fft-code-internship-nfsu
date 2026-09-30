"""db_redis vs cache routing (Phase 31)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.entity_extractor import extract_entity_and_timestamp
from src.ingestion.loaders import detect_log_source, detect_log_source_from_line, resolve_log_source

ROLE = "12345:M 15 Jan 2024 10:00:01.123 * Ready to accept connections"
MONITOR = '1705312803.123456 [0 10.0.0.8:54321] "GET" "key"'
MONITOR_CMD = '1705312803.123456 [0 10.0.0.8:54321] "MONITOR"'
MEMCACHED = "<10 get session:alice"


def test_redis_role_stays_db_redis() -> None:
    assert detect_log_source_from_line(ROLE) == "db_redis"
    assert resolve_log_source(Path("redis.txt"), ROLE) == "db_redis"
    assert resolve_log_source(Path("monitor.log"), ROLE) == "db_redis"


def test_monitor_output_in_redis_file_is_db_redis() -> None:
    assert detect_log_source_from_line(MONITOR) == "db_redis"
    assert resolve_log_source(Path("redis.txt"), MONITOR) == "db_redis"


def test_monitor_output_in_monitor_log_is_cache() -> None:
    assert resolve_log_source(Path("monitor.log"), MONITOR) == "cache"
    result = extract_entity_and_timestamp(MONITOR, "cache", default_year=1999)
    assert result.extraction_ok is True


def test_monitor_command_marker_is_cache() -> None:
    assert detect_log_source_from_line(MONITOR_CMD) == "cache"
    assert resolve_log_source(Path("redis.txt"), MONITOR_CMD) == "cache"


def test_memcached_verbose_is_cache() -> None:
    assert detect_log_source_from_line(MEMCACHED) == "cache"
    assert resolve_log_source(Path("memcached.txt"), MEMCACHED) == "cache"
    result = extract_entity_and_timestamp(MEMCACHED, "cache", default_year=1999)
    assert result.extraction_ok is True
    assert result.entity_type in {"ip", "host", "service"}


def test_filename_fallback() -> None:
    assert detect_log_source(Path("monitor.log")) == "cache"
    assert detect_log_source(Path("redis.log")) == "db_redis"
    assert detect_log_source(Path("memcached.txt")) == "cache"
