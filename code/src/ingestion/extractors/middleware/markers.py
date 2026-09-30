"""Content-first and filename routing for middleware and queue families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.database.markers import REDIS_MONITOR
from src.ingestion.extractors.identity.common import parse_json_object

KAFKA = re.compile(
    r"\[KafkaServer|\bGroupCoordinator\b|\bkafka\.(?:server|controller|coordinator)\b",
    re.IGNORECASE,
)
RABBIT_USER = re.compile(r"user '[^']+' authenticated", re.IGNORECASE)
RABBIT_CONN = re.compile(r"\bconnection <\d+\.\d+\.\d+>", re.IGNORECASE)
RABBIT_PRODUCT = re.compile(r"\brabbitmq\b", re.IGNORECASE)
AIRFLOW = re.compile(
    r"\bairflow\b|\{taskinstance\.py|\*\*\* Reading local file|\bINFO - DAG:",
    re.IGNORECASE,
)
MONITOR_CMD = re.compile(r'\bMONITOR\b|"MONITOR"', re.IGNORECASE)
MEMCACHED_VERBOSE = re.compile(r"^[<>]\d+\s+(?:get|set|add|delete|incr|decr|touch)\b", re.IGNORECASE)
MEMCACHED_STORED = re.compile(r"^>\d+\s+(?:STORED|NOT_FOUND|END|VALUE)\b", re.IGNORECASE)
MEMCACHED_PROG = re.compile(r"\bmemcached\[", re.IGNORECASE)

CACHE_BASENAMES = frozenset(
    {
        "monitor.log",
        "monitor.txt",
        "cache.log",
        "cache.txt",
        "memcached.log",
        "memcached.txt",
    }
)

_BASENAME_SOURCES = {
    "kafka.txt": "kafka",
    "kafka.log": "kafka",
    "controller.log": "kafka",
    "rabbitmq.txt": "rabbitmq",
    "rabbitmq.log": "rabbitmq",
    "esb.json": "esb",
    "esb.txt": "esb",
    "monitor.log": "cache",
    "monitor.txt": "cache",
    "cache.log": "cache",
    "cache.txt": "cache",
    "memcached.log": "cache",
    "memcached.txt": "cache",
    "airflow.txt": "airflow",
    "airflow.log": "airflow",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("kafka", "kafka"),
    ("controller.log", "kafka"),
    ("rabbitmq", "rabbitmq"),
    ("esb.json", "esb"),
    ("esb.txt", "esb"),
    ("monitor.log", "cache"),
    ("monitor.txt", "cache"),
    ("memcached", "cache"),
    ("cache.log", "cache"),
    ("cache.txt", "cache"),
    ("airflow", "airflow"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "redis.log",
        "redis.txt",
        "cron.log",
        "cron.txt",
        "auth.log",
        "access.log",
        "server1.log",
    }
)


def is_cache_filename(path: Path) -> bool:
    """Return True when the basename is a documented cache token."""
    return path.name.lower() in CACHE_BASENAMES


def is_redis_monitor_output(line: str) -> bool:
    """Return True for redis-cli MONITOR command-output lines."""
    return REDIS_MONITOR.match((line or "").strip()) is not None


def _is_esb(obj: dict) -> bool:
    if "tx_id" not in obj and "txId" not in obj:
        return False
    return "route" in obj


def detect_middleware_log_source_from_line(line: str) -> str | None:
    """Return a middleware ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_esb(obj):
            return "esb"
        return None
    stripped = line.strip()
    if KAFKA.search(stripped):
        return "kafka"
    if RABBIT_USER.search(stripped) or RABBIT_CONN.search(stripped) or RABBIT_PRODUCT.search(
        stripped
    ):
        return "rabbitmq"
    if AIRFLOW.search(stripped):
        return "airflow"
    if MEMCACHED_VERBOSE.match(stripped) or MEMCACHED_STORED.match(stripped):
        return "cache"
    if MEMCACHED_PROG.search(stripped):
        return "cache"
    if MONITOR_CMD.search(stripped):
        return "cache"
    return None


def detect_middleware_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal redis.log or cron.log."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
