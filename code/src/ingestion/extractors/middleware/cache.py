"""Redis/Memcached cache command extraction (``cache``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.markers import REDIS_MONITOR, REDIS_ROLE
from src.ingestion.extractors.database.redis import MONITOR, extract_redis
from src.ingestion.extractors.middleware.common import (
    YEAR_POLICY_CARRY,
    build_middleware_extraction_result,
    extract_syslog_middleware_line,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

MEMCACHED_VERBOSE = re.compile(
    r"^[<>](?P<fd>\d+)\s+(?P<op>get|set|add|delete|incr|decr|touch|STORED|NOT_FOUND|END|VALUE)\b"
    r"(?:\s+(?P<key>\S+))?",
    re.IGNORECASE,
)
CLIENT_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def extract_cache(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Reuse Phase 26 Redis parsing, or extract memcached verbose commands."""
    stripped = line.strip()
    if REDIS_MONITOR.match(stripped) or REDIS_ROLE.match(stripped) or MONITOR.match(stripped):
        return extract_redis(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    verbose = MEMCACHED_VERBOSE.match(stripped)
    if verbose is None:
        body = stripped
        if ":" in stripped:
            body = stripped.rsplit(":", 1)[-1].strip()
        verbose = MEMCACHED_VERBOSE.match(body)
    extra: dict[str, str] = {"cache_engine": "memcached"}
    if verbose:
        extra["command"] = verbose.group("op").upper()
        key = verbose.group("key")
        if key:
            extra["key"] = key
    ip_match = CLIENT_IP.search(line)
    src_ip = ip_match.group(1) if ip_match else ""
    hostname, program, pid = parse_syslog_fields(line)
    if hostname:
        if program:
            extra["program"] = program
        if pid:
            extra["pid"] = pid
        return extract_syslog_middleware_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            src_ip=src_ip,
            service="memcached",
            extra_fields=extra,
            no_match_reason="no cache entity extracted",
        )
    return build_middleware_extraction_result(
        src_ip=src_ip,
        service="memcached",
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no cache entity extracted",
    )
