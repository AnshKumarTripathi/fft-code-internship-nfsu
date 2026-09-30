"""Redis server-log and MONITOR extraction (``db_redis``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_epoch_timestamp,
    parse_redis_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

ROLE_LINE = re.compile(
    r"^(?P<pid>\d+):(?P<role>[MXSCE])\s+(?P<rest>.+)$"
)
MONITOR = re.compile(
    r'^(?P<epoch>\d+\.\d+)\s+\[(?P<db>\d+)\s+(?P<client>[^\]]+)\]\s+"(?P<cmd>[^"]+)"'
)
CLIENT_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _classify(text: str) -> str:
    lowered = text.lower()
    if "slow log" in lowered or "slowlog" in lowered:
        return "slow"
    if "eval" in lowered or "lua" in lowered:
        return "procedure"
    if "config set" in lowered or "module" in lowered:
        return "ddl"
    if "acl log" in lowered or " auth " in lowered or lowered.startswith("auth"):
        return "audit"
    if "bgsave" in lowered or "bgrewriteaof" in lowered:
        return "backup"
    if "aof" in lowered or "rdb" in lowered:
        return "wal"
    if "replica" in lowered or ("master" in lowered and "sync" in lowered):
        return "replication"
    if "accepted" in lowered or "client closed" in lowered or "ready to accept" in lowered:
        return "session"
    if re.search(r'"(get|set|hget|hset|del|incr)"', lowered):
        return "query"
    return "query"


def extract_redis(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract cluster/IP from Redis server logs and MONITOR lines."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    monitor = MONITOR.match(stripped)
    if monitor:
        client = monitor.group("client")
        ip_match = CLIENT_IP.search(client)
        extra = {
            "command": monitor.group("cmd"),
            "redis_db": monitor.group("db"),
        }
        event_timestamp = parse_epoch_timestamp(monitor.group("epoch"))
        cmd = monitor.group("cmd").upper()
        event_class = "procedure" if cmd == "EVAL" else "query"
        if cmd in {"CONFIG"}:
            event_class = "ddl"
        return build_database_extraction_result(
            event_class=event_class,
            src_ip=ip_match.group(1) if ip_match else "",
            service="redis",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no redis entity extracted",
        )
    role = ROLE_LINE.match(stripped)
    rest = role.group("rest") if role else stripped
    extra: dict[str, str] = {}
    if role:
        extra["pid"] = role.group("pid")
        extra["role"] = role.group("role")
    ip_match = CLIENT_IP.search(rest)
    event_timestamp = parse_redis_timestamp(stripped)
    return build_database_extraction_result(
        event_class=_classify(rest),
        src_ip=ip_match.group(1) if ip_match else "",
        service="redis",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no redis entity extracted",
    )
