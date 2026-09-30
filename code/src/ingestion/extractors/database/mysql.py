"""MySQL/MariaDB general and slow-query extraction (``db_mysql``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

GENERAL = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<id>\d+)\s+(?P<cmd>\S+)\s*(?P<rest>.*)$"
)
SLOW = re.compile(
    r"# Time: (?P<ts>\S+).*?User@Host:\s+(?P<user>[^\s\[]+).*?"
    r"Query_time:\s+(?P<ms>[\d.]+)",
    re.IGNORECASE,
)
SLOW_SHORT = re.compile(r"# Query_time:\s+(?P<ms>[\d.]+)", re.IGNORECASE)
CONNECT = re.compile(
    r"(?P<user>[^@\s]+)@(?P<ip>[0-9.]+)\s+on\s+(?P<db>\S+)",
    re.IGNORECASE,
)
USER_HOST = re.compile(r"User@Host:\s+(?P<user>[^\s\[]+)", re.IGNORECASE)


def _classify(cmd: str, rest: str) -> str:
    combined = f"{cmd} {rest}".lower()
    if "query_time" in combined:
        return "slow"
    if cmd.lower() == "connect" or cmd.lower() == "quit":
        return "session"
    if cmd.lower() == "rotate" or "binlog" in combined:
        return "wal"
    if cmd.lower() == "replica" or "replica" in combined or "slave" in combined:
        return "replication"
    if cmd.lower() == "backup" or "mysqldump" in combined:
        return "backup"
    if re.search(r"\bcall\b", combined):
        return "procedure"
    if combined.startswith("audit:") or "audit:" in combined:
        return "audit"
    if re.search(r"\b(?:create|alter|drop|grant|revoke)\b", combined):
        return "ddl"
    if cmd.lower() in {"query", "prepare", "execute"}:
        return "query"
    return "query"


def extract_mysql(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from MySQL general or one-line slow-query text."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    slow = SLOW.search(stripped)
    if slow:
        event_timestamp = parse_iso_datetime(slow.group("ts"))
        extra = {"duration_ms": slow.group("ms")}
        return build_database_extraction_result(
            event_class="slow",
            username=slow.group("user"),
            service="mysql",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no mysql entity extracted",
        )
    if SLOW_SHORT.search(stripped):
        user_match = USER_HOST.search(stripped)
        duration = SLOW_SHORT.search(stripped)
        extra = {}
        if duration:
            extra["duration_ms"] = duration.group("ms")
        ts_match = re.search(r"# Time: (\S+)", stripped)
        event_timestamp = parse_iso_datetime(ts_match.group(1)) if ts_match else None
        return build_database_extraction_result(
            event_class="slow",
            username=user_match.group("user") if user_match else "",
            service="mysql",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no mysql entity extracted",
        )
    general = GENERAL.match(stripped)
    if general is None:
        return build_database_extraction_result(
            event_class="query",
            service="mysql",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no mysql entity extracted",
        )
    rest = general.group("rest")
    cmd = general.group("cmd")
    username = ""
    src_ip = ""
    database = "mysql"
    conn = CONNECT.search(rest)
    if conn:
        username = conn.group("user")
        src_ip = conn.group("ip")
        database = conn.group("db").rstrip(";")
    event_timestamp = parse_iso_datetime(general.group("ts"))
    extra = {"thread_id": general.group("id"), "command": cmd}
    return build_database_extraction_result(
        event_class=_classify(cmd, rest),
        username=username,
        src_ip=src_ip,
        service=database,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no mysql entity extracted",
    )
