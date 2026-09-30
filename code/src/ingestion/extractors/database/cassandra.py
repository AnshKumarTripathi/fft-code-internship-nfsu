"""Cassandra system.log extraction (``db_cassandra``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_cassandra_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

LINE = re.compile(
    r"^(?P<level>INFO|WARN|ERROR|DEBUG)\s+"
    r"\[(?P<thread>[^\]]+)\]\s+"
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+"
    r"(?P<rest>.+)"
)
USER = re.compile(r"\buser[=\s]+([A-Za-z0-9._-]+)", re.IGNORECASE)
KEYSPACE = re.compile(r"\b(?:keyspace|ks)\s+([A-Za-z0-9_]+)", re.IGNORECASE)


def _classify(thread: str, rest: str) -> str:
    blob = f"{thread} {rest}".lower()
    if "slow query" in blob or "slow_query" in blob:
        return "slow"
    if "stored proc" in blob or "procedure" in blob:
        return "procedure"
    if "create keyspace" in blob or "alter keyspace" in blob or "drop keyspace" in blob:
        return "ddl"
    if "audit" in blob:
        return "audit"
    if "commitlog" in blob or "commit log" in blob:
        return "wal"
    if "repair" in blob or "streaming" in blob or "replication" in blob:
        return "replication"
    if "snapshot" in blob or "backup" in blob or "nodetool snapshot" in blob:
        return "backup"
    if "select" in blob or "insert" in blob or "cql query" in blob:
        return "query"
    if "listening for cql" in blob or "connection" in blob or "native-transport" in blob:
        return "session"
    return "query"


def extract_cassandra(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract cluster/user from Cassandra system.log text."""
    del default_year, year_state, year_policy
    match = LINE.match(line.strip())
    rest = match.group("rest") if match else line
    thread = match.group("thread") if match else ""
    extra: dict[str, str] = {}
    if match:
        extra["level"] = match.group("level")
        extra["thread"] = thread
    user_match = USER.search(line)
    ks = KEYSPACE.search(line)
    event_timestamp = parse_cassandra_timestamp(line)
    return build_database_extraction_result(
        event_class=_classify(thread, rest),
        username=user_match.group(1) if user_match else "",
        service=ks.group(1) if ks else "cassandra",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no cassandra entity extracted",
    )
