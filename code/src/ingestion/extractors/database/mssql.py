"""SQL Server errorlog extraction (``db_mssql``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_space_iso_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<spid>spid\d+)\s+(?P<msg>.+)"
)
USER = re.compile(r"user '([^']+)'", re.IGNORECASE)
CLIENT = re.compile(r"client (\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
DATABASE = re.compile(r"database '([^']+)'", re.IGNORECASE)


def _classify(msg: str) -> str:
    lowered = msg.lower()
    if "query_time" in lowered or "slow query" in lowered:
        return "slow"
    if "rpc:completed" in lowered or "stored proc" in lowered or "procedure" in lowered:
        return "procedure"
    if "create table" in lowered or "alter " in lowered or "drop " in lowered:
        return "ddl"
    if "audit" in lowered:
        return "audit"
    if "checkpoint" in lowered:
        return "wal"
    if "replica" in lowered or "mirroring" in lowered or "always on" in lowered:
        return "replication"
    if "login succeeded" in lowered or "logout" in lowered or "login failed" in lowered:
        return "session"
    if "backup" in lowered or "restore" in lowered:
        return "backup"
    if "statement:" in lowered:
        return "query"
    return "query"


def extract_mssql(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from SQL Server errorlog text."""
    del default_year, year_state, year_policy
    match = LINE.match(line.strip())
    if match is None:
        return build_database_extraction_result(
            event_class="query",
            service="mssql",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no mssql entity extracted",
        )
    msg = match.group("msg")
    user_match = USER.search(msg)
    client = CLIENT.search(msg)
    db_match = DATABASE.search(msg)
    extra = {"spid": match.group("spid")}
    event_timestamp = parse_space_iso_timestamp(match.group("ts"))
    return build_database_extraction_result(
        event_class=_classify(msg),
        username=user_match.group(1) if user_match else "",
        src_ip=client.group(1) if client else "",
        service=db_match.group(1) if db_match else "mssql",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no mssql entity extracted",
    )
