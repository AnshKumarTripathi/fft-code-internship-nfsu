"""PostgreSQL stderr extraction (``db_postgres``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_space_iso_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\S+\s+"
    r"\[(?P<pid>\d+)\](?:\s+(?P<user>[^@\s]+)@(?P<db>\S+))?\s+"
    r"(?P<level>\w+):\s+(?P<msg>.+)"
)
DURATION = re.compile(r"duration:\s+(?P<ms>[\d.]+)\s+ms", re.IGNORECASE)


def _classify(msg: str) -> str:
    lowered = msg.lower()
    if "duration:" in lowered and "statement:" in lowered:
        return "slow"
    if re.search(r"\bstatement:\s+call\b", lowered):
        return "procedure"
    if re.search(r"\bstatement:\s+(?:create|alter|drop|grant|revoke)\b", lowered):
        return "ddl"
    if "connection authorized" in lowered or lowered.startswith("audit:"):
        return "audit"
    if "checkpoint" in lowered or re.search(r"\bredo\b", lowered):
        return "wal"
    if "wal receiver" in lowered or "walsender" in lowered or "logical replication" in lowered:
        return "replication"
    if "connection received" in lowered or "disconnection:" in lowered:
        return "session"
    if "pg_basebackup" in lowered or "base backup" in lowered:
        return "backup"
    if "statement:" in lowered or lowered.startswith("execute "):
        return "query"
    return "query"


def extract_postgres(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from PostgreSQL stderr log_line_prefix lines."""
    del default_year, year_state, year_policy
    match = LINE.match(line.strip())
    if match is None:
        return build_database_extraction_result(
            event_class="query",
            service="postgres",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no postgres entity extracted",
        )
    msg = match.group("msg")
    extra: dict[str, str] = {"pid": match.group("pid"), "level": match.group("level")}
    duration = DURATION.search(msg)
    if duration:
        extra["duration_ms"] = duration.group("ms")
    event_timestamp = parse_space_iso_timestamp(match.group("ts"))
    return build_database_extraction_result(
        event_class=_classify(msg),
        username=match.group("user") or "",
        service=match.group("db") or "postgres",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no postgres entity extracted",
    )
