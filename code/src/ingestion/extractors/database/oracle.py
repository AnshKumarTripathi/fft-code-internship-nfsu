"""Oracle alert-log extraction (``db_oracle``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_oracle_alert_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

USER = re.compile(r"\buser[=\s]+([A-Za-z0-9_$#]+)", re.IGNORECASE)
DATABASE = re.compile(r"\b(?:ON|database)\s+([A-Za-z0-9_$#.]+)", re.IGNORECASE)
ORA = re.compile(r"\b(ORA-\d{5})\b")


def _classify(line: str) -> str:
    lowered = line.lower()
    if "slow query" in lowered or "duration:" in lowered:
        return "slow"
    if "procedure" in lowered or " pl/sql " in lowered or "begin " in lowered:
        return "procedure"
    if re.search(r"\b(?:create|alter|drop|grant|revoke)\b", lowered):
        return "ddl"
    if "audit:" in lowered or "unified audit" in lowered:
        return "audit"
    if re.search(r"\barc\d:", lowered) or "redo" in lowered:
        return "wal"
    if "dataguard" in lowered or "replication" in lowered or "lgwr" in lowered:
        return "replication"
    if "starting oracle instance" in lowered or "logon" in lowered:
        return "session"
    if "rman-" in lowered or "backup" in lowered:
        return "backup"
    if "action: select" in lowered or "action: insert" in lowered:
        return "query"
    return "query"


def extract_oracle(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from Oracle alert-log text."""
    del default_year, year_state, year_policy
    extra: dict[str, str] = {}
    ora = ORA.search(line)
    if ora:
        extra["ora"] = ora.group(1)
    user_match = USER.search(line)
    db_match = DATABASE.search(line)
    event_timestamp = parse_oracle_alert_timestamp(line)
    service = "oracle"
    if db_match:
        token = db_match.group(1)
        if token.lower() not in {"oracle", "instance"}:
            service = token
    return build_database_extraction_result(
        event_class=_classify(line),
        username=user_match.group(1) if user_match else "",
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no oracle entity extracted",
    )
