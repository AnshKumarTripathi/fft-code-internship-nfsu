"""MongoDB JSON log extraction (``db_mongodb``)."""

from __future__ import annotations

from typing import Any

from src.ingestion.extractors.database.common import (
    build_database_extraction_result,
    parse_json_object,
    parse_mongo_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def _attr_blob(attr: dict[str, Any]) -> str:
    return str(attr).lower()


def _classify(component: str, msg: str, attr: dict[str, Any]) -> str:
    blob = f"{msg} {_attr_blob(attr)}".lower()
    if "slow query" in blob or "durationmillis" in blob or "slowms" in blob:
        return "slow"
    if "eval" in blob or "procedure" in blob:
        return "procedure"
    if any(token in blob for token in ("createindexes", "dropdatabase", "createcollection")):
        return "ddl"
    if component == "ACCESS":
        return "audit"
    if component in {"STORAGE", "JOURNAL", "WT"} or "checkpoint" in blob:
        return "wal"
    if component == "REPL" or "replication" in blob:
        return "replication"
    if component == "NETWORK" or "connection" in blob:
        return "session"
    if "backup" in blob or "dump" in blob:
        return "backup"
    if component in {"COMMAND", "QUERY", "WRITE"}:
        return "query"
    return "query"


def extract_mongodb(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/database from MongoDB JSON logs. No syslog year-carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_database_extraction_result(
            event_class="query",
            service="mongodb",
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no mongodb entity extracted",
        )
    attr = obj.get("attr") if isinstance(obj.get("attr"), dict) else {}
    component = str(obj.get("c") or "")
    msg = str(obj.get("msg") or "")
    extra: dict[str, str] = {}
    if component:
        extra["component"] = component
    if obj.get("id") is not None:
        extra["mongo_id"] = str(obj.get("id"))
    username = str(attr.get("user") or obj.get("user") or "")
    database = str(attr.get("db") or attr.get("ns") or "mongodb")
    if "." in database and database != "mongodb":
        database = database.split(".", 1)[0]
    remote = str(attr.get("remote") or "")
    src_ip = remote.split(":")[0] if remote else ""
    event_timestamp = parse_mongo_timestamp(obj)
    return build_database_extraction_result(
        event_class=_classify(component.upper(), msg, attr),
        username=username,
        src_ip=src_ip,
        service=database or "mongodb",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no mongodb entity extracted",
    )
