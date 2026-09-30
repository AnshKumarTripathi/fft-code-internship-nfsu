"""Airflow / enterprise scheduler extraction (``airflow``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.middleware.common import (
    YEAR_POLICY_CARRY,
    build_middleware_extraction_result,
    extract_syslog_middleware_line,
    parse_bracket_or_space_timestamp,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

DAG = re.compile(
    r"\b(?:DAG(?:_ID)?|dag_id)[=:\s]+(?P<dag>[\w.-]+)",
    re.IGNORECASE,
)
TASK = re.compile(
    r"\b(?:Task(?:_ID)?|task_id)[=:\s]+(?P<task>[\w.-]+)",
    re.IGNORECASE,
)
OWNER = re.compile(
    r"\b(?:owner|user)[=:\s]+(?P<user>[\w.-]+)",
    re.IGNORECASE,
)
DAG_PATH = re.compile(r"dag_id=(?P<dag>[\w.-]+)", re.IGNORECASE)


def extract_airflow(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user or DAG service from Airflow task / scheduler logs."""
    dag_match = DAG.search(line) or DAG_PATH.search(line)
    dag = dag_match.group("dag") if dag_match else ""
    task_match = TASK.search(line)
    extra: dict[str, str] = {}
    if dag:
        extra["dag"] = dag
    if task_match:
        extra["task"] = task_match.group("task")
    owner_match = OWNER.search(line)
    username = owner_match.group("user") if owner_match else ""
    service = dag or "airflow"
    hostname, program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_middleware_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            service=service,
            extra_fields=extra,
            no_match_reason="no airflow entity extracted",
        )
    if program:
        extra["program"] = program
    event_timestamp = parse_bracket_or_space_timestamp(line)
    return build_middleware_extraction_result(
        username=username,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no airflow entity extracted",
    )
