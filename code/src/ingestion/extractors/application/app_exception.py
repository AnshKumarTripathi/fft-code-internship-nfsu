"""Python/Java traceback-header extraction (``app_exception``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.application.common import (
    build_application_extraction_result,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_TRACEBACK = re.compile(r"Traceback \(most recent call last\):")
_JAVA = re.compile(
    r"Exception in thread |[a-z][a-z0-9_.]+\.[A-Za-z]+(?:Error|Exception)"
)
_LEADING_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z)?)"
)
_SERVICE = re.compile(r"\[(?P<svc>[A-Za-z0-9._-]+)\]")


def extract_app_exception(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract service/host from a traceback header. Continuation lines fail."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    if not (_TRACEBACK.search(stripped) or _JAVA.search(stripped)):
        return build_application_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no app_exception header",
        )
    extra: dict[str, str] = {"event_class": "exception"}
    service = ""
    svc = _SERVICE.search(stripped)
    if svc:
        service = svc.group("svc")
        extra["service"] = service
    ts_match = _LEADING_TS.match(stripped)
    event_timestamp = None
    if ts_match:
        token = ts_match.group("ts").replace(",", ".")
        event_timestamp = parse_iso_datetime(token)
    if not service:
        service = "app"
    return build_application_extraction_result(
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no app_exception entity extracted",
    )
