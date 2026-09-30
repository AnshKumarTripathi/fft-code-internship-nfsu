"""Deployment / release extraction (``cicd_deploy``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.cicd.common import (
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    json_username,
    normalize_username,
    parse_cicd_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

_USER = re.compile(r"\buser[=:]\s*(?P<user>\S+)", re.IGNORECASE)
_SERVICE = re.compile(
    r"\b(?:service|app|environment)[=:]\s*(?P<svc>\S+)",
    re.IGNORECASE,
)


def extract_cicd_deploy(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/service from deploy JSON or deploy text. No syslog carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is not None:
        username = json_username(obj)
        service = str(obj.get("service") or obj.get("app") or obj.get("environment") or "")
        extra: dict[str, str] = {}
        event = str(obj.get("event") or obj.get("action") or "")
        if event:
            extra["action"] = event.lower()
        if service:
            extra["job"] = service
        event_timestamp = parse_cicd_json_timestamp(obj)
        return build_cicd_extraction_result(
            username=username,
            service=service or "deploy",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no cicd_deploy JSON entity extracted",
        )
    user_match = _USER.search(line)
    svc_match = _SERVICE.search(line)
    username = normalize_username(user_match.group("user") if user_match else "")
    service = svc_match.group("svc") if svc_match else "deploy"
    return build_cicd_extraction_result(
        username=username,
        service=service,
        extra_fields={"action": "deploy"},
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no cicd_deploy entity extracted",
    )
