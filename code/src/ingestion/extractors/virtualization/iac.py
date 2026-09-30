"""IaC apply extraction (``iac``) — Terraform plan/apply."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    build_virt_extraction_result,
    json_username,
    parse_iso_datetime,
    parse_json_object,
    parse_virt_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

USER = re.compile(r"\b(?:user|USER)[=:\s]+(?P<user>[\w.-]+)", re.IGNORECASE)
HOST = re.compile(r"\b(?:host|workspace)[=:\s]+(?P<host>[\w.-]+)", re.IGNORECASE)
APPLY = re.compile(
    r"Apply complete! Resources:\s*(?P<summary>.+)|Plan:\s*(?P<plan>.+)",
    re.IGNORECASE,
)
ISO_LEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def extract_iac(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/host from Terraform apply/plan text or JSON logs."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is not None:
        username = json_username(obj)
        hostname = str(obj.get("host") or obj.get("workspace") or "")
        extra: dict[str, str] = {"tool": "terraform"}
        message = str(obj.get("@message") or obj.get("message") or "")
        if message:
            extra["message"] = message[:200]
        event_timestamp = parse_virt_json_timestamp(obj)
        if event_timestamp is None:
            event_timestamp = parse_iso_datetime(str(obj.get("@timestamp") or ""))
        return build_virt_extraction_result(
            username=username,
            hostname=hostname or "terraform",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no iac JSON entity extracted",
        )
    extra = {"tool": "terraform"}
    apply = APPLY.search(line)
    if apply:
        extra["summary"] = (apply.group("summary") or apply.group("plan") or "").strip()
    user_match = USER.search(line)
    username = user_match.group("user") if user_match else ""
    host_match = HOST.search(line)
    hostname = host_match.group("host") if host_match else ""
    iso = ISO_LEAD.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    return build_virt_extraction_result(
        username=username,
        hostname=hostname or "terraform",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no iac entity extracted",
    )
