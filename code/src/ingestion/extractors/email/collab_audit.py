"""Slack / Teams / Zoom collaboration audit extraction (``collab_audit``)."""

from __future__ import annotations

from src.ingestion.extractors.email.common import (
    YEAR_POLICY_CARRY,
    build_email_extraction_result,
    canonical_src_ip,
    nested_str,
    normalize_username,
    parse_email_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_collab_audit(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract actor and IP from Slack/Teams/Zoom audit JSON. No syslog carry."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_email_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no collab_audit JSON object",
        )
    username = normalize_username(
        str(
            obj.get("actor")
            or obj.get("user")
            or obj.get("username")
            or nested_str(obj, "actor", "name")
            or ""
        )
    )
    src_ip = canonical_src_ip(
        str(obj.get("ip") or obj.get("client_ip") or obj.get("src_ip") or "")
    )
    extra: dict[str, str] = {}
    platform = str(obj.get("platform") or "")
    if platform:
        extra["platform"] = platform.lower()
    action = str(obj.get("action") or "")
    if action:
        extra["action"] = action
    workspace = str(obj.get("workspace") or "")
    if workspace:
        extra["workspace"] = workspace
    event_timestamp = parse_email_json_timestamp(obj)
    return build_email_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no collab_audit entity extracted",
    )
