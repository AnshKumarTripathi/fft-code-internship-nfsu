"""Mail gateway / anti-spam extraction (``mail_gateway``)."""

from __future__ import annotations

from src.ingestion.extractors.email.common import (
    ACTION_FIELD,
    FROM_ANGLE,
    SCORE_FIELD,
    USER_FIELD,
    YEAR_POLICY_CARRY,
    build_email_extraction_result,
    canonical_src_ip,
    envelope_address,
    extract_syslog_mail_line,
    first_bracket_ip,
    normalize_username,
    parse_email_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_mail_gateway(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract IP/user from rspamd/spamd syslog or gateway JSON."""
    obj = parse_json_object(line)
    if obj is not None:
        username = normalize_username(str(obj.get("user") or obj.get("username") or ""))
        if not username:
            username = normalize_username(str(obj.get("from") or ""))
        src_ip = canonical_src_ip(str(obj.get("ip") or obj.get("src_ip") or ""))
        extra: dict[str, str] = {}
        action = str(obj.get("action") or "")
        if action:
            extra["action"] = action
        score = obj.get("score")
        if score not in {None, ""}:
            extra["score"] = str(score)
        event_timestamp = parse_email_json_timestamp(obj)
        return build_email_extraction_result(
            username=username,
            src_ip=src_ip,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no mail_gateway JSON entity extracted",
        )
    username = ""
    user_match = USER_FIELD.search(line)
    if user_match:
        username = normalize_username(user_match.group("user"))
    if not username:
        username = envelope_address(line, FROM_ANGLE)
    extra = {}
    action_match = ACTION_FIELD.search(line)
    if action_match:
        extra["action"] = action_match.group("action").strip()
    score_match = SCORE_FIELD.search(line)
    if score_match:
        extra["score"] = score_match.group("score")
    return extract_syslog_mail_line(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        username=username,
        src_ip=first_bracket_ip(line),
        extra_fields=extra,
        no_match_reason="no mail_gateway entity extracted",
    )
