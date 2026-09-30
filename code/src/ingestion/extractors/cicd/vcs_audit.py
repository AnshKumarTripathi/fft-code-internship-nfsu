"""VCS server audit extraction (``vcs_audit``)."""

from __future__ import annotations

from src.ingestion.extractors.cicd.common import (
    FROM_IP,
    GIT_USER,
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    canonical_src_ip,
    extract_syslog_cicd_line,
    json_username,
    parse_cicd_json_timestamp,
    parse_json_object,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_vcs_audit(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract git user / JSON author and IP from VCS audit lines."""
    obj = parse_json_object(line)
    if obj is not None:
        username = json_username(obj)
        src_ip = canonical_src_ip(
            str(obj.get("ip") or obj.get("client_ip") or obj.get("src_ip") or "")
        )
        extra: dict[str, str] = {}
        action = str(obj.get("action") or "")
        if action:
            extra["action"] = action
        repo = str(obj.get("repo") or obj.get("repository") or "")
        if repo:
            extra["job"] = repo
        event_timestamp = parse_cicd_json_timestamp(obj)
        return build_cicd_extraction_result(
            username=username,
            src_ip=src_ip,
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no vcs_audit JSON entity extracted",
        )
    git_user = GIT_USER.search(line)
    username = git_user.group("user") if git_user else ""
    ip_match = FROM_IP.search(line)
    src_ip = ip_match.group("ip") if ip_match else ""
    hostname, _program, _pid = parse_syslog_fields(line)
    extra = {"action": "received-pack"}
    if hostname:
        return extract_syslog_cicd_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            src_ip=src_ip,
            extra_fields=extra,
            no_match_reason="no vcs_audit entity extracted",
        )
    return build_cicd_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no vcs_audit entity extracted",
    )
