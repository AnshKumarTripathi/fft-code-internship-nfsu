"""Config-management extraction (``config_mgmt``) — Ansible, Puppet, Chef."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    build_virt_extraction_result,
    extract_syslog_virt_line,
    normalize_username,
    parse_iso_datetime,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

USER = re.compile(r"\b(?:user|USER|owner)[=:\s]+(?P<user>[\w.-]+)", re.IGNORECASE)
HOST = re.compile(
    r"\b(?:on|host|ok:|changed:|failed:)[=:\s]+\[?(?P<host>[\w.-]+)\]?",
    re.IGNORECASE,
)
PLAY = re.compile(r"TASK \[(?P<task>[^\]]+)\]|PLAY \[(?P<play>[^\]]+)\]")
ISO_LEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
PRODUCT = re.compile(r"\b(?P<product>ansible-playbook|puppet-agent|Chef Client|puppet|chef)\b", re.IGNORECASE)


def extract_config_mgmt(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from Ansible recap, Puppet report, or Chef client logs."""
    user_match = USER.search(line)
    username = normalize_username(user_match.group("user") if user_match else "")
    extra: dict[str, str] = {}
    product = PRODUCT.search(line)
    if product:
        extra["product"] = product.group("product").lower()
    play = PLAY.search(line)
    if play:
        extra["task"] = (play.group("task") or play.group("play") or "").strip()
    hostname, program, pid = parse_syslog_fields(line)
    host_match = HOST.search(line)
    named_host = host_match.group("host") if host_match else ""
    if named_host in {"ok", "changed", "failed", "unreachable", "skipped"}:
        named_host = ""
    if hostname:
        if program:
            extra["program"] = program
        if pid:
            extra["pid"] = pid
        return extract_syslog_virt_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no config_mgmt entity extracted",
        )
    iso = ISO_LEAD.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    return build_virt_extraction_result(
        username=username,
        hostname=named_host or extra.get("product") or "config_mgmt",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no config_mgmt entity extracted",
    )
