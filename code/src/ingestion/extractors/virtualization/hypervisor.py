"""Hypervisor extraction (``hypervisor``) — ESXi/vCenter, Hyper-V, KVM/libvirt."""

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

USER = re.compile(r"\b(?:user|User|TargetUserName)=(?P<user>\S+)", re.IGNORECASE)
USER_WORD = re.compile(r"\buser\s+(?P<user>\S+)", re.IGNORECASE)
HOST = re.compile(
    r"\b(?:host|Computer|hostname)=(?P<host>\S+)",
    re.IGNORECASE,
)
VM = re.compile(r"\b(?:vm|VM|Domain)\s*[=:]?\s*'?(?P<vm>[\w.-]+)'?", re.IGNORECASE)
ISO_LEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
TIMECREATED = re.compile(
    r"TimeCreated=(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)",
    re.IGNORECASE,
)


def extract_hypervisor(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from ESXi, Hyper-V, or libvirt lines."""
    user_match = USER.search(line) or USER_WORD.search(line)
    username = normalize_username(user_match.group("user") if user_match else "")
    host_match = HOST.search(line)
    extra: dict[str, str] = {}
    vm_match = VM.search(line)
    if vm_match:
        extra["vm"] = vm_match.group("vm")
    syslog_host, program, pid = parse_syslog_fields(line)
    named_host = host_match.group("host").strip(",") if host_match else ""
    if syslog_host:
        return extract_syslog_virt_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no hypervisor entity extracted",
        )
    if program:
        extra["program"] = program
    if pid:
        extra["pid"] = pid
    iso = ISO_LEAD.match(line.strip())
    event_timestamp = parse_iso_datetime(iso.group("ts")) if iso else None
    if event_timestamp is None:
        created = TIMECREATED.search(line)
        if created:
            event_timestamp = parse_iso_datetime(created.group("ts"))
    return build_virt_extraction_result(
        username=username,
        hostname=named_host or extra.get("vm") or "hypervisor",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no hypervisor entity extracted",
    )
