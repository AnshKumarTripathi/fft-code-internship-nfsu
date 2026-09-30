"""SELinux / AppArmor denial extraction (``linux_mac``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

SCONTEXT = re.compile(r"scontext=(?P<ctx>\S+)")
APPARMOR_PROFILE = re.compile(r'apparmor="DENIED"[^;]*profile="(?P<profile>[^"]+)"')
PROFILE_ONLY = re.compile(r'profile="(?P<profile>[^"]+)"')
COMM = re.compile(r'comm="(?P<comm>[^"]+)"')


def extract_linux_mac(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/user from SELinux avc denied or AppArmor DENIED lines."""
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if pid:
        extra["pid"] = pid
    scontext = SCONTEXT.search(line)
    if scontext:
        extra["avc_scontext"] = scontext.group("ctx")
    apparmor = APPARMOR_PROFILE.search(line) or PROFILE_ONLY.search(line)
    if apparmor and 'apparmor="DENIED"' in line:
        extra["apparmor_profile"] = apparmor.group("profile")
    comm = COMM.search(line)
    if comm:
        extra["comm"] = comm.group("comm")
    return build_unix_extraction_result(
        username="",
        hostname=hostname,
        program=program or "kernel",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_mac entity extracted",
    )
