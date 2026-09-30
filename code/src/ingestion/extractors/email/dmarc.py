"""DKIM / SPF / DMARC extraction (``dmarc``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.email.common import (
    CHECK_RESULT,
    YEAR_POLICY_CARRY,
    extract_syslog_mail_line,
    first_bracket_ip,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

_DOMAIN = re.compile(r"\b(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")


def extract_dmarc(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/IP and pass/fail from OpenDMARC / OpenDKIM syslog."""
    extra: dict[str, str] = {}
    result = CHECK_RESULT.search(line)
    if result:
        extra["check_result"] = result.group("result").lower()
    domain_match = _DOMAIN.search(line)
    if domain_match:
        extra["domain"] = domain_match.group("domain")
    return extract_syslog_mail_line(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        src_ip=first_bracket_ip(line),
        extra_fields=extra,
        no_match_reason="no dmarc entity extracted",
    )
