"""NTP synchronization extraction (``ntp``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.virtualization.common import (
    YEAR_POLICY_CARRY,
    extract_syslog_virt_line,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

PEER = re.compile(
    r"\b(?:synchronized to|Selected source|peer)\s+(?P<peer>\S+)",
    re.IGNORECASE,
)


def extract_ntp(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host from ntpd / chronyd syslog."""
    extra: dict[str, str] = {}
    peer = PEER.search(line)
    if peer:
        extra["peer"] = peer.group("peer")
    return extract_syslog_virt_line(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        extra_fields=extra,
        no_match_reason="no ntp entity extracted",
    )
