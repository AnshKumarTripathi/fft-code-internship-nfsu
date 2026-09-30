"""dpkg.log package extraction (``linux_package``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.unix_os.common import build_unix_extraction_result
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

DPKG_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<action>install|remove|status|configure|upgrade)\s+"
    r"(?P<rest>.+)$"
)


def extract_linux_package(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host-level package events from dpkg.log. No syslog carry."""
    del default_year, year_state, year_policy
    match = DPKG_LINE.match(line.strip())
    event_timestamp = None
    ts_ok = False
    action = ""
    rest = ""
    if match:
        try:
            event_timestamp = datetime.strptime(
                match.group("ts"), "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            ts_ok = True
        except ValueError:
            ts_ok = False
        action = match.group("action")
        rest = match.group("rest")
    extra: dict[str, str] = {}
    if action:
        extra["package_action"] = action
    package = rest.split()[0] if rest else ""
    if package:
        extra["package"] = package
    return build_unix_extraction_result(
        hostname="",
        program="dpkg",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_package entity extracted",
    )
