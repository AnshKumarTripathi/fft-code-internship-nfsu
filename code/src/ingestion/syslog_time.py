"""Parse classic syslog timestamps and apply year-carry across Dec→Jan wraps.

Syslog lines often omit the year. ``file_mtime`` (v1) stamps every line with the
source file mtime year. ``carry`` walks lines in file order and increments the
year when month goes from December to January.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

YEAR_POLICY_CARRY = "carry"
YEAR_POLICY_FILE_MTIME = "file_mtime"
YEAR_POLICIES = frozenset({YEAR_POLICY_CARRY, YEAR_POLICY_FILE_MTIME})

# Optional year: "2024 Jan  5 12:34:56" or "Jan  5 12:34:56" / "Jan 5 12:34:56"
SYSLOG_TS = re.compile(
    r"^(?:(?P<year>\d{4})\s+)?"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class SyslogYearState:
    """Per-source-file year cursor for the carry policy.

    ``zeek_fields`` / ``pfirewall_fields`` hold the latest ``#fields`` /
    ``#Fields`` column lists for Zeek (Phase 83) and classic pfirewall
    (Phase 85); unused for other families.
    """

    year: int
    prev_month: int | None = None
    warned_backward_jump: bool = False
    zeek_fields: list[str] | None = None
    pfirewall_fields: list[str] | None = None


def advance_syslog_year(prev_month: int | None, month: int, year: int) -> int:
    """Return ``year`` or ``year + 1`` on a December → January wrap."""
    if prev_month is not None and prev_month == 12 and month == 1:
        return year + 1
    return year


def parse_syslog_timestamp(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> tuple[datetime | None, bool]:
    """Parse a syslog wall-clock as UTC.

    Invalid calendar dates (including leap-year failures) return ``(None, False)``.
    When ``year_state`` is provided, month/year cursors are updated in place.
    """
    match = SYSLOG_TS.match(line.strip())
    if not match:
        return None, False

    month = MONTHS[match.group("month")]
    explicit_year = match.group("year")
    if explicit_year is not None:
        year = int(explicit_year)
    elif year_policy == YEAR_POLICY_CARRY and year_state is not None:
        year = advance_syslog_year(year_state.prev_month, month, year_state.year)
    else:
        year = year_state.year if year_state is not None else default_year

    if (
        year_state is not None
        and year_policy == YEAR_POLICY_CARRY
        and not year_state.warned_backward_jump
        and year_state.prev_month is not None
        and explicit_year is None
        and not (year_state.prev_month == 12 and month == 1)
        and year_state.prev_month - month >= 2
    ):
        logger.warning(
            "syslog month jumped backward from %s to %s without Dec→Jan wrap; "
            "keeping year %s",
            year_state.prev_month,
            month,
            year,
        )
        year_state.warned_backward_jump = True

    day = int(match.group("day"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        parsed = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None, False

    if year_state is not None:
        year_state.year = year
        year_state.prev_month = month
    return parsed, True
