"""Package manager / dependency-resolution extraction (``package_resolve``)."""

from __future__ import annotations

from src.ingestion.extractors.cicd.common import (
    YEAR_POLICY_CARRY,
    build_cicd_extraction_result,
    extract_syslog_cicd_line,
    parse_syslog_fields,
)
from src.ingestion.extractors.cicd.markers import MAVEN, NPM, PIP
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_package_resolve(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/service from npm, pip, or Maven resolve lines."""
    manager = "package"
    if NPM.search(line):
        manager = "npm"
    elif PIP.search(line):
        manager = "pip"
    elif MAVEN.search(line):
        manager = "maven"
    hostname, _program, _pid = parse_syslog_fields(line)
    extra = {"platform": manager}
    if hostname:
        return extract_syslog_cicd_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            service=manager,
            extra_fields=extra,
            no_match_reason="no package_resolve entity extracted",
        )
    return build_cicd_extraction_result(
        service=manager,
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no package_resolve entity extracted",
    )
