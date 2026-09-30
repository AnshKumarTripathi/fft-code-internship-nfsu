"""GCP IAM policy-change extraction (``gcp_iam``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.gcp_audit import extract_gcp_audit
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_gcp_iam(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Same Cloud Audit parser with ``event_class=iam`` and ``log_source=gcp_iam``."""
    return extract_gcp_audit(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        event_class="iam",
    )
