"""SMTP send/receive/relay extraction (``smtp``)."""

from __future__ import annotations

from src.ingestion.extractors.email.common import (
    FROM_ANGLE,
    QUEUE_ID,
    SASL_FAIL,
    SASL_USER,
    TO_ANGLE,
    YEAR_POLICY_CARRY,
    envelope_address,
    extract_syslog_mail_line,
    first_bracket_ip,
    normalize_auth_result,
    normalize_username,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState


def extract_smtp(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP and SASL user from Postfix smtpd/smtp or sendmail."""
    sasl = SASL_USER.search(line)
    username = normalize_username(sasl.group("user") if sasl else "")
    if not username:
        username = envelope_address(line, FROM_ANGLE)
    if not username:
        username = envelope_address(line, TO_ANGLE)
    src_ip = first_bracket_ip(line)
    extra: dict[str, str] = {}
    queue = QUEUE_ID.search(line)
    if queue:
        extra["queue_id"] = queue.group("qid")
    sasl_failed = SASL_FAIL.search(line) is not None
    if sasl or sasl_failed:
        extra["auth_result"] = "failure" if sasl_failed else normalize_auth_result("success")
    return extract_syslog_mail_line(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        no_match_reason="no smtp entity extracted",
    )
