"""Email family extractors (Phase 29)."""

from src.ingestion.extractors.email.collab_audit import extract_collab_audit
from src.ingestion.extractors.email.dmarc import extract_dmarc
from src.ingestion.extractors.email.mail_gateway import extract_mail_gateway
from src.ingestion.extractors.email.mta import extract_mta
from src.ingestion.extractors.email.smtp import extract_smtp
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

EMAIL_LOG_SOURCES = frozenset(
    {
        "smtp",
        "mail_gateway",
        "mta",
        "dmarc",
        "collab_audit",
    }
)

_EXTRACTORS = {
    "smtp": extract_smtp,
    "mail_gateway": extract_mail_gateway,
    "mta": extract_mta,
    "dmarc": extract_dmarc,
    "collab_audit": extract_collab_audit,
}

__all__ = [
    "EMAIL_LOG_SOURCES",
    "extract_email_family",
]


def extract_email_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch an email ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported email log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
