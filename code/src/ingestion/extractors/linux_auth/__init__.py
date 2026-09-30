"""Linux auth family extractors (PAM, auth.log, wtmp)."""

from src.ingestion.extractors.linux_auth.authlog import extract_linux_authlog
from src.ingestion.extractors.linux_auth.pam import extract_linux_pam
from src.ingestion.extractors.linux_auth.wtmp import extract_linux_wtmp
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

__all__ = [
    "extract_linux_auth_family",
    "extract_linux_authlog",
    "extract_linux_pam",
    "extract_linux_wtmp",
]


def extract_linux_auth_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a Linux-auth ``log_source`` to its extractor."""
    kwargs = {
        "default_year": default_year,
        "year_state": year_state,
        "year_policy": year_policy,
    }
    if log_source == "linux_pam":
        return extract_linux_pam(line, **kwargs)
    if log_source == "linux_auth":
        return extract_linux_authlog(line, **kwargs)
    if log_source == "linux_wtmp":
        return extract_linux_wtmp(line, **kwargs)
    return ExtractionResult(
        extraction_ok=False,
        failure_reason=f"unsupported linux auth log_source: {log_source}",
    )
