"""PKI / cryptographic family extractors (Phase 35)."""

from src.ingestion.extractors.pki.ca import extract_pki_ca
from src.ingestion.extractors.pki.code_signing import extract_code_signing
from src.ingestion.extractors.pki.ct_log import extract_ct_log
from src.ingestion.extractors.pki.hsm import extract_hsm
from src.ingestion.extractors.pki.tls import extract_tls
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

PKI_LOG_SOURCES = frozenset(
    {
        "pki_ca",
        "hsm",
        "tls",
        "ct_log",
        "code_signing",
    }
)

_EXTRACTORS = {
    "pki_ca": extract_pki_ca,
    "hsm": extract_hsm,
    "tls": extract_tls,
    "ct_log": extract_ct_log,
    "code_signing": extract_code_signing,
}

__all__ = [
    "PKI_LOG_SOURCES",
    "extract_pki_family",
]


def extract_pki_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a PKI ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported pki log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
