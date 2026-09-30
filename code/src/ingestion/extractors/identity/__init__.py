"""Identity family extractors (Phase 22)."""

from src.ingestion.extractors.identity.idp import extract_idp
from src.ingestion.extractors.identity.kerberos_kdc import extract_kerberos_kdc
from src.ingestion.extractors.identity.ldap import extract_ldap
from src.ingestion.extractors.identity.mfa import extract_mfa
from src.ingestion.extractors.identity.radius import extract_radius
from src.ingestion.extractors.identity.vault import extract_vault
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

IDENTITY_LOG_SOURCES = frozenset(
    {
        "ldap",
        "radius",
        "idp",
        "mfa",
        "kerberos_kdc",
        "vault",
    }
)

_EXTRACTORS = {
    "ldap": extract_ldap,
    "radius": extract_radius,
    "idp": extract_idp,
    "mfa": extract_mfa,
    "kerberos_kdc": extract_kerberos_kdc,
    "vault": extract_vault,
}

__all__ = [
    "IDENTITY_LOG_SOURCES",
    "extract_identity_family",
]


def extract_identity_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch an identity ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported identity log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
