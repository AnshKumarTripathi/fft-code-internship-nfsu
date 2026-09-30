"""Virtualization family extractors (Phase 32)."""

from src.ingestion.extractors.virtualization.backup import extract_backup
from src.ingestion.extractors.virtualization.config_mgmt import extract_config_mgmt
from src.ingestion.extractors.virtualization.hypervisor import extract_hypervisor
from src.ingestion.extractors.virtualization.iac import extract_iac
from src.ingestion.extractors.virtualization.license import extract_license
from src.ingestion.extractors.virtualization.ntp import extract_ntp
from src.ingestion.extractors.virtualization.san import extract_san
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

VIRTUALIZATION_LOG_SOURCES = frozenset(
    {
        "hypervisor",
        "san",
        "backup",
        "ntp",
        "license",
        "config_mgmt",
        "iac",
    }
)

_EXTRACTORS = {
    "hypervisor": extract_hypervisor,
    "san": extract_san,
    "backup": extract_backup,
    "ntp": extract_ntp,
    "license": extract_license,
    "config_mgmt": extract_config_mgmt,
    "iac": extract_iac,
}

__all__ = [
    "VIRTUALIZATION_LOG_SOURCES",
    "extract_virtualization_family",
]


def extract_virtualization_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a virtualization ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported virtualization log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
