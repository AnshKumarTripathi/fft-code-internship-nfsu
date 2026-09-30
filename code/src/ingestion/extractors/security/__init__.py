"""Security appliance family extractors (Phase 24)."""

from src.ingestion.extractors.security.antivirus import extract_antivirus
from src.ingestion.extractors.security.cef import extract_cef
from src.ingestion.extractors.security.dlp import extract_dlp
from src.ingestion.extractors.security.edr import extract_edr
from src.ingestion.extractors.security.honeypot import extract_honeypot
from src.ingestion.extractors.security.ids_ips import extract_ids_ips
from src.ingestion.extractors.security.sandbox import extract_sandbox
from src.ingestion.extractors.security.siem import extract_siem
from src.ingestion.extractors.security.threat_intel import extract_threat_intel
from src.ingestion.extractors.security.vuln_scanner import extract_vuln_scanner
from src.ingestion.extractors.security.waf import extract_waf
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

SECURITY_LOG_SOURCES = frozenset(
    {
        "ids_ips",
        "waf",
        "dlp",
        "edr",
        "antivirus",
        "vuln_scanner",
        "siem",
        "honeypot",
        "sandbox",
        "threat_intel",
        "cef",
    }
)

_EXTRACTORS = {
    "ids_ips": extract_ids_ips,
    "waf": extract_waf,
    "dlp": extract_dlp,
    "edr": extract_edr,
    "antivirus": extract_antivirus,
    "vuln_scanner": extract_vuln_scanner,
    "siem": extract_siem,
    "honeypot": extract_honeypot,
    "sandbox": extract_sandbox,
    "threat_intel": extract_threat_intel,
    "cef": extract_cef,
}

__all__ = [
    "SECURITY_LOG_SOURCES",
    "extract_security_family",
]


def extract_security_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a security ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported security log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
