"""Unix OS + macOS family extractors (Phase 21)."""

from src.ingestion.extractors.unix_os.auditd import extract_linux_auditd
from src.ingestion.extractors.unix_os.boot import extract_linux_boot
from src.ingestion.extractors.unix_os.cron import extract_linux_cron
from src.ingestion.extractors.unix_os.dmesg import extract_linux_dmesg
from src.ingestion.extractors.unix_os.journald import extract_linux_journald
from src.ingestion.extractors.unix_os.kern import extract_linux_kern
from src.ingestion.extractors.unix_os.mac import extract_linux_mac
from src.ingestion.extractors.unix_os.macos_asl import extract_macos_asl
from src.ingestion.extractors.unix_os.macos_install import extract_macos_install
from src.ingestion.extractors.unix_os.macos_unified import extract_macos_unified
from src.ingestion.extractors.unix_os.package import extract_linux_package
from src.ingestion.extractors.unix_os.syslog import extract_linux_syslog
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

UNIX_OS_LOG_SOURCES = frozenset(
    {
        "linux_syslog",
        "linux_kern",
        "linux_dmesg",
        "linux_journald",
        "linux_cron",
        "linux_package",
        "linux_auditd",
        "linux_boot",
        "linux_mac",
        "macos_unified",
        "macos_asl",
        "macos_install",
    }
)

_EXTRACTORS = {
    "linux_syslog": extract_linux_syslog,
    "linux_kern": extract_linux_kern,
    "linux_dmesg": extract_linux_dmesg,
    "linux_journald": extract_linux_journald,
    "linux_cron": extract_linux_cron,
    "linux_package": extract_linux_package,
    "linux_auditd": extract_linux_auditd,
    "linux_boot": extract_linux_boot,
    "linux_mac": extract_linux_mac,
    "macos_unified": extract_macos_unified,
    "macos_asl": extract_macos_asl,
    "macos_install": extract_macos_install,
}

__all__ = [
    "UNIX_OS_LOG_SOURCES",
    "extract_unix_os_family",
]


def extract_unix_os_family(
    line: str,
    log_source: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch a unix_os / macOS ``log_source`` to its extractor."""
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported unix_os log_source: {log_source}",
        )
    return extractor(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
