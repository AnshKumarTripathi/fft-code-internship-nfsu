"""Windows Event Log family extractors (Phase 20)."""

from src.ingestion.extractors.windows.ad import extract_windows_ad
from src.ingestion.extractors.windows.application import extract_windows_application
from src.ingestion.extractors.windows.bitlocker import extract_windows_bitlocker
from src.ingestion.extractors.windows.defender import extract_windows_defender
from src.ingestion.extractors.windows.firewall import extract_windows_firewall
from src.ingestion.extractors.windows.forwarded import extract_windows_forwarded
from src.ingestion.extractors.windows.gpo import extract_windows_gpo
from src.ingestion.extractors.windows.pfirewall import extract_windows_pfirewall
from src.ingestion.extractors.windows.powershell import extract_windows_powershell
from src.ingestion.extractors.windows.print_service import extract_windows_print
from src.ingestion.extractors.windows.rdp import extract_windows_rdp
from src.ingestion.extractors.windows.security import extract_windows_security
from src.ingestion.extractors.windows.setup import extract_windows_setup
from src.ingestion.extractors.windows.system import extract_windows_system
from src.ingestion.extractors.windows.task_scheduler import extract_windows_task_scheduler
from src.ingestion.extractors.windows.wmi import extract_windows_wmi
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

WINDOWS_LOG_SOURCES = frozenset(
    {
        "windows_security",
        "windows_system",
        "windows_application",
        "windows_setup",
        "windows_forwarded",
        "windows_powershell",
        "windows_defender",
        "windows_task_scheduler",
        "windows_wmi",
        "windows_gpo",
        "windows_print",
        "windows_firewall",
        "windows_pfirewall",
        "windows_bitlocker",
        "windows_rdp",
        "windows_ad",
    }
)

_EXTRACTORS = {
    "windows_security": extract_windows_security,
    "windows_system": extract_windows_system,
    "windows_application": extract_windows_application,
    "windows_setup": extract_windows_setup,
    "windows_forwarded": extract_windows_forwarded,
    "windows_powershell": extract_windows_powershell,
    "windows_defender": extract_windows_defender,
    "windows_task_scheduler": extract_windows_task_scheduler,
    "windows_wmi": extract_windows_wmi,
    "windows_gpo": extract_windows_gpo,
    "windows_print": extract_windows_print,
    "windows_firewall": extract_windows_firewall,
    "windows_bitlocker": extract_windows_bitlocker,
    "windows_rdp": extract_windows_rdp,
    "windows_ad": extract_windows_ad,
}

__all__ = [
    "WINDOWS_LOG_SOURCES",
    "extract_windows_family",
]


def extract_windows_family(
    line: str,
    log_source: str,
    *,
    default_year: int = 0,
    year_state: object | None = None,
    year_policy: str = "",
) -> ExtractionResult:
    """Dispatch a windows_* log_source.

    Event Log extractors ignore syslog year-carry. Classic ``pfirewall.log``
    uses ``year_state.pfirewall_fields`` for ``#Fields`` (Phase 85).
    """
    del default_year, year_policy
    if log_source == "windows_pfirewall":
        state = year_state if isinstance(year_state, SyslogYearState) else None
        return extract_windows_pfirewall(line, year_state=state)
    extractor = _EXTRACTORS.get(log_source)
    if extractor is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason=f"unsupported windows log_source: {log_source}",
        )
    return extractor(line)
