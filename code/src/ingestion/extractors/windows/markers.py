"""Content-first and filename routing for Windows Event Log families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.windows.common import (
    extract_channel,
    extract_provider,
    parse_event_id,
)
from src.ingestion.extractors.windows.pfirewall import looks_like_pfirewall

SECURITY_EVENT_IDS = frozenset(
    {4624, 4625, 4634, 4648, 4672, 4688, 4768, 4769, 4771, 4776}
)
POWERSHELL_EVENT_IDS = frozenset({4103, 4104})
DEFENDER_EVENT_IDS = frozenset({1116, 1117, 5001})
FIREWALL_EVENT_IDS = frozenset({5156, 5157, 2004, 2006})
SYSTEM_EVENT_IDS = frozenset({6005, 6006, 7036, 7045})
WMI_EVENT_IDS = frozenset({5857, 5858, 5859, 5860, 5861})
GPO_EVENT_IDS = frozenset(range(8001, 8017))
PRINT_EVENT_IDS = frozenset({307, 805})
BITLOCKER_EVENT_IDS = frozenset(range(768, 781))
RDP_STRONG_EVENT_IDS = frozenset({1149})
AD_EVENT_IDS = frozenset({2889, 1644, 1200, 1201, 501, 510})

_WINDOWS_HINT = re.compile(
    r"EventID\s*[=:]|Event\s*ID\s*[=:]|\bId\s*[=:]\s*\d+|TimeCreated\s*=|"
    r"<Event\s+xmlns|Microsoft-Windows-|\bLogName\s*=",
    re.IGNORECASE,
)
_TERMINAL_SERVICES = re.compile(r"TerminalServices", re.IGNORECASE)
_TRANSCRIPTION = re.compile(r"Transcription started", re.IGNORECASE)

_BASENAME_SOURCES = {
    "security.txt": "windows_security",
    "security.log": "windows_security",
    "system.txt": "windows_system",
    "application.txt": "windows_application",
    "setup.txt": "windows_setup",
    "setup.log": "windows_setup",
    "forwarded.txt": "windows_forwarded",
    "powershell.txt": "windows_powershell",
    "defender.txt": "windows_defender",
    "task_scheduler.txt": "windows_task_scheduler",
    "wmi.txt": "windows_wmi",
    "gpo.txt": "windows_gpo",
    "print.txt": "windows_print",
    "firewall.txt": "windows_firewall",
    "pfirewall.log": "windows_pfirewall",
    "pfirewall.txt": "windows_pfirewall",
    "bitlocker.txt": "windows_bitlocker",
    "rdp.txt": "windows_rdp",
    "ad.txt": "windows_ad",
}
_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("powershell", "windows_powershell"),
    ("defender", "windows_defender"),
    ("task_scheduler", "windows_task_scheduler"),
    ("taskschd", "windows_task_scheduler"),
    ("bitlocker", "windows_bitlocker"),
    ("directory_service", "windows_ad"),
    ("adfs", "windows_ad"),
    ("forwarded", "windows_forwarded"),
    ("grouppolicy", "windows_gpo"),
    ("windows_gpo", "windows_gpo"),
    ("print_service", "windows_print"),
    ("printservice", "windows_print"),
    ("windows_print", "windows_print"),
    ("windows_wmi", "windows_wmi"),
    ("wmi", "windows_wmi"),
    ("windows_rdp", "windows_rdp"),
    ("rdp", "windows_rdp"),
    ("terminalservices", "windows_rdp"),
    ("windows_application", "windows_application"),
    ("application.evtx", "windows_application"),
    ("windows_setup", "windows_setup"),
    ("setup.evtx", "windows_setup"),
    ("windows_system", "windows_system"),
    ("system.evtx", "windows_system"),
)


def looks_like_windows_line(line: str) -> bool:
    """Return True when the line has Windows Event Log markers (not SSH)."""
    return bool(line) and _WINDOWS_HINT.search(line) is not None


def detect_windows_log_source_from_line(line: str) -> str | None:
    """Return a windows_* source from channel/provider/EventID, else None."""
    if looks_like_pfirewall(line):
        return "windows_pfirewall"
    if not looks_like_windows_line(line) and not _TRANSCRIPTION.search(line):
        return None

    channel = extract_channel(line)
    provider = extract_provider(line)
    for token in (channel, provider):
        mapped = _source_from_channel_or_provider(token)
        if mapped:
            return mapped
    if _TERMINAL_SERVICES.search(line):
        return "windows_rdp"

    if _TRANSCRIPTION.search(line):
        return "windows_powershell"

    event_id = parse_event_id(line)
    if event_id is not None:
        mapped = _source_from_event_id(event_id, line)
        if mapped:
            return mapped
    return None


def detect_windows_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback tokens; do not steal generic firewall.log."""
    name = path.name.lower()
    if name in _BASENAME_SOURCES:
        if name == "firewall.txt":
            return "windows_firewall"
        return _BASENAME_SOURCES[name]
    if "pfirewall" in name:
        return "windows_pfirewall"
    if "firewall" in name:
        if any(token in name for token in ("windows", "wfp", "filtering")):
            return "windows_firewall"
        return None
    if "security.evtx" in name or name.startswith("security.") or "windows_security" in name:
        return "windows_security"
    if "system.evtx" in name or "windows_system" in name:
        return "windows_system"
    if "application.evtx" in name or "windows_application" in name:
        return "windows_application"
    if "setup.evtx" in name or "windows_setup" in name:
        return "windows_setup"
    if "gpo" in name:
        return "windows_gpo"
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None


def _source_from_channel_or_provider(token: str) -> str | None:
    if not token:
        return None
    lowered = token.lower().replace("\\", "/")
    if "forwardedevents" in lowered:
        return "windows_forwarded"
    if "terminalservices" in lowered or "terminal-services" in lowered:
        return "windows_rdp"
    if "powershell" in lowered:
        return "windows_powershell"
    if "defender" in lowered:
        return "windows_defender"
    if "taskscheduler" in lowered or "task scheduler" in lowered:
        return "windows_task_scheduler"
    if "wmi-activity" in lowered or "wmi/" in lowered:
        return "windows_wmi"
    if "grouppolicy" in lowered or "group-policy" in lowered:
        return "windows_gpo"
    if "printservice" in lowered or "print-service" in lowered:
        return "windows_print"
    if "filtering-platform" in lowered or "windows firewall" in lowered:
        return "windows_firewall"
    if "bitlocker" in lowered:
        return "windows_bitlocker"
    if "directory service" in lowered or "adfs" in lowered or "ad fs" in lowered:
        return "windows_ad"
    if lowered == "security" or lowered.endswith("/security") or "security-auditing" in lowered:
        return "windows_security"
    if lowered == "system" or lowered.endswith("/system"):
        return "windows_system"
    if lowered == "application" or lowered.endswith("/application"):
        return "windows_application"
    if lowered == "setup" or lowered.endswith("/setup"):
        return "windows_setup"
    return None


def _source_from_event_id(event_id: int, line: str) -> str | None:
    if event_id in SECURITY_EVENT_IDS:
        return "windows_security"
    if event_id in POWERSHELL_EVENT_IDS:
        return "windows_powershell"
    if event_id in DEFENDER_EVENT_IDS:
        return "windows_defender"
    if event_id in FIREWALL_EVENT_IDS:
        return "windows_firewall"
    if event_id in SYSTEM_EVENT_IDS:
        return "windows_system"
    if event_id in WMI_EVENT_IDS:
        return "windows_wmi"
    if event_id in GPO_EVENT_IDS:
        return "windows_gpo"
    if event_id in PRINT_EVENT_IDS:
        return "windows_print"
    if event_id in BITLOCKER_EVENT_IDS:
        return "windows_bitlocker"
    if event_id in AD_EVENT_IDS:
        return "windows_ad"
    if event_id in RDP_STRONG_EVENT_IDS:
        return "windows_rdp"
    if event_id in {21, 24, 25} and _TERMINAL_SERVICES.search(line):
        return "windows_rdp"
    return None
