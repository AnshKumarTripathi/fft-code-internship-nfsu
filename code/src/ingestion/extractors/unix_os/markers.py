"""Content-first and filename routing for Unix OS and macOS families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.unix_os.common import is_rfc3164, is_rfc5424

_AUDIT = re.compile(
    r"\btype=(?:USER_AUTH|USER_LOGIN|SYSCALL)\b|\bmsg=audit\(",
    re.IGNORECASE,
)
_MAC = re.compile(r"avc:\s*denied|apparmor=\"DENIED\"", re.IGNORECASE)
_CRON = re.compile(r"\bCRON\[|\bcron\[", re.IGNORECASE)
_DPKG = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} "
    r"(?:install|remove|status|configure|upgrade)\b"
)
_JOURNAL_EXPORT = re.compile(r"\b_SYSTEMD_UNIT=|\b_COMM=", re.IGNORECASE)
_SYSTEMD_PROG = re.compile(r"\bsystemd\[", re.IGNORECASE)
_KERNEL_PROG = re.compile(r"\bkernel:|\bkernel\[", re.IGNORECASE)
_DMESG_UPTIME = re.compile(r"^\s*\[\s*\d+\.\d+\]")
_DMESG_T = re.compile(
    r"^\[\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
)
_DMESG_ISO = re.compile(r"^\[\d{4}-\d{2}-\d{2}T")
_BOOT = re.compile(r"\[\s*(?:OK|FAILED)\s*\]", re.IGNORECASE)
_MACOS_UNIFIED = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4}\s+0x[0-9a-fA-F]+"
)
_ASL = re.compile(r"\[Time\s+.+\].*\[Sender\s+", re.IGNORECASE)
_INSTALL = re.compile(
    r"PackageKit|\binstalld\[|Date/Time:|\bInstaller\[",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "syslog.txt": "linux_syslog",
    "syslog.log": "linux_syslog",
    "messages": "linux_syslog",
    "messages.log": "linux_syslog",
    "kern.txt": "linux_kern",
    "kern.log": "linux_kern",
    "dmesg.txt": "linux_dmesg",
    "dmesg.log": "linux_dmesg",
    "dmesg": "linux_dmesg",
    "journald.txt": "linux_journald",
    "journalctl.txt": "linux_journald",
    "cron.txt": "linux_cron",
    "cron.log": "linux_cron",
    "package.txt": "linux_package",
    "dpkg.log": "linux_package",
    "auditd.txt": "linux_auditd",
    "audit.log": "linux_auditd",
    "boot.txt": "linux_boot",
    "boot.log": "linux_boot",
    "mac.txt": "linux_mac",
    "macos_unified.txt": "macos_unified",
    "macos_asl.txt": "macos_asl",
    "macos_install.txt": "macos_install",
    "install.log": "macos_install",
    "asl.log": "macos_asl",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("journalctl", "linux_journald"),
    ("journald", "linux_journald"),
    ("dpkg.log", "linux_package"),
    ("auditd", "linux_auditd"),
    ("audit.log", "linux_auditd"),
    ("selinux", "linux_mac"),
    ("apparmor", "linux_mac"),
    ("log_show", "macos_unified"),
    ("macos_unified", "macos_unified"),
    ("DiagnosticReports", "macos_install"),
    ("install.log", "macos_install"),
    ("crash", "macos_install"),
    ("kern.log", "linux_kern"),
    ("dmesg", "linux_dmesg"),
    ("boot.log", "linux_boot"),
)


def detect_unix_os_log_source_from_line(line: str) -> str | None:
    """Return a unix/macOS source from strong content markers, else None."""
    if not line:
        return None
    if _AUDIT.search(line):
        return "linux_auditd"
    if _MAC.search(line):
        return "linux_mac"
    if _CRON.search(line):
        return "linux_cron"
    if _DPKG.match(line.strip()):
        return "linux_package"
    if _JOURNAL_EXPORT.search(line) or _SYSTEMD_PROG.search(line):
        return "linux_journald"
    if is_rfc3164(line) and _KERNEL_PROG.search(line):
        return "linux_kern"
    stripped = line.strip()
    if _DMESG_UPTIME.match(stripped) or _DMESG_T.match(stripped) or _DMESG_ISO.match(stripped):
        return "linux_dmesg"
    if _BOOT.search(line):
        return "linux_boot"
    if _MACOS_UNIFIED.match(stripped):
        return "macos_unified"
    if _ASL.search(line):
        return "macos_asl"
    if _INSTALL.search(line):
        return "macos_install"
    if is_rfc3164(line) or is_rfc5424(line):
        return "linux_syslog"
    return None


def detect_unix_os_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback for Unix OS / macOS; do not steal SSH auth.log."""
    name = path.name.lower()
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    if name == "system.log":
        return "linux_syslog"
    if name in {"syslog", "messages"}:
        return "linux_syslog"
    if "crash" in name and "macos" in name:
        return "macos_install"
    if name.endswith(".crash"):
        return "macos_install"
    for token, source in _FILENAME_TOKENS:
        if token.lower() in name:
            return source
    if name == "cron" or name.endswith("cron.log"):
        return "linux_cron"
    if "asl" in name:
        return "macos_asl"
    if name.startswith("kern.") or name == "kern":
        return "linux_kern"
    if "syslog" in name:
        return "linux_syslog"
    return None
