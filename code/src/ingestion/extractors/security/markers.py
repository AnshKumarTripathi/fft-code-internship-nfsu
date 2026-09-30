"""Content-first and filename routing for security-appliance families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object
from src.ingestion.extractors.security.cef import looks_like_cef
from src.ingestion.extractors.security.snort_fast import looks_like_snort_fast

SURICATA_EVENT_TYPES = frozenset(
    {
        "alert",
        "anomaly",
        "drop",
        "flow",
        "dns",
        "http",
        "tls",
        "fileinfo",
        "ssh",
        "ftp",
        "smtp",
        "stats",
        "ikev2",
        "nfs",
        "tftp",
        "smb",
        "dcerpc",
        "krb5",
        "snmp",
        "rdp",
        "sip",
        "mqtt",
    }
)

_CLAMD = re.compile(r"\bclamd\[", re.IGNORECASE)
_CLAMSCAN = re.compile(r"\bclamscan\b", re.IGNORECASE)
_CLAM_FOUND = re.compile(r":\s+\S.+\sFOUND\s*$")

_BASENAME_SOURCES = {
    "eve.json": "ids_ips",
    "suricata.json": "ids_ips",
    "suricata.txt": "ids_ips",
    "ids_ips.txt": "ids_ips",
    "ids_ips.json": "ids_ips",
    "snort_fast.alert": "ids_ips",
    "snort.alert": "ids_ips",
    "fast.alert": "ids_ips",
    "modsec.json": "waf",
    "waf.json": "waf",
    "waf.txt": "waf",
    "dlp.json": "dlp",
    "dlp.txt": "dlp",
    "edr.json": "edr",
    "edr.txt": "edr",
    "crowdstrike.json": "edr",
    "clamav.txt": "antivirus",
    "clamav.log": "antivirus",
    "antivirus.txt": "antivirus",
    "vuln_scanner.json": "vuln_scanner",
    "vuln_scanner.txt": "vuln_scanner",
    "nessus.json": "vuln_scanner",
    "siem.json": "siem",
    "siem.txt": "siem",
    "cef.log": "cef",
    "cef.txt": "cef",
    "events.cef": "cef",
    "cowrie.json": "honeypot",
    "honeypot.json": "honeypot",
    "honeypot.txt": "honeypot",
    "cuckoo.json": "sandbox",
    "sandbox.json": "sandbox",
    "sandbox.txt": "sandbox",
    "threat_intel.json": "threat_intel",
    "stix.json": "threat_intel",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("suricata", "ids_ips"),
    ("eve.json", "ids_ips"),
    ("snort", "ids_ips"),
    (".fast", "ids_ips"),
    (".alert", "ids_ips"),
    ("modsec", "waf"),
    ("clamav", "antivirus"),
    ("crowdstrike", "edr"),
    ("cowrie", "honeypot"),
    ("cuckoo", "sandbox"),
    ("nessus", "vuln_scanner"),
    ("stix", "threat_intel"),
    ("ids_ips", "ids_ips"),
    ("vuln_scanner", "vuln_scanner"),
    ("threat_intel", "threat_intel"),
    ("honeypot", "honeypot"),
    ("sandbox", "sandbox"),
    ("antivirus", "antivirus"),
    ("waf", "waf"),
    ("dlp", "dlp"),
    ("edr", "edr"),
    ("siem", "siem"),
    (".cef", "cef"),
    ("cef.", "cef"),
)


def _is_cowrie(obj: dict) -> bool:
    eventid = str(obj.get("eventid") or "")
    return eventid.startswith("cowrie.")


def _is_suricata(obj: dict) -> bool:
    event_type = str(obj.get("event_type") or "")
    if event_type not in SURICATA_EVENT_TYPES:
        return False
    return "src_ip" in obj or "dest_ip" in obj or "alert" in obj


def _is_cuckoo(obj: dict) -> bool:
    return "malscore" in obj


def _is_stix(obj: dict) -> bool:
    kind = str(obj.get("type") or "")
    if kind == "indicator":
        return True
    if "pattern" in obj and ("spec_version" in obj or "verdict" in obj):
        return True
    return False


def _is_edr(obj: dict) -> bool:
    return "event_simpleName" in obj


def _is_dlp(obj: dict) -> bool:
    if "policy" not in obj or "action" not in obj:
        return False
    return "user" in obj or "file" in obj or "host" in obj


def _is_waf(obj: dict) -> bool:
    return isinstance(obj.get("transaction"), dict)


def _is_vuln(obj: dict) -> bool:
    return "pluginID" in obj or "plugin_id" in obj


def _is_siem(obj: dict) -> bool:
    if "rule_name" not in obj:
        return False
    return "siem" in obj or "correlation_id" in obj or "correlated" in obj


def detect_security_log_source_from_line(line: str) -> str | None:
    """Return a security source from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_cowrie(obj):
            return "honeypot"
        if _is_suricata(obj):
            return "ids_ips"
        if _is_cuckoo(obj):
            return "sandbox"
        if _is_stix(obj):
            return "threat_intel"
        if _is_edr(obj):
            return "edr"
        if _is_dlp(obj):
            return "dlp"
        if _is_waf(obj):
            return "waf"
        if _is_vuln(obj):
            return "vuln_scanner"
        if _is_siem(obj):
            return "siem"
        return None
    if looks_like_cef(line):
        return "cef"
    if looks_like_snort_fast(line):
        return "ids_ips"
    if _CLAMD.search(line) or _CLAMSCAN.search(line):
        return "antivirus"
    if _CLAM_FOUND.search(line.strip()):
        return "antivirus"
    return None


def detect_security_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal defender.txt or firewall.txt."""
    name = path.name.lower()
    if name in {"defender.txt", "firewall.txt", "application.txt"}:
        return None
    if name.endswith(".cef"):
        return "cef"
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
