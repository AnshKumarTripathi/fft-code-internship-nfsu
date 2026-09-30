"""Content-first and filename routing for virtualization and infrastructure families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

ESXI = re.compile(
    r"\bHostd(?:\[|:|\s)|\bvpxd(?:\[|:|\s)|\besx\.audit\b|\bvmware-hostd\b",
    re.IGNORECASE,
)
HYPERV = re.compile(r"\bHyper-V-VMMS\b|\bHyper-V-Worker\b|\bHyper-V-SynthStor\b")
LIBVIRT = re.compile(r"\blibvirtd\[|\bqemu-kvm\b|\bqemu\[", re.IGNORECASE)
SAN_STRONG = re.compile(
    r"\bLUN\s+\d+|\bvolume\s+\S+|\bsan(?:d)?\[|\bstoraged\[",
    re.IGNORECASE,
)
VEEAM = re.compile(r"\bVeeam\b", re.IGNORECASE)
COMMVAULT = re.compile(r"\bCommvault\b|\bCVJob\b", re.IGNORECASE)
BACULA = re.compile(r"\bbacula-(?:dir|sd|fd)\b|\bbacula\b", re.IGNORECASE)
JOB_FINISHED = re.compile(r"\bJob (?:finished|completed|ended)\b", re.IGNORECASE)
NTP = re.compile(r"\bntpd\[|\bchronyd\[", re.IGNORECASE)
FLEXLM = re.compile(r"\b(?:OUT|IN|DENIED):\s+\"[^\"]+\"|\blmgrd\[", re.IGNORECASE)
ANSIBLE = re.compile(r"\bPLAY RECAP\b|\bTASK \[|\bansible-playbook\b", re.IGNORECASE)
PUPPET = re.compile(r"\bpuppet-agent\[|\bApplied catalog\b|\bpuppet\b.*\breport\b", re.IGNORECASE)
CHEF = re.compile(r"\bChef Client\b|\bchef-client\[", re.IGNORECASE)
TERRAFORM_TEXT = re.compile(
    r"\bApply complete!|\bTerraform (?:will perform|Apply)|^\s*Plan:\s+\d+ to add",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "esxi.txt": "hypervisor",
    "esxi.log": "hypervisor",
    "hyperv.txt": "hypervisor",
    "hyperv.log": "hypervisor",
    "kvm.txt": "hypervisor",
    "kvm.log": "hypervisor",
    "libvirt.log": "hypervisor",
    "san.txt": "san",
    "san.log": "san",
    "veeam.txt": "backup",
    "commvault.txt": "backup",
    "bacula.txt": "backup",
    "backup.txt": "backup",
    "ntp.txt": "ntp",
    "ntp.log": "ntp",
    "chrony.log": "ntp",
    "license.txt": "license",
    "flexlm.txt": "license",
    "ansible.txt": "config_mgmt",
    "puppet.txt": "config_mgmt",
    "chef.txt": "config_mgmt",
    "terraform.txt": "iac",
    "terraform.json": "iac",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("esxi", "hypervisor"),
    ("hyperv", "hypervisor"),
    ("libvirt", "hypervisor"),
    ("kvm.txt", "hypervisor"),
    ("kvm.log", "hypervisor"),
    ("san.txt", "san"),
    ("san.log", "san"),
    ("veeam", "backup"),
    ("commvault", "backup"),
    ("bacula", "backup"),
    ("chrony", "ntp"),
    ("ntp.txt", "ntp"),
    ("ntp.log", "ntp"),
    ("flexlm", "license"),
    ("license.txt", "license"),
    ("ansible", "config_mgmt"),
    ("puppet", "config_mgmt"),
    ("chef.txt", "config_mgmt"),
    ("chef.log", "config_mgmt"),
    ("terraform", "iac"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "docker.log",
        "docker.txt",
        "deploy.json",
        "deploy.txt",
        "cron.log",
        "auth.log",
        "access.log",
    }
)


def _is_terraform_json(obj: dict) -> bool:
    module = str(obj.get("@module") or obj.get("module") or "")
    if "terraform" in module.lower():
        return True
    message = str(obj.get("@message") or obj.get("message") or "")
    if TERRAFORM_TEXT.search(message):
        return True
    type_name = str(obj.get("type") or "")
    return type_name in {"apply_complete", "change_summary", "planned_change"}


def detect_virtualization_log_source_from_line(line: str) -> str | None:
    """Return a virtualization ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_terraform_json(obj):
            return "iac"
        return None
    stripped = line.strip()
    if ESXI.search(stripped) or HYPERV.search(stripped) or LIBVIRT.search(stripped):
        return "hypervisor"
    if NTP.search(stripped):
        return "ntp"
    if FLEXLM.search(stripped):
        return "license"
    if ANSIBLE.search(stripped) or PUPPET.search(stripped) or CHEF.search(stripped):
        return "config_mgmt"
    if TERRAFORM_TEXT.search(stripped):
        return "iac"
    if VEEAM.search(stripped) or COMMVAULT.search(stripped) or BACULA.search(stripped):
        return "backup"
    if JOB_FINISHED.search(stripped) and SAN_STRONG.search(stripped):
        return "san"
    if SAN_STRONG.search(stripped):
        return "san"
    return None


def detect_virtualization_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal docker.log or deploy.json."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
