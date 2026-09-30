"""Content-first and filename routing for physical-security / IoT / ICS families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

CCTV_EVENTS = frozenset({"motion", "offline", "online", "tamper"})
IOT_FW_EVENTS = frozenset({"firmware_update", "fw_update", "ota", "firmware"})

CSV_HEADER = re.compile(r"^ts\s*,\s*badge_id\s*,\s*door\s*,\s*result\b", re.IGNORECASE)
CSV_ROW = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[^,]+,[^,]+,[^,]+,"
    r"(?:allow|deny|allowed|denied|granted|rejected)\b",
    re.IGNORECASE,
)
BADGE_SYSLOG = re.compile(
    r"\bbadge_id=\S+.*\bdoor=|\bdoor=\S+.*\bbadge_id=",
    re.IGNORECASE,
)
BMS_SYSLOG = re.compile(
    r"\bpanel=\S+.*\b(?:alarm=|zone=|setpoint=)|\b(?:alarm=|zone=|setpoint=)\S+.*\bpanel=",
    re.IGNORECASE,
)
ICS_SYSLOG = re.compile(
    r"\bplc=\S+.*\b(?:tag=|value=)|\b(?:tag=|value=)\S+.*\bplc=",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "badge.csv": "badge",
    "badge.txt": "badge",
    "badge.log": "badge",
    "access-control.csv": "badge",
    "cctv.json": "cctv",
    "cctv.txt": "cctv",
    "bms.txt": "bms",
    "bms.json": "bms",
    "hvac.log": "bms",
    "hvac.txt": "bms",
    "iot.json": "iot",
    "iot.txt": "iot",
    "ics.txt": "ics",
    "ics.json": "ics",
    "scada.txt": "ics",
    "scada.json": "ics",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("badge", "badge"),
    ("access-control", "badge"),
    ("cctv", "cctv"),
    ("hvac", "bms"),
    ("bms.txt", "bms"),
    ("bms.json", "bms"),
    ("iot.json", "iot"),
    ("iot.txt", "iot"),
    ("scada", "ics"),
    ("ics.txt", "ics"),
    ("ics.json", "ics"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "auth.log",
        "access.log",
        "app_runtime.json",
    }
)


def _is_cctv(obj: dict) -> bool:
    camera = str(obj.get("camera_id") or obj.get("camera") or "").strip()
    if not camera:
        return False
    event = str(obj.get("event") or "").strip().lower()
    return event in CCTV_EVENTS


def _is_bms(obj: dict) -> bool:
    if "panel" not in obj and "zone" not in obj:
        return False
    return "alarm" in obj or "hvac" in obj or "setpoint" in obj


def _is_iot(obj: dict) -> bool:
    if not str(obj.get("device_id") or "").strip():
        return False
    if str(obj.get("fw_version") or obj.get("firmware_version") or "").strip():
        return True
    event = str(obj.get("event") or "").strip().lower()
    return event in IOT_FW_EVENTS


def _is_ics(obj: dict) -> bool:
    if not str(obj.get("plc") or "").strip():
        return False
    return "tag" in obj or "value" in obj


def detect_physical_log_source_from_line(line: str) -> str | None:
    """Return a physical ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_cctv(obj):
            return "cctv"
        if _is_bms(obj):
            return "bms"
        if _is_iot(obj):
            return "iot"
        if _is_ics(obj):
            return "ics"
        return None
    stripped = line.strip()
    if CSV_HEADER.match(stripped) or CSV_ROW.match(stripped) or BADGE_SYSLOG.search(stripped):
        return "badge"
    if BMS_SYSLOG.search(stripped):
        return "bms"
    if ICS_SYSLOG.search(stripped):
        return "ics"
    return None


def detect_physical_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal syslog.log or app_runtime.json."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
