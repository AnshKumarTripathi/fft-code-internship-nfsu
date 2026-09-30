"""Content-first and filename routing for telephony families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

SIP_PROG = re.compile(r"\b(?:asterisk|kamailio|freeswitch)\[", re.IGNORECASE)
SIP_METHOD = re.compile(r"\b(?:INVITE|REGISTER)\b")
SIP_URI = re.compile(r"\bsip:", re.IGNORECASE)

PBX_HEADER = re.compile(
    r"^(?:ts\s*,\s*)?src\s*,\s*dst\s*,\s*duration\s*,\s*disposition\b",
    re.IGNORECASE,
)
PBX_DISPOSITION = r"(?:ANSWERED|NO ANSWER|BUSY|FAILED|CONGESTION|VOICEMAIL)"
PBX_ROW = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}T[^,]+,)?"
    r"[^,]+,[^,]+,\d+,"
    rf"{PBX_DISPOSITION}\b",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "voip.txt": "voip",
    "voip.log": "voip",
    "asterisk.log": "voip",
    "asterisk.txt": "voip",
    "kamailio.log": "voip",
    "kamailio.txt": "voip",
    "freeswitch.log": "voip",
    "freeswitch.txt": "voip",
    "sip.txt": "voip",
    "sip.log": "voip",
    "pbx.csv": "pbx",
    "pbx.txt": "pbx",
    "cdr.csv": "pbx",
    "video_conf.json": "video_conf",
    "video_conf.txt": "video_conf",
    "ivr.json": "ivr",
    "ivr.txt": "ivr",
    "ivr.csv": "ivr",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("voip", "voip"),
    ("asterisk", "voip"),
    ("kamailio", "voip"),
    ("freeswitch", "voip"),
    ("pbx", "pbx"),
    ("cdr.csv", "pbx"),
    ("video_conf", "video_conf"),
    ("ivr.json", "ivr"),
    ("ivr.txt", "ivr"),
    ("ivr.csv", "ivr"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "auth.log",
        "access.log",
        "collab.json",
        "slack_audit.json",
        "app_runtime.json",
    }
)


def has_strong_sip_markers(line: str) -> bool:
    """True when INVITE/REGISTER plus sip: or a SIP program is present."""
    if not line:
        return False
    has_method = SIP_METHOD.search(line) is not None
    has_uri = SIP_URI.search(line) is not None
    has_prog = SIP_PROG.search(line) is not None
    if has_method and (has_uri or has_prog):
        return True
    return has_prog and has_uri


def _is_video_conf(obj: dict) -> bool:
    if not str(obj.get("meeting_id") or "").strip():
        return False
    if str(obj.get("organizer") or "").strip():
        return True
    return "join" in obj


def _is_ivr(obj: dict) -> bool:
    if not str(obj.get("call_id") or "").strip():
        return False
    return "menu" in obj or "agent" in obj


def detect_telephony_log_source_from_line(line: str) -> str | None:
    """Return a telephony ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_video_conf(obj):
            return "video_conf"
        if _is_ivr(obj):
            return "ivr"
        return None
    stripped = line.strip()
    if has_strong_sip_markers(stripped):
        return "voip"
    if PBX_HEADER.match(stripped) or PBX_ROW.match(stripped):
        return "pbx"
    return None


def detect_telephony_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal syslog, auth, or collab audit files."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
