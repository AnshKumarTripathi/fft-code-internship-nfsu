"""Content-first and filename routing for email and collaboration families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.email.common import parse_json_object

COLLAB_PLATFORMS = frozenset({"slack", "teams", "zoom"})

SMTP_PROG = re.compile(
    r"\bpostfix/(?:smtpd|smtp)\[|\bsmtpd\[|\bsmtp\[|\bsendmail\[",
    re.IGNORECASE,
)
MTA_PROG = re.compile(
    r"\bpostfix/(?:qmgr|pickup|cleanup)\[",
    re.IGNORECASE,
)
GATEWAY_PROG = re.compile(r"\brspamd\[|\bspamd\[", re.IGNORECASE)
DMARC_PROG = re.compile(
    r"\bopendmarc\[|\bopendkim\[|\bpolicyd-spf\[",
    re.IGNORECASE,
)
EXCHANGE_TRACKING = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}.*\b(?:SMTP|STOREDRIVER)\b"
    r".*\b(?:RECEIVE|SEND|DELIVER|FAIL|DSN|EXPAND|TRANSFER)\b",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "smtp.log": "smtp",
    "smtp.txt": "smtp",
    "sendmail.log": "smtp",
    "sendmail.txt": "smtp",
    "rspamd.txt": "mail_gateway",
    "rspamd.log": "mail_gateway",
    "spamassassin.txt": "mail_gateway",
    "spamassassin.log": "mail_gateway",
    "mta.txt": "mta",
    "mta.log": "mta",
    "qmgr.txt": "mta",
    "qmgr.log": "mta",
    "exchange_tracking.txt": "mta",
    "dmarc.txt": "dmarc",
    "dmarc.log": "dmarc",
    "opendkim.txt": "dmarc",
    "opendkim.log": "dmarc",
    "opendmarc.txt": "dmarc",
    "collab.json": "collab_audit",
    "slack_audit.json": "collab_audit",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("sendmail", "smtp"),
    ("smtp.txt", "smtp"),
    ("smtp.log", "smtp"),
    ("spamassassin", "mail_gateway"),
    ("rspamd", "mail_gateway"),
    ("exchange_tracking", "mta"),
    ("qmgr", "mta"),
    ("mta.txt", "mta"),
    ("mta.log", "mta"),
    ("opendkim", "dmarc"),
    ("opendmarc", "dmarc"),
    ("dmarc.txt", "dmarc"),
    ("dmarc.log", "dmarc"),
    ("slack_audit", "collab_audit"),
    ("collab.json", "collab_audit"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "mail.log",
        "maillog",
        "auth.log",
        "access.log",
        "audit.log",
    }
)


def _is_collab(obj: dict) -> bool:
    platform = str(obj.get("platform") or "").strip().lower()
    if platform not in COLLAB_PLATFORMS:
        return False
    return "actor" in obj or "action" in obj or "workspace" in obj


def _is_gateway_json(obj: dict) -> bool:
    if "action" not in obj:
        return False
    if "score" not in obj and "symbols" not in obj:
        return False
    return "ip" in obj or "user" in obj


def detect_email_log_source_from_line(line: str) -> str | None:
    """Return an email ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_collab(obj):
            return "collab_audit"
        if _is_gateway_json(obj):
            return "mail_gateway"
        return None
    stripped = line.strip()
    if MTA_PROG.search(stripped):
        return "mta"
    if SMTP_PROG.search(stripped):
        return "smtp"
    if GATEWAY_PROG.search(stripped):
        return "mail_gateway"
    if DMARC_PROG.search(stripped):
        return "dmarc"
    if EXCHANGE_TRACKING.search(stripped) and "@" in stripped:
        return "mta"
    return None


def detect_email_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal syslog, mail.log, or maillog."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
