"""Content-first and filename routing for identity families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

_SLAPD = re.compile(r"\bslapd\[", re.IGNORECASE)
_BIND_DN = re.compile(r"\bBIND dn=", re.IGNORECASE)
_RADIUS_ACCEPT = re.compile(r"\bAccess-Accept\b", re.IGNORECASE)
_RADIUS_REJECT = re.compile(r"\bAccess-Reject\b", re.IGNORECASE)
_RADIUS_AUTH = re.compile(r"Auth:\s*Login (?:OK|incorrect)", re.IGNORECASE)
_RADIUSD = re.compile(r"\bradiusd\[", re.IGNORECASE)
_TAC_PLUS = re.compile(r"\btac_plus\[", re.IGNORECASE)
_DUO_SYSLOG = re.compile(r"\bduo(?:_auth_proxy)?\[", re.IGNORECASE)
_KDC_PROG = re.compile(r"\b(?:krb5kdc|kadmind)\[", re.IGNORECASE)
_KDC_REQ = re.compile(r"\b(?:AS_REQ|TGS_REQ)\b")
_EVENT_ID = re.compile(r"\bEventID\s*[=:]", re.IGNORECASE)

_BASENAME_SOURCES = {
    "ldap.txt": "ldap",
    "ldap.log": "ldap",
    "slapd.log": "ldap",
    "slapd.txt": "ldap",
    "radius.txt": "radius",
    "radius.log": "radius",
    "freeradius.log": "radius",
    "tac_plus.log": "radius",
    "idp.txt": "idp",
    "okta.txt": "idp",
    "okta.json": "idp",
    "mfa.txt": "mfa",
    "duo.txt": "mfa",
    "duo.log": "mfa",
    "kerberos_kdc.txt": "kerberos_kdc",
    "krb5kdc.log": "kerberos_kdc",
    "kdc.log": "kerberos_kdc",
    "vault.txt": "vault",
    "vault.json": "vault",
    "vault_audit.json": "vault",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("freeradius", "radius"),
    ("tac_plus", "radius"),
    ("slapd", "ldap"),
    ("ldap.log", "ldap"),
    ("krb5kdc", "kerberos_kdc"),
    ("kdc.log", "kerberos_kdc"),
    ("okta", "idp"),
    ("auth0", "idp"),
    ("duo", "mfa"),
    ("vault", "vault"),
    ("radius", "radius"),
    ("idp", "idp"),
)


def _is_vault_obj(obj: dict) -> bool:
    kind = obj.get("type")
    if kind not in {"request", "response"}:
        return False
    return "auth" in obj or "request" in obj or "hmac" in obj


def _is_duo_obj(obj: dict) -> bool:
    if "eventtype" not in obj:
        return False
    return "isotimestamp" in obj or "username" in obj


def _is_idp_obj(obj: dict) -> bool:
    if "eventType" not in obj:
        return False
    return "published" in obj or "actor" in obj or "outcome" in obj


def detect_identity_log_source_from_line(line: str) -> str | None:
    """Return an identity source from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_vault_obj(obj):
            return "vault"
        if _is_duo_obj(obj):
            return "mfa"
        if _is_idp_obj(obj):
            return "idp"
        if "bindDN" in obj or "bind_dn" in obj:
            return "ldap"
    if _DUO_SYSLOG.search(line):
        return "mfa"
    if _SLAPD.search(line) or _BIND_DN.search(line):
        return "ldap"
    if (
        _RADIUS_ACCEPT.search(line)
        or _RADIUS_REJECT.search(line)
        or _RADIUS_AUTH.search(line)
        or _TAC_PLUS.search(line)
        or _RADIUSD.search(line)
    ):
        return "radius"
    if _EVENT_ID.search(line):
        return None
    if _KDC_PROG.search(line) or _KDC_REQ.search(line):
        return "kerberos_kdc"
    return None


def detect_identity_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback for identity sources; do not steal auth.log."""
    name = path.name.lower()
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
