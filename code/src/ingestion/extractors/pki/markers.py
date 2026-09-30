"""Content-first and filename routing for PKI / crypto families."""

from __future__ import annotations

import re
from pathlib import Path

from src.ingestion.extractors.identity.common import parse_json_object

CA_ACTIONS = frozenset({"issued", "revoked", "issue", "revoke"})
CT_EVENTS = frozenset({"seen", "misissue"})

CA_SYSLOG = re.compile(
    r"\b(?:issued|revoked)\b.*\bcn=|\bcn=\S+.*\b(?:issued|revoked)\b",
    re.IGNORECASE,
)
HSM_SYSLOG = re.compile(
    r"\bslot=\S+.*\bop=|\bop=\S+.*\bslot=",
    re.IGNORECASE,
)
TLS_HANDSHAKE = re.compile(
    r"\bssl_handshake\b|\bSSL_do_handshake\b",
    re.IGNORECASE,
)
OPENSSL_SSERVER = re.compile(
    r"\bs_server\b.*\bTLS|\bTLS\b.*\bs_server\b",
    re.IGNORECASE,
)

_BASENAME_SOURCES = {
    "pki_ca.json": "pki_ca",
    "pki_ca.txt": "pki_ca",
    "cfssl.json": "pki_ca",
    "cfssl.txt": "pki_ca",
    "step-ca.txt": "pki_ca",
    "step-ca.json": "pki_ca",
    "hsm.txt": "hsm",
    "hsm.json": "hsm",
    "pkcs11.txt": "hsm",
    "tls.txt": "tls",
    "tls.log": "tls",
    "ssl_handshake.log": "tls",
    "ssl_handshake.txt": "tls",
    "openssl_s_server.txt": "tls",
    "ct_log.json": "ct_log",
    "ct_log.txt": "ct_log",
    "code_signing.json": "code_signing",
    "code_signing.txt": "code_signing",
    "signtool.txt": "code_signing",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("pki_ca", "pki_ca"),
    ("cfssl", "pki_ca"),
    ("step-ca", "pki_ca"),
    ("pkcs11", "hsm"),
    ("hsm.txt", "hsm"),
    ("hsm.json", "hsm"),
    ("ssl_handshake", "tls"),
    ("s_server", "tls"),
    ("tls.txt", "tls"),
    ("tls.log", "tls"),
    ("ct_log", "ct_log"),
    ("code_signing", "code_signing"),
    ("signtool", "code_signing"),
)

_SKIP_NAMES = frozenset(
    {
        "syslog.log",
        "syslog.txt",
        "auth.log",
        "access.log",
        "vault.json",
        "vault.txt",
        "vault_audit.json",
        "app_runtime.json",
    }
)


def _cn_from_obj(obj: dict) -> str:
    raw = str(obj.get("cn") or obj.get("subject") or "").strip()
    if raw.upper().startswith("CN="):
        return raw[3:].strip()
    return raw


def _is_pki_ca(obj: dict) -> bool:
    if not _cn_from_obj(obj):
        return False
    action = str(obj.get("action") or obj.get("event") or "").strip().lower()
    return action in CA_ACTIONS


def _is_hsm(obj: dict) -> bool:
    if obj.get("slot") in {None, ""}:
        return False
    return obj.get("op") not in {None, ""}


def _is_ct_log(obj: dict) -> bool:
    if not str(obj.get("domain") or "").strip():
        return False
    if not str(obj.get("issuer") or "").strip():
        return False
    event = str(obj.get("event") or "").strip().lower()
    return event in CT_EVENTS


def _is_code_signing(obj: dict) -> bool:
    if not str(obj.get("hash") or "").strip():
        return False
    if not str(obj.get("signer") or "").strip():
        return False
    return obj.get("result") not in {None, ""}


def detect_pki_log_source_from_line(line: str) -> str | None:
    """Return a PKI ``log_source`` from strong content markers, else None."""
    if not line:
        return None
    obj = parse_json_object(line)
    if obj is not None:
        if _is_pki_ca(obj):
            return "pki_ca"
        if _is_hsm(obj):
            return "hsm"
        if _is_ct_log(obj):
            return "ct_log"
        if _is_code_signing(obj):
            return "code_signing"
        return None
    stripped = line.strip()
    if CA_SYSLOG.search(stripped):
        return "pki_ca"
    if HSM_SYSLOG.search(stripped):
        return "hsm"
    if TLS_HANDSHAKE.search(stripped) or OPENSSL_SSERVER.search(stripped):
        return "tls"
    return None


def detect_pki_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback; do not steal access.log or vault audit files."""
    name = path.name.lower()
    if name in _SKIP_NAMES:
        return None
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
