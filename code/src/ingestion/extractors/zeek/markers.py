"""Content-first and filename routing for Zeek TSV (Phase 83)."""

from __future__ import annotations

from pathlib import Path

from src.ingestion.extractors.zeek.common import parse_zeek_fields_header

_BASENAME_SOURCES = {
    "conn.log": "zeek_conn",
    "dns.log": "zeek_dns",
    "zeek_conn.log": "zeek_conn",
    "zeek_dns.log": "zeek_dns",
    "zeek_conn.txt": "zeek_conn",
    "zeek_dns.txt": "zeek_dns",
}

_FILENAME_TOKENS: tuple[tuple[str, str], ...] = (
    ("zeek_conn", "zeek_conn"),
    ("zeek_dns", "zeek_dns"),
    ("conn.log", "zeek_conn"),
    ("dns.log", "zeek_dns"),
)


def detect_zeek_log_source_from_line(line: str) -> str | None:
    """Return zeek_conn / zeek_dns from ``#fields`` headers only."""
    cols = parse_zeek_fields_header(line)
    if cols is None:
        return None
    names = set(cols)
    if "query" in names and ("qtype" in names or "qtype_name" in names):
        return "zeek_dns"
    if "id.orig_h" in names and "id.resp_h" in names and "proto" in names:
        # dns also has id.orig_h — prefer dns when query present (above)
        return "zeek_conn"
    return None


def detect_zeek_log_source_from_filename(path: Path) -> str | None:
    """Filename fallback for Zeek TSV exports."""
    name = path.name.lower()
    if name in _BASENAME_SOURCES:
        return _BASENAME_SOURCES[name]
    # Avoid stealing Apache/Squid access.log — require conn.log / dns.log tokens
    for token, source in _FILENAME_TOKENS:
        if token in name:
            return source
    return None
