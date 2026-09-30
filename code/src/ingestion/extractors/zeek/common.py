"""Shared Zeek TSV helpers (Phase 83)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.ingestion.extractors.identity.common import looks_like_ip
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

ZEEK_EMPTY = frozenset({"-", "(empty)", ""})


def is_zeek_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def parse_zeek_fields_header(line: str) -> list[str] | None:
    """Return column names from ``#fields\\t...`` or None."""
    stripped = line.strip()
    if not stripped.startswith("#fields"):
        return None
    # "#fields\tts\tid.orig_h\t..." or "#fields ts id.orig_h" (space rare)
    rest = stripped[len("#fields") :].lstrip()
    if not rest:
        return None
    if "\t" in rest:
        cols = rest.split("\t")
    else:
        cols = rest.split()
    return [c.strip() for c in cols if c.strip()]


def update_zeek_fields_state(line: str, year_state: SyslogYearState | None) -> list[str] | None:
    """If ``line`` is ``#fields``, store columns on ``year_state`` and return them."""
    cols = parse_zeek_fields_header(line)
    if cols is None:
        return None
    if year_state is not None:
        year_state.zeek_fields = cols
    return cols


def zeek_row_dict(
    line: str,
    fields: list[str] | None,
) -> dict[str, str] | None:
    """Map a TSV data line to a dict using ``fields``; None if unusable."""
    if not fields or is_zeek_comment(line):
        return None
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        return None
    # Pad / truncate to field count (Zeek sometimes omits trailing empties)
    while len(parts) < len(fields):
        parts.append("-")
    row = {}
    for key, value in zip(fields, parts[: len(fields)], strict=False):
        token = value.strip()
        if token in ZEEK_EMPTY:
            continue
        row[key] = token
    return row if row else None


def parse_zeek_ts(token: str | None) -> datetime | None:
    """Parse Zeek epoch float ``ts`` as UTC."""
    if not token:
        return None
    try:
        value = float(token)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def build_zeek_result(
    *,
    src_ip: str = "",
    dst_ip: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
) -> ExtractionResult:
    """Entity prefers orig host IP, then resp IP."""
    src = src_ip if src_ip and looks_like_ip(src_ip) else ""
    dst = dst_ip if dst_ip and looks_like_ip(dst_ip) else ""
    entity_ip = src or dst
    raw_fields: dict[str, Any] = {}
    if src:
        raw_fields["src_ip"] = src
    if dst:
        raw_fields["dst_ip"] = dst
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True
    if not entity_ip:
        return ExtractionResult(
            event_timestamp=event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason=no_match_reason,
        )
    return ExtractionResult(
        entity_id=entity_ip,
        entity_type="ip",
        event_timestamp=event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if ts_ok else "timestamp parse failed",
    )


# Standard Zeek 2.x/3.x/5.x column sets when #fields not yet seen
DEFAULT_CONN_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
]

DEFAULT_DNS_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "trans_id",
    "rtt",
    "query",
    "qclass",
    "qclass_name",
    "qtype",
    "qtype_name",
    "rcode",
    "rcode_name",
    "AA",
    "TC",
    "RD",
    "RA",
    "Z",
    "answers",
    "TTLs",
    "rejected",
]
