"""Classic Windows ``pfirewall.log`` text (``windows_pfirewall``, Phase 85).

Typical shape::

    #Version: 1.5
    #Fields: date time action protocol src-ip dst-ip src-port dst-port …
    2024-01-15 10:00:01 DROP TCP 10.0.0.1 10.0.0.2 54321 22 …

Event Log WFP (``windows_firewall``) is unchanged. ``#Fields`` is stored on
``SyslogYearState.pfirewall_fields`` per source path.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.windows.common import looks_like_ip
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

DEFAULT_PFIREWALL_FIELDS = [
    "date",
    "time",
    "action",
    "protocol",
    "src-ip",
    "dst-ip",
    "src-port",
    "dst-port",
    "size",
    "tcpflags",
    "tcpsynack",
    "tcpsize",
    "tcpwindowstatus",
    "path",
]

_DATA_ROW = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>ALLOW|DROP|OPEN|CLOSE|INFO)\s+",
    re.IGNORECASE,
)
_FIELDS_HEADER = re.compile(r"^#Fields:\s*(?P<cols>.+)$", re.IGNORECASE)


def looks_like_pfirewall(line: str) -> bool:
    """True for classic pfirewall headers or space-separated data rows."""
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.lower().startswith("#fields:"):
        lower = stripped.lower()
        return "src-ip" in lower and "dst-ip" in lower and "action" in lower
    if stripped.startswith("#"):
        return False
    return bool(_DATA_ROW.match(stripped))


def parse_pfirewall_fields_header(line: str) -> list[str] | None:
    """Parse ``#Fields: …`` into a column name list."""
    match = _FIELDS_HEADER.match(line.strip())
    if not match:
        return None
    cols = [c.strip().lower() for c in match.group("cols").split() if c.strip()]
    return cols or None


def update_pfirewall_fields_state(
    line: str, year_state: SyslogYearState | None
) -> list[str] | None:
    """If line is ``#Fields``, store columns on ``year_state`` and return them."""
    cols = parse_pfirewall_fields_header(line)
    if cols is None:
        return None
    if year_state is not None:
        year_state.pfirewall_fields = cols
    return cols


def _row_dict(line: str, fields: list[str]) -> dict[str, str] | None:
    parts = line.strip().split()
    if len(parts) < 5:
        return None
    row: dict[str, str] = {}
    for idx, name in enumerate(fields):
        if idx >= len(parts):
            break
        row[name] = parts[idx]
    # If header missing but line matches data pattern, bind defaults by position
    if "src-ip" not in row and len(parts) >= 6:
        row = {
            "date": parts[0],
            "time": parts[1],
            "action": parts[2],
            "protocol": parts[3],
            "src-ip": parts[4],
            "dst-ip": parts[5],
        }
        if len(parts) > 6:
            row["src-port"] = parts[6]
        if len(parts) > 7:
            row["dst-port"] = parts[7]
    return row


def _parse_timestamp(row: dict[str, str]) -> datetime | None:
    date = row.get("date", "")
    time = row.get("time", "")
    if not date or not time:
        return None
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _normalize_action(raw: str) -> str:
    token = (raw or "").strip().upper()
    if token in {"ALLOW", "OPEN"}:
        return "allow"
    if token in {"DROP", "CLOSE"}:
        return "deny"
    return ""


def extract_windows_pfirewall(
    line: str,
    *,
    year_state: SyslogYearState | None = None,
) -> ExtractionResult:
    """Extract src/dst IP and DROP/ALLOW from classic ``pfirewall.log`` text."""
    stripped = line.strip()
    if not stripped:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="empty windows_pfirewall line",
            raw_fields={"dialect": "pfirewall_file"},
        )
    if update_pfirewall_fields_state(stripped, year_state) is not None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="pfirewall_header",
            raw_fields={"dialect": "pfirewall_file"},
        )
    if stripped.startswith("#"):
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="pfirewall_comment",
            raw_fields={"dialect": "pfirewall_file"},
        )

    fields = (
        (year_state.pfirewall_fields if year_state else None) or DEFAULT_PFIREWALL_FIELDS
    )
    row = _row_dict(stripped, fields)
    if row is None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="no windows_pfirewall row",
            raw_fields={"dialect": "pfirewall_file"},
        )

    src = row.get("src-ip") or row.get("src_ip") or ""
    dst = row.get("dst-ip") or row.get("dst_ip") or ""
    action_raw = row.get("action") or ""
    action = _normalize_action(action_raw)
    protocol = row.get("protocol") or ""
    src_port = row.get("src-port") or row.get("src_port") or ""
    dst_port = row.get("dst-port") or row.get("dst_port") or ""
    event_timestamp = _parse_timestamp(row)
    ts_ok = event_timestamp is not None

    raw_fields: dict[str, str | bool] = {"dialect": "pfirewall_file"}
    if action_raw:
        raw_fields["action_raw"] = action_raw
    if action:
        raw_fields["action"] = action
    if protocol:
        raw_fields["protocol"] = protocol
    if src and looks_like_ip(src):
        raw_fields["src_ip"] = src
    if dst and looks_like_ip(dst):
        raw_fields["dst_ip"] = dst
    if src_port and src_port not in {"-", ""}:
        raw_fields["src_port"] = src_port
    if dst_port and dst_port not in {"-", ""}:
        raw_fields["dst_port"] = dst_port
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    if not src or not looks_like_ip(src):
        return ExtractionResult(
            event_timestamp=event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason="no windows_pfirewall entity extracted",
        )
    return ExtractionResult(
        entity_id=src,
        entity_type="ip",
        event_timestamp=event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if ts_ok else "timestamp parse failed",
    )


__all__ = [
    "DEFAULT_PFIREWALL_FIELDS",
    "extract_windows_pfirewall",
    "looks_like_pfirewall",
    "parse_pfirewall_fields_header",
    "update_pfirewall_fields_state",
]
