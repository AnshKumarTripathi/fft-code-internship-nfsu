"""Common Event Format (ArcSight CEF) text dialect (``cef``, Phase 84).

Locked MVP::

    CEF:0|Vendor|Product|1.0|100|Something happened|5|src=10.0.0.1 dst=10.0.0.2 suser=alice rt=Jan 15 2024 10:00:01

Optional syslog / PRI prefix before ``CEF:`` is accepted. LEEF is out of this phase.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    looks_like_ip,
)
from src.ingestion.extractors.unix_os.common import (
    is_rfc3164,
    is_rfc5424,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_CEF_MARK = re.compile(r"(?:^|[\s|])CEF:\d+", re.IGNORECASE)

# ArcSight-style rt= without timezone (MVP)
_RT_WITH_YEAR = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+"
    r"(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})$"
)
_RT_NO_YEAR = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})$"
)
_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


def looks_like_cef(line: str) -> bool:
    """True when the line carries a CEF header (not JSON SIEM)."""
    stripped = line.strip()
    if not stripped or stripped.startswith("{"):
        return False
    if stripped.upper().startswith("CEF:"):
        return True
    return bool(_CEF_MARK.search(stripped))


def find_cef_payload(line: str) -> str | None:
    """Return the substring starting at ``CEF:``, else None."""
    idx = line.find("CEF:")
    if idx < 0:
        idx = line.lower().find("cef:")
        if idx < 0:
            return None
        return "CEF:" + line[idx + 4 :]
    return line[idx:]


def unescape_cef(value: str) -> str:
    """Unescape CEF backslash sequences for ``=``, ``|``, ``\\``, ``n``, ``r``."""
    out: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n:
            nxt = value[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt in {"=", "|", "\\"}:
                out.append(nxt)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def split_cef_header(payload: str) -> tuple[list[str], str] | None:
    """Split ``CEF:ver|…|severity|extension`` into seven header fields + extension."""
    if not payload.upper().startswith("CEF:"):
        return None
    body = payload[4:]
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(body[i + 1])
            i += 2
            continue
        if ch == "|" and len(parts) < 7:
            parts.append(unescape_cef("".join(buf)))
            buf = []
            i += 1
            if len(parts) == 7:
                return parts, body[i:]
            continue
        buf.append(ch)
        i += 1
    if len(parts) == 6:
        parts.append(unescape_cef("".join(buf)))
        return parts, ""
    return None


def parse_cef_extensions(extension: str) -> dict[str, str]:
    """Parse CEF extension ``key=value`` pairs with escaped ``=`` / spaces."""
    result: dict[str, str] = {}
    i = 0
    n = len(extension)
    while i < n:
        while i < n and extension[i] == " ":
            i += 1
        if i >= n:
            break
        key_start = i
        while i < n and extension[i] != "=":
            i += 1
        if i >= n or i == key_start:
            break
        key = extension[key_start:i]
        i += 1
        val_chars: list[str] = []
        while i < n:
            ch = extension[i]
            if ch == "\\" and i + 1 < n:
                val_chars.append(unescape_cef(extension[i : i + 2]))
                i += 2
                continue
            if ch == " ":
                j = i + 1
                while j < n and extension[j] == " ":
                    j += 1
                k = j
                while k < n and extension[k] not in {" ", "="}:
                    k += 1
                if k < n and extension[k] == "=" and k > j:
                    break
                val_chars.append(" ")
                i += 1
                continue
            val_chars.append(ch)
            i += 1
        result[key] = "".join(val_chars)
    return result


def parse_cef_rt(
    token: str,
    *,
    default_year: int,
) -> datetime | None:
    """Parse CEF ``rt`` as epoch ms/s or ``MMM dd [yyyy] HH:mm:ss`` (UTC)."""
    raw = token.strip()
    if not raw:
        return None
    if re.fullmatch(r"\d{10,13}", raw):
        try:
            number = int(raw)
        except ValueError:
            return None
        if number >= 10**12:
            number //= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    match = _RT_WITH_YEAR.match(raw)
    if match:
        month = _MONTHS.get(match.group("mon").lower())
        if month is None:
            return None
        try:
            return datetime(
                int(match.group("year")),
                month,
                int(match.group("day")),
                int(match.group("hour")),
                int(match.group("min")),
                int(match.group("sec")),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    match = _RT_NO_YEAR.match(raw)
    if match and default_year > 0:
        month = _MONTHS.get(match.group("mon").lower())
        if month is None:
            return None
        try:
            return datetime(
                default_year,
                month,
                int(match.group("day")),
                int(match.group("hour")),
                int(match.group("min")),
                int(match.group("sec")),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    return None


def extract_cef(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract entity + timestamp from a CEF line.

    Entity policy: ``suser`` → user, else ``src`` → ip, else ``dhost``/``shost`` → host.
    """
    payload = find_cef_payload(line)
    if payload is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no cef header",
        )
    split = split_cef_header(payload)
    if split is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="malformed cef header",
        )
    header, extension = split
    # header: version, vendor, product, device_version, signature_id, name, severity
    vendor = header[1] if len(header) > 1 else ""
    product = header[2] if len(header) > 2 else ""
    signature_id = header[4] if len(header) > 4 else ""
    name = header[5] if len(header) > 5 else ""
    severity = header[6] if len(header) > 6 else ""
    fields = parse_cef_extensions(extension)

    src = fields.get("src") or fields.get("sourceAddress") or ""
    dst = fields.get("dst") or fields.get("destinationAddress") or ""
    suser = fields.get("suser") or fields.get("sourceUserName") or ""
    dhost = fields.get("dhost") or fields.get("destinationHostName") or ""
    shost = fields.get("shost") or fields.get("sourceHostName") or ""
    hostname = dhost or shost
    outcome = fields.get("outcome") or fields.get("act") or ""

    event_timestamp: datetime | None = None
    ts_ok = False
    rt = fields.get("rt") or ""
    if rt:
        event_timestamp = parse_cef_rt(rt, default_year=default_year)
        ts_ok = event_timestamp is not None
    if not ts_ok and (is_rfc3164(line) or is_rfc5424(line)):
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )

    if src and not looks_like_ip(src):
        src = ""
    if dst and not looks_like_ip(dst):
        dst = ""

    extra: dict[str, str] = {"dialect": "cef"}
    if vendor:
        extra["vendor"] = vendor
    if product:
        extra["product"] = product
    if signature_id:
        extra["signature_id"] = signature_id
    if name:
        extra["name"] = name
    if outcome:
        extra["outcome"] = outcome

    return build_security_extraction_result(
        username=suser,
        src_ip=src,
        dst_ip=dst,
        hostname=hostname,
        action=outcome,
        severity=severity,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no cef entity extracted",
    )


__all__ = [
    "extract_cef",
    "find_cef_payload",
    "looks_like_cef",
    "parse_cef_extensions",
    "parse_cef_rt",
    "split_cef_header",
    "unescape_cef",
]
