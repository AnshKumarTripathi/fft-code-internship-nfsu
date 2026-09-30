"""pfSense filterlog extraction (``firewall``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.network.common import (
    build_network_extraction_result,
    parse_network_syslog,
    syslog_extra,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

FILTERLOG_PAYLOAD = re.compile(r"filterlog\[\d+\]:\s*(?P<csv>.+)", re.IGNORECASE)


def _parse_filterlog_csv(csv: str) -> dict[str, str]:
    parts = csv.split(",")
    if len(parts) < 20:
        return {}
    ip_version = parts[8]
    if ip_version not in {"4", "6"}:
        return {}
    fields: dict[str, str] = {
        "interface": parts[4],
        "reason": parts[5],
        "action": parts[6],
        "direction": parts[7],
        "protocol": parts[16],
        "src_ip": parts[18],
        "dst_ip": parts[19],
    }
    if len(parts) > 21:
        fields["src_port"] = parts[20]
        fields["dst_port"] = parts[21]
    return fields


def extract_firewall(
    line: str,
    *,
    default_year: int,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst IP and allow/deny from pfSense filterlog CSV."""
    event_timestamp, ts_ok, hostname, program, pid = parse_network_syslog(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    extra = syslog_extra(program, pid)
    payload = FILTERLOG_PAYLOAD.search(line)
    parsed = _parse_filterlog_csv(payload.group("csv")) if payload else {}
    if parsed.get("interface"):
        extra["interface"] = parsed["interface"]
    if parsed.get("direction"):
        extra["direction"] = parsed["direction"]
    if parsed.get("reason"):
        extra["reason"] = parsed["reason"]
    return build_network_extraction_result(
        src_ip=parsed.get("src_ip", ""),
        dst_ip=parsed.get("dst_ip", ""),
        src_port=parsed.get("src_port", ""),
        dst_port=parsed.get("dst_port", ""),
        action=parsed.get("action", ""),
        protocol=parsed.get("protocol", "") or "filterlog",
        hostname=hostname,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no firewall entity extracted",
        prefer_ip_entity=True,
    )
