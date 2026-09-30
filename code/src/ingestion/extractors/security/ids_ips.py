"""IDS/IPS extraction (``ids_ips``): Suricata EVE JSON + Snort fast alert."""

from __future__ import annotations

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    nested_str,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.extractors.security.snort_fast import (
    extract_snort_fast,
    looks_like_snort_fast,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def _extract_suricata_eve(line: str) -> ExtractionResult:
    """Extract src/dst IP and alert severity from Suricata EVE JSON."""
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no ids_ips JSON object",
        )
    extra: dict[str, str] = {"dialect": "suricata_eve"}
    event_type = str(obj.get("event_type") or "")
    if event_type:
        extra["event_type"] = event_type
    signature = nested_str(obj, "alert", "signature")
    if signature:
        extra["signature"] = signature
    sid = nested_str(obj, "alert", "signature_id")
    if sid:
        extra["sid"] = sid
    proto = str(obj.get("proto") or "")
    if proto:
        extra["protocol"] = proto
    action = nested_str(obj, "alert", "action") or str(obj.get("action") or "")
    severity = nested_str(obj, "alert", "severity")
    if not severity and obj.get("severity") is not None:
        severity = str(obj.get("severity"))
    event_timestamp = parse_security_json_timestamp(obj)
    return build_security_extraction_result(
        src_ip=str(obj.get("src_ip") or ""),
        dst_ip=str(obj.get("dest_ip") or obj.get("dst_ip") or ""),
        hostname=str(obj.get("host") or obj.get("hostname") or ""),
        action=action,
        severity=severity,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no ids_ips entity extracted",
    )


def extract_ids_ips(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Dispatch Suricata EVE JSON or Snort fast-alert text under ``ids_ips``."""
    obj = parse_json_object(line)
    if obj is not None:
        return _extract_suricata_eve(line)
    if looks_like_snort_fast(line):
        return extract_snort_fast(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    return build_security_extraction_result(
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no ids_ips JSON object",
    )
