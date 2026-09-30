"""ModSecurity JSON WAF extraction (``waf``)."""

from __future__ import annotations

from typing import Any

from src.ingestion.extractors.security.common import (
    build_security_extraction_result,
    nested_str,
    parse_iso_datetime,
    parse_json_object,
    parse_security_json_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def _first_message(obj: dict[str, Any]) -> dict[str, Any]:
    messages = obj.get("messages")
    if isinstance(messages, list) and messages and isinstance(messages[0], dict):
        return messages[0]
    return {}


def extract_waf(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP and rule action from ModSecurity JSON."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_security_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no waf JSON object",
        )
    txn = obj.get("transaction")
    if not isinstance(txn, dict):
        txn = obj
    extra: dict[str, str] = {}
    method = nested_str(txn, "request", "method")
    uri = nested_str(txn, "request", "uri")
    if method:
        extra["method"] = method
    if uri:
        extra["path"] = uri
    code = nested_str(txn, "response", "http_code")
    if code:
        extra["status"] = code
    message = _first_message(txn)
    details = message.get("details") if isinstance(message.get("details"), dict) else {}
    rule_id = str(details.get("ruleId") or details.get("rule_id") or "")
    if rule_id:
        extra["rule_id"] = rule_id
    msg = str(message.get("message") or "")
    if msg:
        extra["message"] = msg
    action = str(details.get("match") or txn.get("action") or obj.get("action") or "")
    if not action and code and str(code).startswith(("4", "5")):
        action = "block"
    elif not action:
        action = "allow"
    severity = str(details.get("severity") or txn.get("severity") or "")
    src_ip = str(txn.get("client_ip") or obj.get("client_ip") or "")
    hostname = str(txn.get("host_ip") or txn.get("server_id") or "")
    event_timestamp = parse_security_json_timestamp(txn) or parse_security_json_timestamp(obj)
    if event_timestamp is None:
        stamp = str(txn.get("time_stamp") or "")
        event_timestamp = parse_iso_datetime(stamp) if stamp else None
    return build_security_extraction_result(
        src_ip=src_ip,
        hostname=hostname,
        action=action,
        severity=severity,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no waf entity extracted",
    )
