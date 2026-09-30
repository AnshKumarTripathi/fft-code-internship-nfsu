"""HSM access extraction (``hsm``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.pki.common import (
    YEAR_POLICY_CARRY,
    build_pki_extraction_result,
    extract_syslog_pki_line,
    parse_json_object,
    parse_pki_json_timestamp,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

SLOT = re.compile(r"\bslot=(?P<slot>\S+)", re.IGNORECASE)
OP = re.compile(r"\bop=(?P<op>\S+)", re.IGNORECASE)
USER = re.compile(r"\buser=(?P<user>\S+)", re.IGNORECASE)


def extract_hsm(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract HSM user (else syslog host) from slot/op lines."""
    obj = parse_json_object(line)
    if obj is not None:
        username = str(obj.get("user") or obj.get("username") or "").strip()
        extra: dict[str, str] = {}
        if obj.get("slot") not in {None, ""}:
            extra["slot"] = str(obj.get("slot"))
        if obj.get("op") not in {None, ""}:
            extra["op"] = str(obj.get("op"))
        event_timestamp = parse_pki_json_timestamp(obj)
        return build_pki_extraction_result(
            username=username,
            hostname="" if username else str(obj.get("host") or "hsm"),
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no hsm JSON entity extracted",
        )
    extra = {}
    slot = SLOT.search(line)
    if slot:
        extra["slot"] = slot.group("slot").rstrip(",;")
    op = OP.search(line)
    if op:
        extra["op"] = op.group("op").rstrip(",;")
    user = USER.search(line)
    username = user.group("user").rstrip(",;") if user else ""
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_pki_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            extra_fields=extra,
            no_match_reason="no hsm entity extracted",
        )
    return build_pki_extraction_result(
        username=username,
        hostname="" if username else "hsm",
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no hsm entity extracted",
    )
