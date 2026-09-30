"""CA issuance / revocation extraction (``pki_ca``)."""

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

CN = re.compile(r"\bcn=(?P<cn>\S+)", re.IGNORECASE)
USER = re.compile(r"\buser=(?P<user>\S+)", re.IGNORECASE)
ISSUED = re.compile(r"\bissued\b|\bissue\b", re.IGNORECASE)
REVOKED = re.compile(r"\brevoked\b|\brevoke\b", re.IGNORECASE)


def _cn_from_obj(obj: dict) -> str:
    raw = str(obj.get("cn") or obj.get("subject") or "").strip()
    if raw.upper().startswith("CN="):
        return raw[3:].strip()
    return raw


def _action_fields(action: str) -> dict[str, str]:
    extra: dict[str, str] = {}
    token = action.strip().lower()
    if token in {"issued", "issue"}:
        extra["action"] = "issued"
        extra["auth_result"] = "success"
    elif token in {"revoked", "revoke"}:
        extra["action"] = "revoked"
    return extra


def extract_pki_ca(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract CN as service (else user/host); store issued/revoked action."""
    obj = parse_json_object(line)
    if obj is not None:
        username = str(obj.get("user") or obj.get("username") or "").strip()
        cn = _cn_from_obj(obj)
        extra = _action_fields(str(obj.get("action") or obj.get("event") or ""))
        if cn:
            extra["cn"] = cn
        event_timestamp = parse_pki_json_timestamp(obj)
        return build_pki_extraction_result(
            username=username,
            service="" if username else cn,
            hostname="" if username or cn else "ca",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no pki_ca JSON entity extracted",
        )
    extra: dict[str, str] = {}
    cn_match = CN.search(line)
    cn = cn_match.group("cn").rstrip(",;") if cn_match else ""
    if cn:
        extra["cn"] = cn
    user_match = USER.search(line)
    username = user_match.group("user").rstrip(",;") if user_match else ""
    if ISSUED.search(line) and not REVOKED.search(line):
        extra.update(_action_fields("issued"))
    elif REVOKED.search(line):
        extra.update(_action_fields("revoked"))
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_pki_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            username=username,
            service="" if username else cn,
            extra_fields=extra,
            no_match_reason="no pki_ca entity extracted",
        )
    return build_pki_extraction_result(
        username=username,
        service="" if username else cn,
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no pki_ca entity extracted",
    )
