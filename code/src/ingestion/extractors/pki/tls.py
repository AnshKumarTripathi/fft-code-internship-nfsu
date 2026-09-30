"""TLS handshake / negotiation extraction (``tls``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.pki.common import (
    YEAR_POLICY_CARRY,
    build_pki_extraction_result,
    canonical_src_ip,
    extract_syslog_pki_line,
    parse_syslog_fields,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import SyslogYearState

FROM_IP = re.compile(
    r"\b(?:from|client)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b",
    re.IGNORECASE,
)
TLS_VER = re.compile(r"\b(TLS(?:v?\d(?:\.\d)?)?)\b", re.IGNORECASE)


def extract_tls(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP (else syslog host) from handshake lines."""
    ip_match = FROM_IP.search(line)
    src_ip = canonical_src_ip(ip_match.group("ip") if ip_match else "")
    extra: dict[str, str] = {}
    ver = TLS_VER.search(line)
    if ver:
        extra["tls_version"] = ver.group(1)
    hostname, _program, _pid = parse_syslog_fields(line)
    if hostname:
        return extract_syslog_pki_line(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
            src_ip=src_ip,
            extra_fields=extra,
            no_match_reason="no tls entity extracted",
        )
    return build_pki_extraction_result(
        src_ip=src_ip,
        hostname="" if src_ip else "tls",
        extra_fields=extra,
        event_timestamp=None,
        ts_ok=False,
        no_match_reason="no tls entity extracted",
    )
