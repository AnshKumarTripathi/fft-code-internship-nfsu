"""Pod / container stdout-stderr extraction (``k8s_pod``)."""

from __future__ import annotations

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    parse_cri_prefix,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_k8s_pod(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract service/host from a CRI ``kubectl logs`` line."""
    del default_year, year_state, year_policy
    parsed = parse_cri_prefix(line)
    extra: dict[str, str] = {}
    username = ""
    src_ip = ""
    hostname = ""
    service = ""
    event_timestamp = None
    if parsed is not None:
        event_timestamp, stream, tag, message = parsed
        extra["stream"] = stream
        extra["cri_tag"] = tag
        service = stream
        payload = parse_json_object(message)
        if payload is not None:
            username = str(payload.get("user") or payload.get("username") or "")
            src_ip = str(payload.get("src_ip") or payload.get("ip") or "")
            hostname = str(payload.get("host") or payload.get("hostname") or "")
            nested_svc = str(payload.get("service") or payload.get("pod") or "")
            if nested_svc:
                service = nested_svc
        elif message:
            extra["msg"] = message[:200]
    return build_container_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no k8s_pod entity extracted",
        prefer_service=not (username or src_ip or hostname),
    )
