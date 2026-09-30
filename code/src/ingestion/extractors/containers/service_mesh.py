"""Istio Envoy / Linkerd access-log extraction (``service_mesh``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.containers.common import (
    ENVOY,
    MESH_CLUSTER,
    build_container_extraction_result,
    looks_like_ip,
    parse_iso_datetime,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

_IP_PORT = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):\d+")


def extract_service_mesh(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP and upstream service from an Envoy/Istio access line."""
    del default_year, year_state, year_policy
    stripped = line.strip()
    extra: dict[str, str] = {}
    src_ip = ""
    service = ""
    event_timestamp = None
    match = ENVOY.match(stripped)
    if match:
        event_timestamp = parse_iso_datetime(match.group("ts"))
        extra["method"] = match.group("method")
        extra["path"] = match.group("path")
    cluster = MESH_CLUSTER.search(stripped)
    if cluster:
        service = cluster.group("svc").rstrip('"')
        extra["mesh_cluster"] = cluster.group(0)
    if "istio" in stripped.lower():
        extra["mesh"] = "istio"
    elif "linkerd" in stripped.lower() or "l5d-" in stripped.lower():
        extra["mesh"] = "linkerd"
    for found in _IP_PORT.finditer(stripped):
        candidate = found.group("ip")
        if looks_like_ip(candidate):
            src_ip = candidate
            break
    if not service:
        service = extra.get("mesh") or "envoy"
    return build_container_extraction_result(
        src_ip=src_ip,
        service=service if not src_ip else service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no service_mesh entity extracted",
        prefer_service=not src_ip,
    )
