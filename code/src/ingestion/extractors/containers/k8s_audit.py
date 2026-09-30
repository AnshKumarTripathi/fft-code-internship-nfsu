"""Kubernetes audit JSON extraction (``k8s_audit``)."""

from __future__ import annotations

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    parse_container_json_timestamp,
    parse_json_object,
    service_account_tail,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_k8s_audit(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user or service account and source IP from a K8s audit line."""
    del default_year, year_state, year_policy
    obj = parse_json_object(line)
    if obj is None:
        return build_container_extraction_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no k8s audit JSON object",
        )
    user = obj.get("user") if isinstance(obj.get("user"), dict) else {}
    username = str(user.get("username") or "")
    namespace, sa_name = service_account_tail(username)
    extra: dict[str, str] = {}
    verb = str(obj.get("verb") or "")
    if verb:
        extra["verb"] = verb
    uri = str(obj.get("requestURI") or "")
    if uri:
        extra["request_uri"] = uri
    groups = user.get("groups")
    if isinstance(groups, list) and groups:
        extra["groups"] = ",".join(str(item) for item in groups[:8])
    service = ""
    entity_user = username
    prefer_service = False
    if sa_name:
        service = sa_name
        extra["service_account"] = sa_name
        if namespace:
            extra["sa_namespace"] = namespace
        extra["username"] = username
        entity_user = ""
        prefer_service = True
    source_ips = obj.get("sourceIPs")
    src_ip = ""
    if isinstance(source_ips, list) and source_ips:
        src_ip = str(source_ips[0] or "")
    event_timestamp = parse_container_json_timestamp(obj)
    return build_container_extraction_result(
        username=entity_user,
        src_ip=src_ip,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no k8s audit entity extracted",
        prefer_service=prefer_service,
    )
