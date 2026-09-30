"""Kubernetes admission-controller extraction (``k8s_admission``)."""

from __future__ import annotations

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    extract_klog_component,
    nested_str,
    parse_container_json_timestamp,
    parse_json_object,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_k8s_admission(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/service from AdmissionReview JSON or admission klog."""
    obj = parse_json_object(line)
    if obj is None:
        return extract_klog_component(
            line,
            component="admission",
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    username = nested_str(obj, "request", "userInfo", "username")
    namespace = nested_str(obj, "request", "namespace")
    extra: dict[str, str] = {}
    uid = nested_str(obj, "request", "uid")
    if uid:
        extra["uid"] = uid
    kind = nested_str(obj, "request", "kind", "kind")
    if kind:
        extra["resource_kind"] = kind
    if namespace:
        extra["namespace"] = namespace
    event_timestamp = parse_container_json_timestamp(obj)
    service = "admission" if not username else ""
    return build_container_extraction_result(
        username=username,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no k8s admission entity extracted",
        prefer_service=not username,
    )
