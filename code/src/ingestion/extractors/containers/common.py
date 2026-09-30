"""Shared timestamp, entity, and raw_fields helpers for container families."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.ingestion.extractors.identity.common import (
    looks_like_ip,
    nested_str,
    normalize_username,
    parse_iso_datetime,
    parse_json_object,
)
from src.ingestion.extractors.unix_os.common import (
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

KLOG = re.compile(
    r"(?P<sev>[IWEF])(?P<mm>\d{2})(?P<dd>\d{2}) "
    r"(?P<hms>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?\s+"
    r"(?P<tid>\d+)\s+"
    r"(?P<file>[^\]\s]+)\]\s*"
)
CRI = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+"
    r"(?P<stream>stdout|stderr)\s+"
    r"(?P<tag>[FP])\s+"
    r"(?P<msg>.*)$"
)
ENVOY = re.compile(
    r'^\[(?P<ts>\d{4}-\d{2}-\d{2}T[^\]]+)\]\s+"'
    r"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/"
)
MESH_CLUSTER = re.compile(
    r"\b(?:outbound|inbound)\|\d+\|[^|]*\|(?P<svc>\S+)"
)
SA_PREFIX = "system:serviceaccount:"
_TS_KEYS = (
    "requestReceivedTimestamp",
    "stageTimestamp",
    "time",
    "timestamp",
    "ts",
    "TimeGenerated",
)


def parse_klog_timestamp(line: str, *, default_year: int) -> datetime | None:
    """Parse bare klog ``I0115 10:00:01.123456``. Does not mutate year-carry."""
    match = KLOG.search(line)
    if match is None:
        return None
    year = default_year if default_year else 1970
    month = int(match.group("mm"))
    day = int(match.group("dd"))
    hour, minute, second = (int(part) for part in match.group("hms").split(":"))
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_cri_prefix(line: str) -> tuple[datetime | None, str, str, str] | None:
    """Return CRI timestamp, stream, tag, and message, else None."""
    match = CRI.match(line.strip())
    if match is None:
        return None
    return (
        parse_iso_datetime(match.group("ts")),
        match.group("stream"),
        match.group("tag"),
        match.group("msg"),
    )


def parse_container_json_timestamp(obj: dict[str, Any]) -> datetime | None:
    """Parse ISO timestamps from container JSON keys. No syslog carry."""
    for key in _TS_KEYS:
        raw = obj.get(key)
        if raw in {None, ""}:
            continue
        parsed = parse_iso_datetime(str(raw))
        if parsed is not None:
            return parsed
    return parse_iso_datetime(str(obj.get("time") or ""))


def service_account_tail(username: str) -> tuple[str, str]:
    """Split ``system:serviceaccount:ns:name`` into namespace and name."""
    token = (username or "").strip()
    if not token.startswith(SA_PREFIX):
        return "", ""
    rest = token[len(SA_PREFIX) :]
    if ":" not in rest:
        return "", rest
    namespace, _, name = rest.partition(":")
    return namespace, name


def canonical_src_ip(raw: str) -> str:
    """Return an IP string, dropping placeholders."""
    token = (raw or "").strip()
    if not token or token in {"-", "localhost"}:
        return ""
    if looks_like_ip(token):
        return token
    return ""


def assign_container_entity(
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    *,
    prefer_service: bool = False,
) -> tuple[str, str]:
    """Apply user → ip → host → service, with optional SA-as-service."""
    user = normalize_username(username)
    if user and user not in {"-"}:
        return user, "user"
    if prefer_service and service and service not in {"-"}:
        return service, "service"
    if src_ip and looks_like_ip(src_ip):
        return src_ip, "ip"
    if hostname and hostname not in {"-"}:
        return hostname, "host"
    if service and service not in {"-"}:
        return service, "service"
    return "", "host"


def build_container_extraction_result(
    *,
    username: str = "",
    src_ip: str = "",
    hostname: str = "",
    service: str = "",
    extra_fields: dict[str, Any] | None = None,
    event_timestamp: datetime | None,
    ts_ok: bool,
    no_match_reason: str,
    prefer_service: bool = False,
) -> ExtractionResult:
    """Build an ExtractionResult with canonical container raw_fields."""
    user = normalize_username(username)
    if user in {"-"}:
        user = ""
    src = canonical_src_ip(src_ip)
    host = hostname if hostname not in {"", "-"} else ""
    svc = service if service not in {"", "-"} else ""
    raw_fields: dict[str, Any] = {}
    if user:
        raw_fields["username"] = user
    if src:
        raw_fields["src_ip"] = src
    if host:
        raw_fields["hostname"] = host
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_container_entity(
        user, src, host, svc, prefer_service=prefer_service
    )
    if not entity_id:
        return ExtractionResult(
            event_timestamp=event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason=no_match_reason,
        )
    return ExtractionResult(
        entity_id=entity_id,
        entity_type=entity_type,  # type: ignore[arg-type]
        event_timestamp=event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if ts_ok else "timestamp parse failed",
    )


def extract_klog_component(
    line: str,
    *,
    component: str,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/service from a kube-component klog or syslog line."""
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {"component": component}
    if pid:
        extra["pid"] = pid
    if program:
        extra["program"] = program
    klog = KLOG.search(line)
    if klog:
        extra["klog_file"] = klog.group("file")
        extra["severity"] = klog.group("sev")
    event_timestamp = None
    ts_ok = False
    if hostname:
        event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
            line,
            default_year=default_year,
            year_state=year_state,
            year_policy=year_policy,
        )
    if event_timestamp is None:
        event_timestamp = parse_klog_timestamp(line, default_year=default_year)
        ts_ok = event_timestamp is not None
    service = "" if hostname else component
    return build_container_extraction_result(
        hostname=hostname,
        service=service,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason=f"no {component} entity extracted",
        prefer_service=not hostname,
    )


__all__ = [
    "CRI",
    "ENVOY",
    "KLOG",
    "MESH_CLUSTER",
    "assign_container_entity",
    "build_container_extraction_result",
    "canonical_src_ip",
    "extract_klog_component",
    "looks_like_ip",
    "nested_str",
    "normalize_username",
    "parse_container_json_timestamp",
    "parse_cri_prefix",
    "parse_iso_datetime",
    "parse_json_object",
    "parse_klog_timestamp",
    "parse_syslog_fields",
    "parse_syslog_or_rfc5424_timestamp",
    "service_account_tail",
]
