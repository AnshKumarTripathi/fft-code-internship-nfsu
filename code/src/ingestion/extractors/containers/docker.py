"""Docker daemon / json-file extraction (``docker``)."""

from __future__ import annotations

from src.ingestion.extractors.containers.common import (
    build_container_extraction_result,
    parse_container_json_timestamp,
    parse_iso_datetime,
    parse_json_object,
    parse_syslog_fields,
    parse_syslog_or_rfc5424_timestamp,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_docker(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract host/container from dockerd syslog or json-file lines."""
    obj = parse_json_object(line)
    if obj is not None:
        stream = str(obj.get("stream") or "")
        extra = {"stream": stream} if stream else {}
        attrs = obj.get("attrs")
        service = ""
        if isinstance(attrs, dict):
            service = str(attrs.get("name") or attrs.get("container") or "")
        if not service:
            service = str(obj.get("container") or "")
        event_timestamp = parse_container_json_timestamp(obj)
        if event_timestamp is None:
            event_timestamp = parse_iso_datetime(str(obj.get("time") or ""))
        return build_container_extraction_result(
            service=service or stream or "docker",
            extra_fields=extra,
            event_timestamp=event_timestamp,
            ts_ok=event_timestamp is not None,
            no_match_reason="no docker json entity extracted",
            prefer_service=True,
        )
    hostname, program, pid = parse_syslog_fields(line)
    extra: dict[str, str] = {}
    if program:
        extra["program"] = program
    if pid:
        extra["pid"] = pid
    event_timestamp, ts_ok = parse_syslog_or_rfc5424_timestamp(
        line,
        default_year=default_year,
        year_state=year_state,
        year_policy=year_policy,
    )
    return build_container_extraction_result(
        hostname=hostname,
        service="dockerd" if not hostname else "",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no docker entity extracted",
        prefer_service=not hostname,
    )
