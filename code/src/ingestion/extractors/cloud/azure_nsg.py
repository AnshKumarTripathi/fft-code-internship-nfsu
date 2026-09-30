"""Azure NSG flow extraction (``azure_nsg``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_cloud_json_line,
    parse_cloud_json_timestamp,
    parse_epoch_seconds,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_azure_nsg(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract a source IP from NSG flow JSON or a flow tuple string."""
    del default_year, year_state, year_policy
    obj = parse_cloud_json_line(line)
    extra: dict[str, str] = {}
    src_ip = ""
    event_timestamp = None
    if obj is not None:
        tuples = obj.get("flowTuples")
        if isinstance(tuples, list) and tuples:
            first = str(tuples[0])
            extra["flow_tuple"] = first
            parts = first.split(",")
            if len(parts) >= 3:
                src_ip = parts[1] if parts[1].count(".") == 3 else parts[0]
                if parts[0].isdigit():
                    event_timestamp = parse_epoch_seconds(parts[0])
                    src_ip = parts[1]
        event_timestamp = event_timestamp or parse_cloud_json_timestamp(obj)
        mac = str(obj.get("macAddress") or "")
        if mac:
            extra["mac"] = mac
    else:
        parts = line.strip().split(",")
        if len(parts) >= 4:
            extra["flow_tuple"] = line.strip()
            if parts[0].isdigit():
                event_timestamp = parse_epoch_seconds(parts[0])
                src_ip = parts[1]
            else:
                src_ip = parts[0]
    return build_cloud_extraction_result(
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no nsg entity extracted",
    )
