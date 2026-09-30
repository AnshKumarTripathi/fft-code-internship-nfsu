"""AWS VPC Flow Logs extraction (``aws_vpcflow``)."""

from __future__ import annotations

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_epoch_seconds,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_aws_vpcflow(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract src/dst IP and action from default v2 VPC Flow text."""
    del default_year, year_state, year_policy
    parts = line.strip().split()
    extra: dict[str, str] = {}
    src_ip = ""
    dst_ip = ""
    action = ""
    event_timestamp = None
    if len(parts) >= 13:
        extra["account_id"] = parts[1]
        extra["interface"] = parts[2]
        src_ip = parts[3]
        dst_ip = parts[4]
        extra["src_port"] = parts[5]
        extra["dst_port"] = parts[6]
        extra["protocol"] = parts[7]
        event_timestamp = parse_epoch_seconds(parts[10])
        action = parts[12].lower()
        extra["action"] = "allow" if action == "accept" else "deny" if action == "reject" else action
        extra["dst_ip"] = dst_ip
    return build_cloud_extraction_result(
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no vpcflow entity extracted",
    )
