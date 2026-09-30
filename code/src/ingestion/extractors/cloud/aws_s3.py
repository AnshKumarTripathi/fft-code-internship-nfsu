"""AWS S3 server access log extraction (``aws_s3``)."""

from __future__ import annotations

import re

from src.ingestion.extractors.cloud.common import (
    build_cloud_extraction_result,
    parse_s3_bracket_time,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

REMOTE = re.compile(r"\]\s+(?P<ip>\S+)\s+(?P<requester>\S+)\s+\S+\s+(?P<op>REST\.[A-Z.]+)")
BUCKET = re.compile(r"^\S+\s+(?P<bucket>\S+)\s+\[")


def extract_aws_s3(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract requester IP/user from an S3 server access line."""
    del default_year, year_state, year_policy
    extra: dict[str, str] = {}
    bucket = BUCKET.match(line.strip())
    if bucket:
        extra["bucket"] = bucket.group("bucket")
    remote = REMOTE.search(line)
    src_ip = ""
    username = ""
    if remote:
        src_ip = remote.group("ip")
        requester = remote.group("requester")
        extra["operation"] = remote.group("op")
        if requester not in {"-", "Anonymous"}:
            username = requester.rsplit("/", 1)[-1] if "/" in requester else requester
    event_timestamp = parse_s3_bracket_time(line)
    return build_cloud_extraction_result(
        username=username,
        src_ip=src_ip,
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no s3 entity extracted",
    )
