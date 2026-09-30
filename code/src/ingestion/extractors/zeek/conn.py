"""Zeek ``conn.log`` TSV extraction (``zeek_conn``)."""

from __future__ import annotations

from src.ingestion.extractors.zeek.common import (
    DEFAULT_CONN_FIELDS,
    build_zeek_result,
    is_zeek_comment,
    parse_zeek_ts,
    update_zeek_fields_state,
    zeek_row_dict,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_zeek_conn(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract orig/resp hosts from a Zeek conn TSV line."""
    del default_year, year_policy
    stripped = line.strip()
    if not stripped:
        return build_zeek_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="empty zeek_conn line",
        )
    if update_zeek_fields_state(stripped, year_state) is not None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="zeek_header",
            raw_fields={"dialect": "zeek_conn"},
        )
    if is_zeek_comment(stripped):
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="zeek_comment",
            raw_fields={"dialect": "zeek_conn"},
        )

    fields = (year_state.zeek_fields if year_state else None) or DEFAULT_CONN_FIELDS
    row = zeek_row_dict(stripped, fields)
    if row is None:
        return build_zeek_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no zeek_conn row",
        )

    event_timestamp = parse_zeek_ts(row.get("ts"))
    extra = {
        "dialect": "zeek_conn",
        "protocol": row.get("proto", ""),
        "service": row.get("service", ""),
        "conn_state": row.get("conn_state", ""),
        "uid": row.get("uid", ""),
    }
    if row.get("id.orig_p"):
        extra["src_port"] = row["id.orig_p"]
    if row.get("id.resp_p"):
        extra["dst_port"] = row["id.resp_p"]
    if row.get("duration"):
        extra["duration"] = row["duration"]
    if row.get("orig_bytes"):
        extra["orig_bytes"] = row["orig_bytes"]
    if row.get("resp_bytes"):
        extra["resp_bytes"] = row["resp_bytes"]

    return build_zeek_result(
        src_ip=row.get("id.orig_h", ""),
        dst_ip=row.get("id.resp_h", ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no zeek_conn entity extracted",
    )
