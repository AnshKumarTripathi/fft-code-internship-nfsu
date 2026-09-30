"""Zeek ``dns.log`` TSV extraction (``zeek_dns``)."""

from __future__ import annotations

from src.ingestion.extractors.zeek.common import (
    DEFAULT_DNS_FIELDS,
    build_zeek_result,
    is_zeek_comment,
    parse_zeek_ts,
    update_zeek_fields_state,
    zeek_row_dict,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState


def extract_zeek_dns(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract client IP and DNS query from a Zeek dns TSV line."""
    del default_year, year_policy
    stripped = line.strip()
    if not stripped:
        return build_zeek_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="empty zeek_dns line",
        )
    if update_zeek_fields_state(stripped, year_state) is not None:
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="zeek_header",
            raw_fields={"dialect": "zeek_dns"},
        )
    if is_zeek_comment(stripped):
        return ExtractionResult(
            extraction_ok=False,
            failure_reason="zeek_comment",
            raw_fields={"dialect": "zeek_dns"},
        )

    fields = (year_state.zeek_fields if year_state else None) or DEFAULT_DNS_FIELDS
    row = zeek_row_dict(stripped, fields)
    if row is None:
        return build_zeek_result(
            event_timestamp=None,
            ts_ok=False,
            no_match_reason="no zeek_dns row",
        )

    event_timestamp = parse_zeek_ts(row.get("ts"))
    extra = {
        "dialect": "zeek_dns",
        "protocol": row.get("proto", ""),
        "uid": row.get("uid", ""),
        "query": row.get("query", ""),
        "qtype": row.get("qtype_name") or row.get("qtype", ""),
        "rcode": row.get("rcode_name") or row.get("rcode", ""),
    }
    if row.get("id.orig_p"):
        extra["src_port"] = row["id.orig_p"]
    if row.get("id.resp_p"):
        extra["dst_port"] = row["id.resp_p"]
    if row.get("answers"):
        extra["answers"] = row["answers"]

    return build_zeek_result(
        src_ip=row.get("id.orig_h", ""),
        dst_ip=row.get("id.resp_h", ""),
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=event_timestamp is not None,
        no_match_reason="no zeek_dns entity extracted",
    )
