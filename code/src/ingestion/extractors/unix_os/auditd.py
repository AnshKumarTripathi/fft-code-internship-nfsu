"""Linux Audit Framework extraction (``linux_auditd``)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.ingestion.extractors.unix_os.common import (
    build_unix_extraction_result,
    normalize_username,
)
from src.ingestion.models import ExtractionResult
from src.ingestion.syslog_time import YEAR_POLICY_CARRY, SyslogYearState

AUDIT_EPOCH = re.compile(
    r"msg=audit\((?P<epoch>\d+)(?:\.(?P<frac>\d+))?:(?P<serial>\d+)\)"
)
AUDIT_TYPE = re.compile(r"\btype=(?P<atype>[A-Za-z0-9_]+)")
AUDIT_KEY = re.compile(
    r'\b(?P<key>auid|uid|euid|pid|success|exe|acct|hostname|addr)=(?P<val>"[^"]*"|\S+)'
)
UNSET_AUID = frozenset({"4294967295", "-1"})


def extract_linux_auditd(
    line: str,
    *,
    default_year: int = 0,
    year_state: SyslogYearState | None = None,
    year_policy: str = YEAR_POLICY_CARRY,
) -> ExtractionResult:
    """Extract user/host from ausearch-style audit records. No syslog carry."""
    del default_year, year_state, year_policy
    fields = {
        match.group("key"): match.group("val").strip('"')
        for match in AUDIT_KEY.finditer(line)
    }
    type_match = AUDIT_TYPE.search(line)
    audit_type = type_match.group("atype") if type_match else ""
    epoch_match = AUDIT_EPOCH.search(line)
    event_timestamp = None
    ts_ok = False
    if epoch_match:
        epoch = int(epoch_match.group("epoch"))
        frac = epoch_match.group("frac") or "0"
        micro = int((frac + "000000")[:6])
        event_timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(
            microsecond=micro
        )
        ts_ok = True

    auid = fields.get("auid", "")
    acct = fields.get("acct", "")
    username = normalize_username(acct)
    if not username and auid and auid not in UNSET_AUID:
        username = normalize_username(auid)

    success_raw = fields.get("success", "").lower()
    success = ""
    if success_raw in {"yes", "no"}:
        success = success_raw

    extra: dict[str, str] = {}
    if audit_type:
        extra["audit_type"] = audit_type
    if auid:
        extra["auid"] = auid
    if fields.get("uid"):
        extra["uid"] = fields["uid"]
    if fields.get("exe"):
        extra["exe"] = fields["exe"]
    if success:
        extra["success"] = success
    if fields.get("pid"):
        extra["pid"] = fields["pid"]

    hostname = fields.get("hostname", "")
    src_ip = fields.get("addr", "")
    return build_unix_extraction_result(
        username=username,
        src_ip=src_ip,
        hostname=hostname,
        program="auditd",
        extra_fields=extra,
        event_timestamp=event_timestamp,
        ts_ok=ts_ok,
        no_match_reason="no linux_auditd entity extracted",
    )
