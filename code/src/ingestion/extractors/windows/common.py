"""Shared EventID / TimeCreated / entity helpers for Windows Event Log text."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.ingestion.models import ExtractionResult

_LOOKS_LIKE_IP = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:+[0-9a-fA-F:.]+)$"
)
_KV_PAIR = re.compile(
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)"
)
_EVENT_ID_PATTERNS = (
    re.compile(r"<EventID[^>]*>(\d+)</EventID>", re.IGNORECASE),
    re.compile(r"\bEventID\s*[=:]\s*(\d+)", re.IGNORECASE),
    re.compile(r"\bEvent\s*ID\s*[=:]\s*(\d+)", re.IGNORECASE),
    re.compile(r"\bId\s*[=:]\s*(\d+)", re.IGNORECASE),
)
_TIME_CREATED_KV = re.compile(
    r"\bTimeCreated\s*=\s*(?P<value>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
    re.IGNORECASE,
)
_SYSTEM_TIME_ATTR = re.compile(
    r'SystemTime\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
_ISO_IN_LINE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
_US_DATETIME = re.compile(
    r"(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{4})\s+"
    r"(?P<hour>\d{1,2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\s*(?P<ampm>[APap][Mm]))?"
)
_CHANNEL_KV = re.compile(
    r"\b(?:LogName|Channel)\s*=\s*(?P<name>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
    re.IGNORECASE,
)
_PROVIDER_KV = re.compile(
    r"\b(?:ProviderName|Provider)\s*=\s*(?P<name>.+?)(?=\s+[A-Za-z_][A-Za-z0-9_]*=|$)",
    re.IGNORECASE,
)
_PROVIDER_NAME_ATTR = re.compile(
    r'Provider\s+Name\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
_REJECT_USERS = frozenset({"-", "", "ANONYMOUS LOGON"})

USER_KEYS = (
    "TargetUserName",
    "UserName",
    "User",
    "AccountName",
    "SubjectUserName",
    "DetectionUser",
)


@dataclass
class WindowsRecord:
    """Parsed fields from a one-line Windows Event Log export."""

    event_id: int | None = None
    event_timestamp: datetime | None = None
    ts_ok: bool = False
    computer: str = ""
    channel: str = ""
    log_name: str = ""
    provider: str = ""
    username: str = ""
    target_user: str = ""
    subject_user: str = ""
    src_ip: str = ""
    workstation: str = ""
    logon_type: str = ""
    auth_package: str = ""
    forwarded_channel: str = ""
    fields: dict[str, str] = field(default_factory=dict)


def looks_like_ip(token: str) -> bool:
    """Return True when ``token`` looks like IPv4 or IPv6."""
    if not token or token in {":", "*", "-", "0.0.0.0", "::", "-"}:
        return False
    return _LOOKS_LIKE_IP.fullmatch(token) is not None


def parse_event_id(line: str) -> int | None:
    """Return the first EventID / Id integer on the line, if present."""
    for pattern in _EVENT_ID_PATTERNS:
        match = pattern.search(line)
        if match:
            return int(match.group(1))
    return None


def parse_windows_timestamp(line: str) -> tuple[datetime | None, bool]:
    """Parse TimeCreated / ISO-8601 / US datetime. Never applies syslog year-carry."""
    candidates: list[str] = []
    kv = _TIME_CREATED_KV.search(line)
    if kv:
        candidates.append(kv.group("value").strip().strip('"'))
    attr = _SYSTEM_TIME_ATTR.search(line)
    if attr:
        candidates.append(attr.group(1))
    iso = _ISO_IN_LINE.search(line)
    if iso:
        candidates.append(iso.group(0))

    for raw in candidates:
        parsed = _parse_datetime_token(raw)
        if parsed is not None:
            return parsed, True

    us_match = _US_DATETIME.search(line)
    if us_match:
        parsed = _parse_us_datetime(us_match)
        if parsed is not None:
            return parsed, True
    return None, False


def parse_windows_record(line: str) -> WindowsRecord:
    """Parse compact text or a single-line XML Event into a WindowsRecord."""
    if "<Event xmlns" in line:
        record = _parse_xml_event(line)
        if record.event_id is not None or record.computer or record.fields:
            return record
    return _parse_text_event(line)


def extract_channel(line: str) -> str:
    """Return LogName= / Channel= value when present."""
    match = _CHANNEL_KV.search(line)
    if match:
        return match.group("name").strip().strip('"')
    return ""


def extract_provider(line: str) -> str:
    """Return Provider / ProviderName when present."""
    attr = _PROVIDER_NAME_ATTR.search(line)
    if attr:
        return attr.group(1).strip()
    match = _PROVIDER_KV.search(line)
    if match:
        return match.group("name").strip().strip('"')
    return ""


def normalize_username(username: str) -> str:
    """Drop placeholders that must not become the entity."""
    if not username:
        return ""
    stripped = username.strip().strip('"')
    if stripped.upper() in _REJECT_USERS or stripped == "-":
        return ""
    return stripped


def assign_windows_entity(
    username: str,
    src_ip: str,
    workstation: str,
    hostname: str,
    service: str = "",
) -> tuple[str, str]:
    """Apply user → ip → workstation/host → service entity policy."""
    user = normalize_username(username)
    if user:
        return user, "user"
    if src_ip:
        return src_ip, "ip"
    if workstation:
        return workstation, "host"
    if hostname:
        return hostname, "host"
    if service:
        return service, "service"
    return "", "user"


def build_windows_extraction_result(
    record: WindowsRecord,
    *,
    event_class: str = "",
    auth_result: str = "",
    extra_fields: dict[str, Any] | None = None,
    no_match_reason: str = "no windows entity extracted",
    use_service: bool = False,
) -> ExtractionResult:
    """Build an ExtractionResult from a parsed Windows record."""
    username = normalize_username(
        record.target_user or record.username or record.subject_user
    )
    hostname = record.computer
    src_ip = record.src_ip
    workstation = record.workstation
    service = record.provider if use_service else ""

    raw_fields: dict[str, Any] = {}
    if record.event_id is not None:
        raw_fields["event_id"] = record.event_id
    if record.channel:
        raw_fields["channel"] = record.channel
    if record.log_name:
        raw_fields["log_name"] = record.log_name
    if hostname:
        raw_fields["hostname"] = hostname
        raw_fields["computer"] = hostname
    if username:
        raw_fields["username"] = username
    if record.target_user:
        raw_fields["target_user"] = record.target_user
    if record.subject_user:
        raw_fields["subject_user"] = record.subject_user
    if src_ip:
        raw_fields["src_ip"] = src_ip
    if workstation:
        raw_fields["workstation"] = workstation
    if record.logon_type:
        raw_fields["logon_type"] = record.logon_type
    if auth_result:
        raw_fields["auth_result"] = auth_result
    if event_class:
        raw_fields["event_class"] = event_class
    if record.provider:
        raw_fields["provider"] = record.provider
    if record.forwarded_channel:
        raw_fields["forwarded_channel"] = record.forwarded_channel
    if extra_fields:
        for key, value in extra_fields.items():
            if value not in {None, ""}:
                raw_fields[key] = value
    if not record.ts_ok:
        raw_fields["timestamp_parse_failed"] = True

    entity_id, entity_type = assign_windows_entity(
        username,
        src_ip,
        workstation,
        hostname,
        service,
    )
    if not entity_id:
        return ExtractionResult(
            event_timestamp=record.event_timestamp,
            raw_fields=raw_fields,
            extraction_ok=False,
            failure_reason=no_match_reason,
        )
    return ExtractionResult(
        entity_id=entity_id,
        entity_type=entity_type,  # type: ignore[arg-type]
        event_timestamp=record.event_timestamp,
        raw_fields=raw_fields,
        extraction_ok=True,
        failure_reason=None if record.ts_ok else "timestamp parse failed",
    )


def _parse_text_event(line: str) -> WindowsRecord:
    fields = {match.group("key"): match.group("value").strip() for match in _KV_PAIR.finditer(line)}
    event_id = parse_event_id(line)
    timestamp, ts_ok = parse_windows_timestamp(line)
    computer = fields.get("Computer", "")
    log_name = fields.get("LogName", "") or fields.get("Channel", "")
    channel = fields.get("Channel", "") or log_name
    provider = (
        fields.get("ProviderName", "")
        or fields.get("Provider", "")
        or extract_provider(line)
    )
    target_user = fields.get("TargetUserName", "")
    subject_user = fields.get("SubjectUserName", "")
    username = _first_field(fields, USER_KEYS)
    src_ip, workstation = _ip_and_workstation(fields)
    forwarded = fields.get("ForwardedChannel", "")
    if log_name.lower() == "forwardedevents" and channel.lower() not in {
        "",
        "forwardedevents",
    }:
        forwarded = forwarded or channel

    return WindowsRecord(
        event_id=event_id,
        event_timestamp=timestamp,
        ts_ok=ts_ok,
        computer=computer,
        channel=channel,
        log_name=log_name,
        provider=provider,
        username=username,
        target_user=target_user,
        subject_user=subject_user,
        src_ip=src_ip,
        workstation=workstation,
        logon_type=fields.get("LogonType", ""),
        auth_package=fields.get("AuthenticationPackageName", "")
        or fields.get("AuthenticationPackage", ""),
        forwarded_channel=forwarded,
        fields=fields,
    )


def _parse_xml_event(line: str) -> WindowsRecord:
    try:
        root = ET.fromstring(line.strip())
    except ET.ParseError:
        return _parse_text_event(line)

    fields: dict[str, str] = {}
    event_id: int | None = None
    timestamp: datetime | None = None
    ts_ok = False
    computer = ""
    channel = ""
    provider = ""

    for elem in root.iter():
        tag = _local_tag(elem.tag)
        if tag == "EventID" and elem.text and elem.text.strip().isdigit():
            event_id = int(elem.text.strip())
        elif tag == "TimeCreated":
            system_time = elem.attrib.get("SystemTime", "")
            timestamp, ts_ok = parse_windows_timestamp(f'TimeCreated={system_time}')
        elif tag == "Computer" and elem.text:
            computer = elem.text.strip()
        elif tag == "Channel" and elem.text:
            channel = elem.text.strip()
        elif tag == "Provider":
            provider = elem.attrib.get("Name", "") or provider
        elif tag == "Data":
            name = elem.attrib.get("Name", "")
            value = (elem.text or "").strip()
            if name:
                fields[name] = value

    src_ip, workstation = _ip_and_workstation(fields)
    return WindowsRecord(
        event_id=event_id,
        event_timestamp=timestamp,
        ts_ok=ts_ok,
        computer=computer,
        channel=channel,
        log_name=channel,
        provider=provider,
        username=_first_field(fields, USER_KEYS),
        target_user=fields.get("TargetUserName", ""),
        subject_user=fields.get("SubjectUserName", ""),
        src_ip=src_ip,
        workstation=workstation,
        logon_type=fields.get("LogonType", ""),
        auth_package=fields.get("AuthenticationPackageName", "")
        or fields.get("AuthenticationPackage", ""),
        fields=fields,
    )


def _first_field(fields: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = fields.get(key, "")
        if value:
            return value
    return ""


def _ip_and_workstation(fields: dict[str, str]) -> tuple[str, str]:
    src_ip = ""
    for key in ("IpAddress", "IPAddress", "SourceAddress", "ClientAddress", "Address"):
        value = fields.get(key, "").strip()
        if looks_like_ip(value):
            src_ip = value
            break
    workstation = fields.get("WorkstationName", "") or fields.get("Workstation", "")
    if workstation in {"-", ""}:
        workstation = ""
    if not src_ip and looks_like_ip(workstation):
        src_ip = workstation
        workstation = ""
    elif workstation == src_ip:
        workstation = ""
    return src_ip, workstation


def _parse_datetime_token(raw: str) -> datetime | None:
    token = raw.strip().strip('"').strip("'")
    if not token:
        return None
    us_match = _US_DATETIME.fullmatch(token) or _US_DATETIME.search(token)
    if us_match and "/" in token and "T" not in token:
        parsed = _parse_us_datetime(us_match)
        if parsed is not None:
            return parsed
    iso = token
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_us_datetime(match: re.Match[str]) -> datetime | None:
    month = int(match.group("month"))
    day = int(match.group("day"))
    year = int(match.group("year"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    ampm = match.group("ampm")
    if ampm:
        ampm = ampm.upper()
        if ampm == "PM" and hour != 12:
            hour += 12
        elif ampm == "AM" and hour == 12:
            hour = 0
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None


def _local_tag(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag
