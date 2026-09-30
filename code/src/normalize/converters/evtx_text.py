"""evtx_text converter — binary EVTX → one-line Windows Event Log text.

Locked dialect (Phase 81): ``text_oneline`` matching Phase 20 fixtures, e.g.::

    TimeCreated=2017-06-23T05:31:19.787Z EventID=4672 Id=4672 LogName=Security
    Computer=HOSTNAME SubjectUserName=alice …

Uses pure-Python ``python-evtx`` (preferred). Optional Windows ``wevtutil``
fallback is not required for MVP. Missing library → ``converter_unavailable``.
Legacy ``.evt`` is not supported by python-evtx → dead-letter ``unsupported_evt``.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

from src.normalize.converters._common import (
    check_byte_budget,
    resolve_under,
)
from src.normalize.models import ConvertedFile, ConverterError, ConverterResult

_EVTX_MAGIC = b"ElfFile\x00"
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
_SPACE_RE = re.compile(r"\s+")


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _text(elem: ET.Element | None) -> str:
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def _attr(elem: ET.Element | None, name: str) -> str:
    if elem is None:
        return ""
    return str(elem.attrib.get(name, "")).strip()


def _normalize_system_time(raw: str) -> str:
    """Collapse python-evtx SystemTime quirks to ISO-8601-ish Zulu."""
    value = raw.strip()
    if not value:
        return value
    # e.g. "2017-06-23 05:31:19.787264+00:00"
    value = value.replace(" ", "T", 1)
    if value.endswith("+00:00"):
        value = value[:-6] + "Z"
    elif value.endswith("UTC"):
        value = value[:-3].rstrip() + "Z"
    # Trim excessive fractional digits to millis for readability
    if "." in value and "Z" in value:
        head, rest = value.split(".", 1)
        frac = rest.split("Z", 1)[0]
        value = f"{head}.{frac[:3].ljust(3, '0')}Z"
    return value


def event_xml_to_oneline(xml_text: str) -> str:
    """Flatten one Event XML record to a single Phase-20-compatible text line."""
    root = ET.fromstring(xml_text)
    system = None
    event_data = None
    for child in root:
        name = _local(child.tag)
        if name == "System":
            system = child
        elif name == "EventData":
            event_data = child

    fields: dict[str, str] = {}
    if system is not None:
        for child in system:
            name = _local(child.tag)
            if name == "TimeCreated":
                fields["TimeCreated"] = _normalize_system_time(
                    _attr(child, "SystemTime")
                )
            elif name == "EventID":
                fields["EventID"] = _text(child)
                fields["Id"] = fields["EventID"]
            elif name == "Channel":
                fields["LogName"] = _text(child)
            elif name == "Computer":
                fields["Computer"] = _text(child)
            elif name == "Provider":
                provider = _attr(child, "Name")
                if provider:
                    fields["Provider"] = provider
            elif name == "Level":
                if _text(child):
                    fields["Level"] = _text(child)
            elif name == "Task":
                if _text(child):
                    fields["Task"] = _text(child)

    if event_data is not None:
        for child in event_data:
            if _local(child.tag) != "Data":
                continue
            key = _attr(child, "Name") or "Data"
            val = _text(child)
            if not key or not val:
                continue
            # Avoid spaces/newlines breaking the one-line dialect
            fields[key] = _SPACE_RE.sub(" ", val)

    # Stable key order: TimeCreated, EventID, Id, LogName, Computer, Provider, rest
    preferred = (
        "TimeCreated",
        "EventID",
        "Id",
        "LogName",
        "Computer",
        "Provider",
        "Level",
        "Task",
    )
    parts: list[str] = []
    seen: set[str] = set()
    for key in preferred:
        if key in fields and fields[key]:
            parts.append(f"{key}={fields[key]}")
            seen.add(key)
    for key in sorted(k for k in fields if k not in seen and fields[k]):
        parts.append(f"{key}={fields[key]}")
    if not parts:
        raise ConverterError("empty Event XML after flatten", reason="corrupt")
    return " ".join(parts)


def event_xml_to_jsonl(xml_text: str) -> str:
    """Compact JSONL object from Event XML (optional output_format)."""
    line = event_xml_to_oneline(xml_text)
    obj: dict[str, Any] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        obj[key] = value
    return json.dumps(obj, ensure_ascii=False)


def _iter_evtx_xml(path: Path) -> Iterator[str]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ConverterError(
            "python-evtx is not installed; pip install python-evtx",
            reason="converter_unavailable",
        ) from exc

    try:
        with Evtx(str(path)) as log:
            for record in log.records():
                yield record.xml()
    except ConverterError:
        raise
    except Exception as exc:  # noqa: BLE001 — surface as corrupt/unavailable
        raise ConverterError(f"evtx parse failed: {exc}", reason="corrupt") from exc


def convert_evtx_text(
    source: Path,
    output_dir: Path,
    *,
    relative_base: str,
    max_member_bytes: int,
    max_total_output_bytes: int,
    bytes_written_so_far: int,
    max_members_per_archive: int,
    settings: dict[str, Any] | None = None,
) -> ConverterResult:
    _ = max_members_per_archive
    settings = settings or {}
    evtx_cfg = settings.get("evtx") or {}
    if not isinstance(evtx_cfg, dict):
        evtx_cfg = {}
    output_format = str(evtx_cfg.get("output_format", "text_oneline"))
    max_events = int(evtx_cfg.get("max_events", 500_000))

    suffix = source.suffix.lower()
    if suffix == ".evt":
        raise ConverterError(
            "legacy .evt is not supported by python-evtx; convert with wevtutil first",
            reason="unsupported_evt",
        )

    # Guard: empty / clearly not EVTX
    prefix = source.read_bytes()[:8]
    if prefix and not prefix.startswith(_EVTX_MAGIC[: len(prefix)]):
        # Still attempt parse — some truncated reads; magic mismatch → corrupt
        if len(prefix) >= 8 and not prefix.startswith(_EVTX_MAGIC):
            raise ConverterError(
                "file does not start with ElfFile EVTX magic",
                reason="corrupt",
            )

    rel_parent = str(Path(relative_base).parent).replace("\\", "/")
    out_name = f"{source.name}.txt" if output_format != "jsonl" else f"{source.stem}.jsonl"
    if rel_parent in (".", ""):
        relative = out_name
    else:
        relative = f"{rel_parent}/{out_name}"
    destination = resolve_under(output_dir, relative)

    lines: list[str] = []
    count = 0
    for xml_text in _iter_evtx_xml(source):
        count += 1
        if count > max_events:
            raise ConverterError(
                f"evtx exceeds max_events ({max_events})",
                reason="member_cap",
            )
        if output_format == "jsonl":
            lines.append(event_xml_to_jsonl(xml_text))
        else:
            lines.append(event_xml_to_oneline(xml_text))

    if not lines:
        raise ConverterError("evtx contained no records", reason="empty_archive")

    payload = ("\n".join(lines) + "\n").encode("utf-8")
    check_byte_budget(
        adding=len(payload),
        member_bytes=len(payload),
        max_member_bytes=max_member_bytes,
        bytes_written_so_far=bytes_written_so_far,
        max_total_output_bytes=max_total_output_bytes,
    )
    # Rename-only guard: never write source bytes unchanged
    if payload == source.read_bytes():
        raise ConverterError(
            "evtx_text refused rename-only output (bytes identical to input)",
            reason="rename_only",
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return ConverterResult(
        files=[
            ConvertedFile(
                output_path=destination,
                bytes_out=len(payload),
                converter="evtx_text",
            )
        ]
    )
