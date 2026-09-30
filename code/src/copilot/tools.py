"""Allow-listed copilot context tools (Phase 96). No warehouse mutation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from src.api.queries import (
    DEFAULT_ENTITY_RANK_LIMIT,
    MAX_ENTITY_RANK_LIMIT,
    count_incidents,
    get_entity_meta,
    get_incident,
    get_incident_detail,
    list_entity_incidents,
    list_incidents,
    list_top_entities_by_anomaly_count,
)
from src.api.report_files import resolve_report_file
from src.copilot.docs_loader import DocsLoadError, load_docs_markdown
from src.explainability.playbooks import DEFAULT_PLAYBOOKS, load_playbooks, playbook_for
from src.reporting.narrative_llm import build_incident_brief
from src.reporting.report_generator import IncidentRow, build_context

ALLOWED_TOOLS = frozenset(
    {
        "get_incident_brief",
        "get_why_flagged",
        "get_report_excerpt",
        "get_docs_section",
        "rank_entities_by_anomalies",
        "list_incidents_ranked",
        "get_entity_overview",
    }
)

DEFAULT_REPORT_EXCERPT_CHARS = 4000
DEFAULT_DOCS_CHARS = 6000
DEFAULT_INCIDENT_RANK_LIMIT = 10
MAX_INCIDENT_RANK_LIMIT = 20
DEFAULT_ENTITY_OVERVIEW_INCIDENTS = 5


class ToolError(Exception):
    """Allow-listed tool failed or refused."""


@dataclass
class ToolContext:
    """Read-only resources for tool execution."""

    connection: Any | None
    config: dict[str, Any]
    report_dir: Path
    docs_root: Path | None = None
    max_timeline_events: int = 20
    max_report_chars: int = DEFAULT_REPORT_EXCERPT_CHARS
    max_docs_chars: int = DEFAULT_DOCS_CHARS
    warn_band: float = 0.5


def _require_connection(ctx: ToolContext) -> Any:
    if ctx.connection is None:
        raise ToolError("warehouse unavailable")
    return ctx.connection


def _require_incident_id(incident_id: str | None) -> str:
    text = (incident_id or "").strip()
    if not text:
        raise ToolError("incident_id is required")
    if ".." in text or "/" in text or "\\" in text:
        raise ToolError("invalid incident_id")
    return text


def get_incident_brief(ctx: ToolContext, *, incident_id: str | None) -> dict[str, Any]:
    connection = _require_connection(ctx)
    iid = _require_incident_id(incident_id)
    item = get_incident(connection, iid)
    if item is None:
        raise ToolError(f"incident not found: {iid}")
    row = IncidentRow(
        incident_id=item.incident_id,
        entity_id=item.entity_id,
        start_time=item.start_time,
        end_time=item.end_time,
        severity=item.severity,
        summary_text=item.summary_text,
        contributing_anomaly_ids=list(item.contributing_anomaly_ids),
    )
    context = build_context(connection, row)
    brief = build_incident_brief(context)
    cap = max(1, int(ctx.max_timeline_events))
    timeline = brief.get("timeline") or []
    if isinstance(timeline, list) and len(timeline) > cap:
        brief["timeline"] = timeline[:cap]
        brief["timeline_truncated"] = True
    anomalies = brief.get("anomalies") or []
    if isinstance(anomalies, list) and len(anomalies) > 30:
        brief["anomalies"] = anomalies[:30]
        brief["anomalies_truncated"] = True
    return brief


def get_why_flagged(ctx: ToolContext, *, incident_id: str | None) -> dict[str, Any]:
    connection = _require_connection(ctx)
    iid = _require_incident_id(incident_id)
    detail = get_incident_detail(connection, iid, warn_band=ctx.warn_band)
    if detail is None:
        raise ToolError(f"incident not found: {iid}")

    playbooks_path = (
        (ctx.config.get("explainability") or {}).get("playbooks_path")
        if isinstance(ctx.config.get("explainability"), dict)
        else None
    )
    catalog = DEFAULT_PLAYBOOKS
    if isinstance(playbooks_path, str) and playbooks_path.strip():
        try:
            catalog = load_playbooks(playbooks_path)
        except Exception:
            catalog = DEFAULT_PLAYBOOKS

    rows: list[dict[str, Any]] = []
    for anomaly in detail.anomalies[:20]:
        explanation = anomaly.explanation
        playbook = None
        if explanation is not None and explanation.playbook is not None:
            playbook = {
                "title": explanation.playbook.title,
                "hint": explanation.playbook.hint,
            }
        else:
            fallback = playbook_for(anomaly.source_detector, playbooks=catalog)
            if fallback:
                playbook = {
                    "title": fallback.get("title"),
                    "hint": fallback.get("hint"),
                }
        rows.append(
            {
                "anomaly_id": anomaly.anomaly_id,
                "source_detector": anomaly.source_detector,
                "score": anomaly.score,
                "window_start": str(anomaly.window_start) if anomaly.window_start else None,
                "window_end": str(anomaly.window_end) if anomaly.window_end else None,
                "summary": explanation.headline if explanation else None,
                "playbook": playbook,
            }
        )
    return {
        "incident_id": detail.incident_id,
        "severity": detail.severity,
        "summary_text": detail.summary_text,
        "detector_set": list(detail.detector_set or []),
        "anomaly_count": detail.anomaly_count,
        "why_flagged": rows,
    }


def get_report_excerpt(
    ctx: ToolContext,
    *,
    incident_id: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    filename: str | None = None
    if path:
        name = Path(path).name
        if name != path and ("/" in path or "\\" in path):
            # Only bare filenames under report_dir.
            raise ToolError("report path must be a bare incident_*.md|.html filename")
        filename = name
    elif incident_id:
        iid = _require_incident_id(incident_id)
        filename = f"incident_{iid}.md"
    else:
        raise ToolError("incident_id or path is required")

    resolved = resolve_report_file(ctx.report_dir, filename)
    if resolved is None and filename.endswith(".md"):
        # Prefer markdown; fall back to HTML sibling when only the viewer file exists.
        html_name = f"{filename[:-3]}.html"
        resolved = resolve_report_file(ctx.report_dir, html_name)
    if resolved is None and filename.endswith(".html"):
        md_name = f"{filename[:-5]}.md"
        resolved = resolve_report_file(ctx.report_dir, md_name)
    if resolved is None:
        raise ToolError(f"report not found: {filename}")
    text = resolved.read_text(encoding="utf-8", errors="replace")
    if resolved.suffix.lower() == ".html":
        text = _html_to_plain_excerpt(text)
    cap = max(1, int(ctx.max_report_chars))
    return {
        "filename": resolved.name,
        "excerpt": text[:cap],
        "truncated": len(text) > cap,
    }


def _html_to_plain_excerpt(html: str) -> str:
    """Rough HTML → text for LLM context (no full browser parse)."""
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?is)<!--.*?-->", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p>", "\n", text)
    text = re.sub(r"(?i)</h[1-6]>", "\n", text)
    text = re.sub(r"(?i)</tr>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def _require_entity_id(entity_id: str | None) -> str:
    text = (entity_id or "").strip()
    if not text:
        raise ToolError("entity_id is required")
    if ".." in text or "/" in text or "\\" in text:
        raise ToolError("invalid entity_id")
    return text


def _clamp_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def rank_entities_by_anomalies(
    ctx: ToolContext,
    *,
    limit: int | None = None,
) -> dict[str, Any]:
    connection = _require_connection(ctx)
    cap = _clamp_int(
        limit,
        default=DEFAULT_ENTITY_RANK_LIMIT,
        minimum=1,
        maximum=MAX_ENTITY_RANK_LIMIT,
    )
    rows = list_top_entities_by_anomaly_count(connection, limit=cap, offset=0)
    return {
        "limit": cap,
        "entities": [
            {
                "entity_id": row.entity_id,
                "entity_type": row.entity_type,
                "label": row.label,
                "anomaly_count": row.anomaly_count,
                "incident_count": row.incident_count,
                "first_seen": str(row.first_seen) if row.first_seen else None,
                "last_seen": str(row.last_seen) if row.last_seen else None,
            }
            for row in rows
        ],
    }


def list_incidents_ranked(
    ctx: ToolContext,
    *,
    sort: str | None = None,
    limit: int | None = None,
    entity_id: str | None = None,
) -> dict[str, Any]:
    connection = _require_connection(ctx)
    cap = _clamp_int(
        limit,
        default=DEFAULT_INCIDENT_RANK_LIMIT,
        minimum=1,
        maximum=MAX_INCIDENT_RANK_LIMIT,
    )
    sort_key = (sort or "anomaly_count").strip().lower()
    if sort_key not in {"anomaly_count", "severity", "start_time"}:
        sort_key = "anomaly_count"
    eid = (entity_id or "").strip() or None
    if eid and (".." in eid or "/" in eid or "\\" in eid):
        raise ToolError("invalid entity_id")
    items = list_incidents(
        connection,
        entity_id=eid,
        sort=sort_key,
        order="desc",
        limit=cap,
        offset=0,
    )
    return {
        "sort": sort_key,
        "limit": cap,
        "entity_id": eid,
        "incidents": [
            {
                "incident_id": item.incident_id,
                "entity_id": item.entity_id,
                "severity": item.severity,
                "summary_text": item.summary_text,
                "anomaly_count": item.anomaly_count,
                "detector_set": list(item.detector_set or []),
                "start_time": str(item.start_time) if item.start_time else None,
                "end_time": str(item.end_time) if item.end_time else None,
            }
            for item in items
        ],
    }


def get_entity_overview(
    ctx: ToolContext,
    *,
    entity_id: str | None,
) -> dict[str, Any]:
    connection = _require_connection(ctx)
    eid = _require_entity_id(entity_id)
    meta = get_entity_meta(connection, eid)
    if meta is None:
        raise ToolError(f"entity not found: {eid}")
    incident_total = count_incidents(connection, entity_id=eid)
    incidents = list_entity_incidents(
        connection,
        eid,
        limit=DEFAULT_ENTITY_OVERVIEW_INCIDENTS,
        offset=0,
    )
    return {
        "entity_id": meta.entity_id,
        "entity_type": meta.entity_type,
        "label": meta.label,
        "first_seen": str(meta.first_seen) if meta.first_seen else None,
        "last_seen": str(meta.last_seen) if meta.last_seen else None,
        "incident_count": incident_total,
        "recent_incidents": [
            {
                "incident_id": item.incident_id,
                "severity": item.severity,
                "summary_text": item.summary_text,
                "anomaly_count": item.anomaly_count,
                "start_time": str(item.start_time) if item.start_time else None,
            }
            for item in incidents
        ],
    }


def get_docs_section(ctx: ToolContext, *, slug: str | None) -> dict[str, Any]:
    if not slug or not str(slug).strip():
        raise ToolError("slug is required")
    try:
        return load_docs_markdown(
            str(slug),
            docs_root=ctx.docs_root,
            max_chars=ctx.max_docs_chars,
        )
    except DocsLoadError as exc:
        raise ToolError(str(exc)) from exc


_TOOL_IMPLS: dict[str, Callable[..., dict[str, Any]]] = {
    "get_incident_brief": get_incident_brief,
    "get_why_flagged": get_why_flagged,
    "get_report_excerpt": get_report_excerpt,
    "get_docs_section": get_docs_section,
    "rank_entities_by_anomalies": rank_entities_by_anomalies,
    "list_incidents_ranked": list_incidents_ranked,
    "get_entity_overview": get_entity_overview,
}


def run_tool(name: str, ctx: ToolContext, **kwargs: Any) -> dict[str, Any]:
    """Dispatch an allow-listed tool; refuse unknown names."""
    key = (name or "").strip()
    if key not in ALLOWED_TOOLS:
        raise ToolError(f"unknown tool refused: {name!r}")
    return _TOOL_IMPLS[key](ctx, **kwargs)
