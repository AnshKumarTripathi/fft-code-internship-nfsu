"""Deterministic Jinja2 incident report generation (SDD §7.8)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from src.reporting.charts import render_activity_svg, render_psd_svg
from src.explainability.payload import explanation_from_anomaly

MAX_TIMELINE_EVENTS = 100
MAX_REPORT_ANOMALIES = 20
INCIDENT_CHART_PAD_HOURS = 6
CODE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MD_TEMPLATE = "src/reporting/templates/incident_report.md.j2"
DEFAULT_HTML_TEMPLATE = "src/reporting/templates/incident_report.html.j2"
EDGE_COUNT_KEYS = ("precedes", "same_session", "same_ip", "same_host")
DETECTOR_ROLES = {
    "statistical": "rate",
    "spectral": "rhythm",
    "ml": "sequence",
    "cluster_outlier": "peer",
    "changepoint": "level-shift",
}


@dataclass(frozen=True)
class IncidentRow:
    incident_id: str
    entity_id: str
    start_time: datetime | None
    end_time: datetime | None
    severity: str
    summary_text: str | None
    contributing_anomaly_ids: list[str]


class ReportingError(Exception):
    """Hard failure in the report stage (e.g. missing template)."""


class NothingToReport(Exception):
    """Raised when incidents table is empty (soft-skip in run-all)."""


def resolve_template_path(template_path: str | Path) -> Path:
    path = Path(template_path)
    if not path.is_absolute():
        path = CODE_ROOT / path
    return path


def load_incidents(connection: Any) -> list[IncidentRow]:
    rows = connection.execute(
        """
        SELECT incident_id, entity_id, start_time, end_time,
               severity, summary_text, contributing_anomaly_ids
        FROM incidents
        ORDER BY start_time NULLS LAST, incident_id
        """
    ).fetchall()
    incidents: list[IncidentRow] = []
    for (
        incident_id,
        entity_id,
        start_time,
        end_time,
        severity,
        summary_text,
        contributing,
    ) in rows:
        incidents.append(
            IncidentRow(
                incident_id=str(incident_id),
                entity_id=str(entity_id),
                start_time=start_time if isinstance(start_time, datetime) else None,
                end_time=end_time if isinstance(end_time, datetime) else None,
                severity=str(severity),
                summary_text=summary_text,
                contributing_anomaly_ids=_normalize_id_list(contributing),
            )
        )
    return incidents


def _normalize_id_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, tuple):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        except json.JSONDecodeError:
            return [value] if value else []
    return [str(value)]


def _parse_metadata(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _format_metadata(metadata: dict[str, Any]) -> str:
    if not metadata:
        return ""
    parts = [f"{k}={v}" for k, v in sorted(metadata.items())]
    return ", ".join(parts)


def _load_analyst_actions(connection: Any, incident_id: str) -> list[dict[str, Any]]:
    row = connection.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'main' AND lower(table_name) = 'analyst_actions'
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return []
    rows = connection.execute(
        """
        SELECT action_id, incident_id, anomaly_id, action, note,
               operator_label, created_at, run_id
        FROM analyst_actions
        WHERE incident_id = ?
        ORDER BY created_at ASC, action_id ASC
        """,
        [incident_id],
    ).fetchall()
    actions: list[dict[str, Any]] = []
    for item in rows:
        actions.append(
            {
                "action_id": str(item[0]),
                "incident_id": str(item[1]),
                "anomaly_id": str(item[2]) if item[2] else None,
                "action": str(item[3]),
                "note": str(item[4]) if item[4] else None,
                "operator_label": str(item[5]),
                "created_at": item[6],
                "run_id": str(item[7]) if item[7] else None,
            }
        )
    return actions


def _load_entity(connection: Any, entity_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT entity_id, entity_type, first_seen, last_seen, label
        FROM entities
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()
    if row is None:
        return {
            "entity_id": entity_id,
            "entity_type": None,
            "first_seen": None,
            "last_seen": None,
            "label": None,
        }
    return {
        "entity_id": str(row[0]),
        "entity_type": row[1],
        "first_seen": row[2],
        "last_seen": row[3],
        "label": row[4],
    }


def _load_anomalies(
    connection: Any,
    anomaly_ids: list[str],
) -> list[dict[str, Any]]:
    if not anomaly_ids:
        return []
    placeholders = ", ".join("?" for _ in anomaly_ids)
    rows = connection.execute(
        f"""
        SELECT anomaly_id, entity_id, window_start, window_end,
               source_detector, score, metadata
        FROM anomaly_events
        WHERE anomaly_id IN ({placeholders})
        ORDER BY window_start, source_detector
        """,
        anomaly_ids,
    ).fetchall()
    anomalies: list[dict[str, Any]] = []
    for row in rows:
        metadata = _parse_metadata(row[6])
        anomalies.append(
            {
                "anomaly_id": str(row[0]),
                "entity_id": str(row[1]),
                "window_start": row[2],
                "window_end": row[3],
                "source_detector": str(row[4]),
                "score": float(row[5]) if row[5] is not None else 0.0,
                "metadata": metadata,
                "metadata_text": _format_metadata(metadata),
                "explanation": explanation_from_anomaly(
                    detector=str(row[4]),
                    entity_id=str(row[1]),
                    window_start=row[2] if isinstance(row[2], datetime) else None,
                    window_end=row[3] if isinstance(row[3], datetime) else None,
                    score=float(row[5]) if row[5] is not None else 0.0,
                    metadata=metadata,
                ),
            }
        )
    return anomalies


def _count_timeline(
    connection: Any,
    anomaly_ids: list[str],
) -> int:
    if not anomaly_ids:
        return 0
    placeholders = ", ".join("?" for _ in anomaly_ids)
    row = connection.execute(
        f"""
        SELECT COUNT(*)
        FROM correlation_edges
        WHERE dst_anomaly_id IN ({placeholders})
        """,
        anomaly_ids,
    ).fetchone()
    return int(row[0]) if row else 0


def load_timeline(
    connection: Any,
    anomaly_ids: list[str],
    *,
    max_events: int = MAX_TIMELINE_EVENTS,
) -> list[dict[str, Any]]:
    if not anomaly_ids:
        return []
    placeholders = ", ".join("?" for _ in anomaly_ids)
    rows = connection.execute(
        f"""
        SELECT p.event_timestamp, c.relation_type, p.template_id,
               t.template_string, p.raw_fields, c.src_event_id, p.log_source
        FROM correlation_edges c
        JOIN parsed_events p ON p.event_id = c.src_event_id
        LEFT JOIN templates t ON t.template_id = p.template_id
        WHERE c.dst_anomaly_id IN ({placeholders})
        ORDER BY p.event_timestamp
        LIMIT ?
        """,
        [*anomaly_ids, max_events],
    ).fetchall()

    timeline: list[dict[str, Any]] = []
    for (
        event_timestamp,
        relation_type,
        template_id,
        template_string,
        raw_fields,
        _eid,
        log_source,
    ) in rows:
        fields = _parse_metadata(raw_fields)
        if template_string:
            snippet = str(template_string)
        elif template_id:
            snippet = f"template_id={template_id}"
        else:
            snippet = _format_metadata(fields) or "(no fields)"
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        timeline.append(
            {
                "event_timestamp": event_timestamp,
                "relation_type": str(relation_type),
                "template_id": template_id,
                "snippet": snippet,
                "log_source": str(log_source) if log_source else None,
            }
        )
    return timeline


def _load_edge_counts(
    connection: Any,
    anomaly_ids: list[str],
) -> dict[str, int]:
    counts = {key: 0 for key in EDGE_COUNT_KEYS}
    if not anomaly_ids:
        return counts
    placeholders = ", ".join("?" for _ in anomaly_ids)
    rows = connection.execute(
        f"""
        SELECT relation_type, COUNT(*)
        FROM correlation_edges
        WHERE dst_anomaly_id IN ({placeholders})
        GROUP BY relation_type
        """,
        anomaly_ids,
    ).fetchall()
    for relation_type, count in rows:
        key = str(relation_type or "")
        if key in counts:
            counts[key] = int(count)
        else:
            counts[key] = int(count)
    return counts


def _top_anomalies(
    anomalies: list[dict[str, Any]],
    *,
    limit: int = MAX_REPORT_ANOMALIES,
) -> list[dict[str, Any]]:
    ranked = sorted(anomalies, key=lambda row: abs(float(row["score"])), reverse=True)
    return ranked[:limit]


def _group_anomalies_by_detector(
    anomalies: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in anomalies:
        grouped.setdefault(str(row["source_detector"]), []).append(row)
    return grouped


def _padded_window(
    start: datetime | None,
    end: datetime | None,
    *,
    pad_hours: int = INCIDENT_CHART_PAD_HOURS,
) -> tuple[datetime | None, datetime | None]:
    delta = timedelta(hours=pad_hours)
    padded_start = start - delta if start is not None else None
    padded_end = end + delta if end is not None else None
    return padded_start, padded_end


def _load_activity_series(
    connection: Any,
    entity_id: str,
    start: datetime | None,
    end: datetime | None,
) -> tuple[list[datetime | None], list[float], list[tuple[str, datetime | None, datetime | None]]]:
    clauses = ["entity_id = ?"]
    params: list[Any] = [entity_id]
    if start is not None:
        clauses.append("bucket_start >= ?")
        params.append(start)
    if end is not None:
        clauses.append("bucket_start <= ?")
        params.append(end)
    where = " AND ".join(clauses)
    rows = connection.execute(
        f"""
        SELECT bucket_start, event_count
        FROM entity_bucket_counts
        WHERE {where}
        ORDER BY bucket_start
        LIMIT 2000
        """,
        params,
    ).fetchall()
    starts = [row[0] if isinstance(row[0], datetime) else None for row in rows]
    counts = [float(row[1]) if row[1] is not None else 0.0 for row in rows]
    overlays: list[tuple[str, datetime | None, datetime | None]] = []
    for source, table_name in (
        ("statistical", "statistical_window_scores"),
        ("spectral", "spectral_window_scores"),
        ("changepoint", "changepoint_window_scores"),
    ):
        overlay_clauses = ["entity_id = ?", "flagged = TRUE"]
        overlay_params: list[Any] = [entity_id]
        if start is not None:
            overlay_clauses.append("window_end >= ?")
            overlay_params.append(start)
        if end is not None:
            overlay_clauses.append("window_start <= ?")
            overlay_params.append(end)
        overlay_rows = connection.execute(
            f"""
            SELECT window_start, window_end
            FROM {table_name}
            WHERE {' AND '.join(overlay_clauses)}
            ORDER BY window_start
            """,
            overlay_params,
        ).fetchall()
        for window_start, window_end in overlay_rows:
            overlays.append(
                (
                    source,
                    window_start if isinstance(window_start, datetime) else None,
                    window_end if isinstance(window_end, datetime) else None,
                )
            )
    return starts, counts, overlays


def _load_spectrum_arrays(
    connection: Any,
    entity_id: str,
) -> tuple[list[float], list[float], dict[str, Any] | None]:
    features: dict[str, Any] | None = None
    feature_row = connection.execute(
        """
        SELECT dominant_period_hours, dominant_power_frac,
               spectral_entropy, total_power
        FROM entity_spectral_features
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()
    if feature_row is not None:
        features = {
            "dominant_period_hours": feature_row[0],
            "dominant_power_frac": feature_row[1],
            "spectral_entropy": feature_row[2],
            "total_power": feature_row[3],
        }
    baseline_row = connection.execute(
        """
        SELECT freq_grid, psd_norm
        FROM spectral_baselines
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()
    freq_grid: list[float] = []
    psd_norm: list[float] = []
    if baseline_row is not None:
        raw_freq = baseline_row[0] or []
        raw_psd = baseline_row[1] or []
        freq_grid = [float(value) for value in raw_freq]
        psd_norm = [float(value) for value in raw_psd]
    return freq_grid, psd_norm, features


def build_context(
    connection: Any,
    incident: IncidentRow,
    *,
    generated_at: datetime | None = None,
    llm_narrative: str | None = None,
) -> dict[str, Any]:
    """Assemble a plain dict for Jinja (no detection logic)."""
    all_anomalies = _load_anomalies(connection, incident.contributing_anomaly_ids)
    shown = _top_anomalies(all_anomalies)
    timeline = load_timeline(connection, incident.contributing_anomaly_ids)
    timeline_total = _count_timeline(connection, incident.contributing_anomaly_ids)
    entity = _load_entity(connection, incident.entity_id)
    edge_counts = _load_edge_counts(connection, incident.contributing_anomaly_ids)
    ts = generated_at or datetime.now(timezone.utc)
    detector_set = sorted({a["source_detector"] for a in all_anomalies})
    top_score = max((a["score"] for a in all_anomalies), default=None)
    pad_start, pad_end = _padded_window(incident.start_time, incident.end_time)
    bucket_starts, event_counts, overlays = _load_activity_series(
        connection, incident.entity_id, pad_start, pad_end
    )
    freq_grid, psd_norm, spectral_features = _load_spectrum_arrays(
        connection, incident.entity_id
    )
    return {
        "incident": {
            "incident_id": incident.incident_id,
            "entity_id": incident.entity_id,
            "start_time": incident.start_time,
            "end_time": incident.end_time,
            "severity": incident.severity,
            "summary_text": incident.summary_text,
            "contributing_anomaly_ids": incident.contributing_anomaly_ids,
        },
        "entity": entity,
        "anomalies": shown,
        "anomalies_by_detector": _group_anomalies_by_detector(shown),
        "anomalies_total": len(all_anomalies),
        "anomalies_shown": len(shown),
        "timeline": timeline,
        "timeline_total": timeline_total,
        "detector_roles": DETECTOR_ROLES,
        "detector_set": detector_set,
        "edge_counts": edge_counts,
        "has_ip_link": edge_counts.get("same_ip", 0) > 0,
        "has_host_link": edge_counts.get("same_host", 0) > 0,
        "top_score": top_score,
        "spectral_features": spectral_features,
        "activity_svg": render_activity_svg(bucket_starts, event_counts, overlays),
        "psd_svg": render_psd_svg(freq_grid, psd_norm),
        "llm_narrative": llm_narrative or "",
        "generated_at": ts.isoformat(),
        "analyst_actions": _load_analyst_actions(connection, incident.incident_id),
    }


def _render_template(
    context: dict[str, Any],
    *,
    template_path: str | Path,
    autoescape: bool,
) -> str:
    path = resolve_template_path(template_path)
    if not path.is_file():
        raise ReportingError(f"report template not found: {path}")
    env = Environment(
        loader=FileSystemLoader(str(path.parent)),
        autoescape=autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    try:
        template = env.get_template(path.name)
    except TemplateNotFound as exc:
        raise ReportingError(f"report template not found: {path}") from exc
    return template.render(**context)


def render_incident_markdown(
    context: dict[str, Any],
    *,
    template_path: str | Path,
) -> str:
    return _render_template(
        context, template_path=template_path, autoescape=False
    )


def render_incident_html(
    context: dict[str, Any],
    *,
    template_path: str | Path,
) -> str:
    return _render_template(
        context, template_path=template_path, autoescape=True
    )


def report_filename(incident_id: str, suffix: str = "md") -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in incident_id)
    ext = suffix.lstrip(".")
    return f"incident_{safe}.{ext}"


def write_incident_report(
    report_dir: Path,
    incident_id: str,
    body: str,
    *,
    suffix: str = "md",
) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / report_filename(incident_id, suffix=suffix)
    path.write_text(body, encoding="utf-8")
    return path


def prepend_llm_narrative(markdown: str, narrative: str) -> str:
    block = "## LLM narrative\n\n" + narrative.strip() + "\n\n"
    return block + markdown
