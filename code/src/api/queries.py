"""Parameterized read-only warehouse queries for the Phase 10 dashboard."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
import uuid

import duckdb

from src.api.schemas import (
    AnalystActionItem,
    AnomalyExplanation,
    AnomalyItem,
    BucketPoint,
    EntityAnomalyRank,
    EntityMeta,
    FlaggedWindow,
    IncidentDetail,
    IncidentEdgeItem,
    IncidentEdgesResult,
    IncidentItem,
    IncidentKpis,
    IncidentTimelineEvent,
    LogSourceCount,
    PipelineRunItem,
    SpectralFeatures,
    SpectralWindowScore,
    SpectrumResponse,
    StftMatrixResponse,
    TimelineEvent,
)

from src.explainability.payload import explanation_from_anomaly, uncertainty_band

DEFAULT_INCIDENT_LIMIT = 100
MAX_INCIDENT_LIMIT = 500
DEFAULT_TIMELINE_LIMIT = 200
MAX_TIMELINE_LIMIT = 1000
DEFAULT_INCIDENT_TIMELINE_LIMIT = 100
DEFAULT_SPECTRUM_POINTS = 256
DEFAULT_BUCKET_LIMIT = 2000
DEFAULT_RECENT_SCORES = 50
DEFAULT_ENTITY_SEARCH_LIMIT = 50
MAX_ENTITY_SEARCH_LIMIT = 200
DEFAULT_ENTITY_RANK_LIMIT = 10
MAX_ENTITY_RANK_LIMIT = 25
DEFAULT_RUNS_LIMIT = 50
MAX_RUNS_LIMIT = 200
DEFAULT_DETAIL_ANOMALY_LIMIT = 50
LOG_SOURCE_KPI_LIMIT = 8
EDGE_COUNT_KEYS = ("precedes", "same_session", "same_ip", "same_host")
DETECTOR_COUNT_KEYS = (
    "statistical",
    "spectral",
    "ml",
    "cluster_outlier",
    "changepoint",
    "seasonal",
)
INCIDENT_SORT_KEYS = frozenset({"severity", "start_time", "anomaly_count"})
INCIDENT_DISPOSITIONS = frozenset({"open", "dismissed", "any"})
INCIDENT_ORDER_KEYS = frozenset({"asc", "desc"})


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


def _parse_json_object(value: Any) -> dict[str, Any]:
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


def _as_float_list(value: Any) -> list[float]:
    if value is None:
        return []
    if isinstance(value, list):
        return [float(v) for v in value]
    if isinstance(value, tuple):
        return [float(v) for v in value]
    return []


def _downsample_pair(
    xs: list[float],
    ys: list[float],
    max_points: int,
) -> tuple[list[float], list[float], bool]:
    n = min(len(xs), len(ys))
    if n <= max_points or max_points < 2:
        return xs[:n], ys[:n], False
    stride = max(1, n // max_points)
    out_x = xs[::stride][:max_points]
    out_y = ys[::stride][:max_points]
    return out_x, out_y, True


def clamp_limit(limit: int | None, default: int, maximum: int) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), maximum))


def db_reachable(connection: duckdb.DuckDBPyConnection) -> bool:
    try:
        connection.execute("SELECT 1").fetchone()
        return True
    except duckdb.Error:
        return False


def entity_exists(connection: duckdb.DuckDBPyConnection, entity_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM entities WHERE entity_id = ? LIMIT 1",
        [entity_id],
    ).fetchone()
    if row is not None:
        return True
    # Fall back: entity may appear only in fact tables if registry incomplete.
    row = connection.execute(
        "SELECT 1 FROM parsed_events WHERE entity_id = ? LIMIT 1",
        [entity_id],
    ).fetchone()
    return row is not None


def parse_detector_filters(raw: str | list[str] | None) -> list[str]:
    """Normalize repeatable or comma-separated detector query values."""
    if raw is None:
        return []
    parts: list[str] = []
    if isinstance(raw, str):
        parts = raw.split(",")
    else:
        for item in raw:
            parts.extend(str(item).split(","))
    out: list[str] = []
    seen: set[str] = set()
    for part in parts:
        name = part.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _ensure_filter_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _incident_dismissed_sql(connection: duckdb.DuckDBPyConnection) -> str | None:
    """SQL predicate: incident is dismissed under the all-anomalies rule.

    An incident is dismissed iff it has at least one contributing anomaly and
    every contributing anomaly's latest dismiss/reopen action is ``dismiss``.
    Notes are ignored. Anomalies with no dismiss/reopen action count as open.
    Returns None when analyst_actions is missing (treat every incident as open).
    """
    if not analyst_actions_table_exists(connection):
        return None
    return """
    (
      len(incidents.contributing_anomaly_ids) > 0
      AND (
        SELECT COUNT(*)
        FROM (SELECT UNNEST(incidents.contributing_anomaly_ids) AS aid) AS u
        WHERE (
          SELECT aa.action
          FROM analyst_actions AS aa
          WHERE aa.incident_id = incidents.incident_id
            AND aa.anomaly_id = u.aid
            AND aa.action IN ('dismiss', 'reopen')
          ORDER BY aa.created_at DESC, aa.action_id DESC
          LIMIT 1
        ) = 'dismiss'
      ) = len(incidents.contributing_anomaly_ids)
    )
    """


def _incident_filters(
    connection: duckdb.DuckDBPyConnection | None = None,
    *,
    severity: str | None = None,
    entity_id: str | None = None,
    q: str | None = None,
    start_after: datetime | None = None,
    end_before: datetime | None = None,
    detectors: list[str] | None = None,
    min_detectors: int | None = None,
    disposition: str | None = None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if entity_id:
        clauses.append("entity_id = ?")
        params.append(entity_id)
    if q:
        clauses.append("COALESCE(summary_text, '') ILIKE '%' || ? || '%'")
        params.append(q)
    if start_after is not None:
        clauses.append("start_time >= ?")
        params.append(_ensure_filter_utc(start_after))
    if end_before is not None:
        clauses.append("end_time <= ?")
        params.append(_ensure_filter_utc(end_before))
    detector_list = [d for d in (detectors or []) if d]
    if detector_list:
        placeholders = ", ".join("?" for _ in detector_list)
        clauses.append(
            f"""
            EXISTS (
              SELECT 1
              FROM anomaly_events AS ae
              WHERE list_contains(incidents.contributing_anomaly_ids, ae.anomaly_id)
                AND ae.source_detector IN ({placeholders})
            )
            """
        )
        params.extend(detector_list)
    if min_detectors is not None and int(min_detectors) >= 1:
        clauses.append(
            """
            (
              SELECT COUNT(DISTINCT ae.source_detector)
              FROM anomaly_events AS ae
              WHERE list_contains(incidents.contributing_anomaly_ids, ae.anomaly_id)
            ) >= ?
            """
        )
        params.append(int(min_detectors))
    disposition_f = (disposition or "any").strip().lower()
    if disposition_f not in INCIDENT_DISPOSITIONS:
        disposition_f = "any"
    if disposition_f in ("open", "dismissed") and connection is not None:
        dismissed_sql = _incident_dismissed_sql(connection)
        if dismissed_sql is None:
            if disposition_f == "dismissed":
                clauses.append("1 = 0")
        elif disposition_f == "dismissed":
            clauses.append(dismissed_sql)
        else:
            clauses.append(f"NOT {dismissed_sql}")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def _incident_order_by(
    *,
    sort: str | None = None,
    order: str | None = None,
) -> str:
    sort_key = (sort or "severity").strip().lower()
    if sort_key not in INCIDENT_SORT_KEYS:
        sort_key = "severity"
    order_key = (order or "").strip().lower()
    if order_key not in INCIDENT_ORDER_KEYS:
        order_key = "desc" if sort_key != "severity" else "desc"

    if sort_key == "start_time":
        direction = "ASC" if order_key == "asc" else "DESC"
        return f"start_time {direction} NULLS LAST, incident_id"

    if sort_key == "anomaly_count":
        direction = "ASC" if order_key == "asc" else "DESC"
        return (
            f"len(contributing_anomaly_ids) {direction}, "
            f"start_time DESC NULLS LAST, incident_id"
        )

    # severity: desc = critical first (default); asc = low first
    if order_key == "asc":
        severity_case = """
          CASE severity
            WHEN 'low' THEN 0
            WHEN 'medium' THEN 1
            WHEN 'high' THEN 2
            WHEN 'critical' THEN 3
            ELSE 4
          END
        """
    else:
        severity_case = """
          CASE severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4
          END
        """
    return f"{severity_case}, start_time DESC NULLS LAST, incident_id"


def _detectors_for_anomaly_ids(
    connection: duckdb.DuckDBPyConnection,
    anomaly_ids: list[str],
) -> dict[str, str]:
    if not anomaly_ids:
        return {}
    placeholders = ", ".join("?" for _ in anomaly_ids)
    rows = connection.execute(
        f"""
        SELECT anomaly_id, source_detector
        FROM anomaly_events
        WHERE anomaly_id IN ({placeholders})
        """,
        anomaly_ids,
    ).fetchall()
    return {str(row[0]): str(row[1]) for row in rows}


def _detector_set_for_ids(
    mapping: dict[str, str],
    anomaly_ids: list[str],
) -> list[str]:
    return sorted({mapping[aid] for aid in anomaly_ids if aid in mapping})


def _edge_counts_for_ids(
    connection: duckdb.DuckDBPyConnection,
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
        counts[key] = int(count)
    return counts


def list_incidents(
    connection: duckdb.DuckDBPyConnection,
    *,
    severity: str | None = None,
    entity_id: str | None = None,
    q: str | None = None,
    start_after: datetime | None = None,
    end_before: datetime | None = None,
    detectors: list[str] | None = None,
    min_detectors: int | None = None,
    disposition: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    limit: int = DEFAULT_INCIDENT_LIMIT,
    offset: int = 0,
) -> list[IncidentItem]:
    limit = clamp_limit(limit, DEFAULT_INCIDENT_LIMIT, MAX_INCIDENT_LIMIT)
    offset = max(0, int(offset))
    where, params = _incident_filters(
        connection,
        severity=severity,
        entity_id=entity_id,
        q=q,
        start_after=start_after,
        end_before=end_before,
        detectors=detectors,
        min_detectors=min_detectors,
        disposition=disposition,
    )
    order_by = _incident_order_by(sort=sort, order=order)
    rows = connection.execute(
        f"""
        SELECT incident_id, entity_id, start_time, end_time,
               severity, summary_text, contributing_anomaly_ids
        FROM incidents
        {where}
        ORDER BY {order_by}
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    items: list[IncidentItem] = []
    all_ids: list[str] = []
    for r in rows:
        ids = _normalize_id_list(r[6])
        all_ids.extend(ids)
        items.append(
            IncidentItem(
                incident_id=str(r[0]),
                entity_id=str(r[1]),
                start_time=r[2] if isinstance(r[2], datetime) else None,
                end_time=r[3] if isinstance(r[3], datetime) else None,
                severity=str(r[4]),
                summary_text=r[5],
                contributing_anomaly_ids=ids,
                anomaly_count=len(ids),
            )
        )
    mapping = _detectors_for_anomaly_ids(connection, all_ids)
    return [
        item.model_copy(
            update={
                "detector_set": _detector_set_for_ids(
                    mapping, item.contributing_anomaly_ids
                )
            }
        )
        for item in items
    ]


def count_incidents(
    connection: duckdb.DuckDBPyConnection,
    *,
    severity: str | None = None,
    entity_id: str | None = None,
    q: str | None = None,
    start_after: datetime | None = None,
    end_before: datetime | None = None,
    detectors: list[str] | None = None,
    min_detectors: int | None = None,
    disposition: str | None = None,
) -> int:
    where, params = _incident_filters(
        connection,
        severity=severity,
        entity_id=entity_id,
        q=q,
        start_after=start_after,
        end_before=end_before,
        detectors=detectors,
        min_detectors=min_detectors,
        disposition=disposition,
    )
    row = connection.execute(
        f"SELECT COUNT(*) FROM incidents {where}",
        params,
    ).fetchone()
    return int(row[0]) if row else 0


def get_incident(
    connection: duckdb.DuckDBPyConnection,
    incident_id: str,
) -> IncidentItem | None:
    row = connection.execute(
        """
        SELECT incident_id, entity_id, start_time, end_time,
               severity, summary_text, contributing_anomaly_ids
        FROM incidents
        WHERE incident_id = ?
        """,
        [incident_id],
    ).fetchone()
    if row is None:
        return None
    ids = _normalize_id_list(row[6])
    mapping = _detectors_for_anomaly_ids(connection, ids)
    return IncidentItem(
        incident_id=str(row[0]),
        entity_id=str(row[1]),
        start_time=row[2] if isinstance(row[2], datetime) else None,
        end_time=row[3] if isinstance(row[3], datetime) else None,
        severity=str(row[4]),
        summary_text=row[5],
        contributing_anomaly_ids=ids,
        detector_set=_detector_set_for_ids(mapping, ids),
        anomaly_count=len(ids),
    )


def get_incident_detail(
    connection: duckdb.DuckDBPyConnection,
    incident_id: str,
    *,
    warn_band: float = 0.5,
) -> IncidentDetail | None:
    incident = get_incident(connection, incident_id)
    if incident is None:
        return None
    anomalies = load_anomalies(
        connection, incident.contributing_anomaly_ids, warn_band=warn_band
    )
    anomalies_total = len(anomalies)
    ranked = sorted(anomalies, key=lambda item: abs(item.score), reverse=True)
    capped = ranked[:DEFAULT_DETAIL_ANOMALY_LIMIT]
    edge_counts = _edge_counts_for_ids(connection, incident.contributing_anomaly_ids)
    top_score = max((item.score for item in anomalies), default=None)
    return IncidentDetail(
        incident_id=incident.incident_id,
        entity_id=incident.entity_id,
        start_time=incident.start_time,
        end_time=incident.end_time,
        severity=incident.severity,
        summary_text=incident.summary_text,
        contributing_anomaly_ids=incident.contributing_anomaly_ids,
        detector_set=incident.detector_set,
        anomaly_count=incident.anomaly_count,
        anomalies=capped,
        edge_counts=edge_counts,
        has_ip_link=edge_counts.get("same_ip", 0) > 0,
        has_host_link=edge_counts.get("same_host", 0) > 0,
        top_score=top_score,
        anomalies_total=anomalies_total,
        actions=list_analyst_actions(connection, incident_id),
    )


ANALYST_ACTIONS = frozenset({"dismiss", "note", "reopen"})
MAX_ACTION_NOTE_LENGTH = 4000
MAX_OPERATOR_LABEL_LENGTH = 64


def analyst_actions_table_exists(connection: duckdb.DuckDBPyConnection) -> bool:
    row = connection.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'main' AND lower(table_name) = 'analyst_actions'
        LIMIT 1
        """
    ).fetchone()
    return row is not None


def list_analyst_actions(
    connection: duckdb.DuckDBPyConnection,
    incident_id: str,
) -> list[AnalystActionItem]:
    if not analyst_actions_table_exists(connection):
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
    items: list[AnalystActionItem] = []
    for row in rows:
        items.append(
            AnalystActionItem(
                action_id=str(row[0]),
                incident_id=str(row[1]),
                anomaly_id=str(row[2]) if row[2] else None,
                action=str(row[3]),
                note=str(row[4]) if row[4] else None,
                operator_label=str(row[5]),
                created_at=row[6] if isinstance(row[6], datetime) else None,
                run_id=str(row[7]) if row[7] else None,
            )
        )
    return items


def insert_analyst_action(
    connection: duckdb.DuckDBPyConnection,
    *,
    incident_id: str,
    anomaly_id: str | None,
    action: str,
    note: str | None,
    operator_label: str,
    run_id: str | None = None,
) -> AnalystActionItem:
    action_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)
    connection.execute(
        """
        INSERT INTO analyst_actions (
            action_id, incident_id, anomaly_id, action, note,
            operator_label, created_at, run_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            action_id,
            incident_id,
            anomaly_id,
            action,
            note,
            operator_label,
            created_at,
            run_id,
        ],
    )
    return AnalystActionItem(
        action_id=action_id,
        incident_id=incident_id,
        anomaly_id=anomaly_id,
        action=action,
        note=note,
        operator_label=operator_label,
        created_at=created_at,
        run_id=run_id,
    )


def load_anomalies(
    connection: duckdb.DuckDBPyConnection,
    anomaly_ids: list[str],
    *,
    warn_band: float = 0.5,
) -> list[AnomalyItem]:
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
    items: list[AnomalyItem] = []
    for r in rows:
        metadata = _parse_json_object(r[6])
        window_start = r[2] if isinstance(r[2], datetime) else None
        window_end = r[3] if isinstance(r[3], datetime) else None
        detector = str(r[4])
        entity_id = str(r[1])
        score = float(r[5]) if r[5] is not None else 0.0
        items.append(
            AnomalyItem(
                anomaly_id=str(r[0]),
                entity_id=entity_id,
                window_start=window_start,
                window_end=window_end,
                source_detector=detector,
                score=score,
                metadata=metadata,
                explanation=AnomalyExplanation.model_validate(
                    explanation_from_anomaly(
                        detector=detector,
                        entity_id=entity_id,
                        window_start=window_start,
                        window_end=window_end,
                        score=score,
                        metadata=metadata,
                        warn_band=warn_band,
                    )
                ),
            )
        )
    return items


def get_entity_meta(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
) -> EntityMeta | None:
    row = connection.execute(
        """
        SELECT entity_id, entity_type, first_seen, last_seen, label
        FROM entities
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()
    if row is None:
        if not entity_exists(connection, entity_id):
            return None
        return EntityMeta(entity_id=entity_id)
    return EntityMeta(
        entity_id=str(row[0]),
        entity_type=row[1],
        first_seen=row[2] if isinstance(row[2], datetime) else None,
        last_seen=row[3] if isinstance(row[3], datetime) else None,
        label=row[4],
    )


def resolve_series_order(
    order: str | None,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> str:
    """Newest first without a window; oldest (chrono) when start/end is set."""
    if order in ("newest", "oldest"):
        return order
    if start is not None or end is not None:
        return "oldest"
    return "newest"


def list_entity_timeline(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = DEFAULT_TIMELINE_LIMIT,
    offset: int = 0,
    order: str | None = None,
) -> list[TimelineEvent]:
    limit = clamp_limit(limit, DEFAULT_TIMELINE_LIMIT, MAX_TIMELINE_LIMIT)
    offset = max(0, int(offset))
    resolved_order = resolve_series_order(order, start=start, end=end)
    clauses = ["p.entity_id = ?"]
    params: list[Any] = [entity_id]
    if start is not None:
        clauses.append("p.event_timestamp >= ?")
        params.append(start)
    if end is not None:
        clauses.append("p.event_timestamp <= ?")
        params.append(end)
    where = " AND ".join(clauses)
    direction = "DESC" if resolved_order == "newest" else "ASC"
    rows = connection.execute(
        f"""
        SELECT
          p.event_id,
          p.event_timestamp,
          p.template_id,
          t.template_string,
          p.log_source,
          p.raw_fields,
          list(DISTINCT c.dst_anomaly_id) FILTER (WHERE c.dst_anomaly_id IS NOT NULL)
            AS related_anomaly_ids
        FROM parsed_events p
        LEFT JOIN templates t ON t.template_id = p.template_id
        LEFT JOIN correlation_edges c ON c.src_event_id = p.event_id
        WHERE {where}
        GROUP BY
          p.event_id, p.event_timestamp, p.template_id,
          t.template_string, p.log_source, p.raw_fields
        ORDER BY p.event_timestamp {direction}
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    events: list[TimelineEvent] = []
    for row in rows:
        related = _normalize_id_list(row[6])
        events.append(
            TimelineEvent(
                event_id=int(row[0]),
                event_timestamp=row[1] if isinstance(row[1], datetime) else None,
                template_id=str(row[2]) if row[2] is not None else None,
                template_string=row[3],
                log_source=row[4],
                raw_fields=_parse_json_object(row[5]),
                related_anomaly_ids=related,
            )
        )
    return events


def count_entity_timeline(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> int:
    clauses = ["entity_id = ?"]
    params: list[Any] = [entity_id]
    if start is not None:
        clauses.append("event_timestamp >= ?")
        params.append(start)
    if end is not None:
        clauses.append("event_timestamp <= ?")
        params.append(end)
    where = " AND ".join(clauses)
    row = connection.execute(
        f"SELECT COUNT(*) FROM parsed_events WHERE {where}",
        params,
    ).fetchone()
    return int(row[0]) if row else 0


def get_entity_spectrum(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    downsample: bool = True,
    max_points: int = DEFAULT_SPECTRUM_POINTS,
    z_threshold: float | None = None,
    warn_band: float | None = None,
) -> SpectrumResponse | None:
    features_row = connection.execute(
        """
        SELECT entity_id, dominant_period_hours, dominant_power_frac,
               spectral_entropy, total_power, computed_at
        FROM entity_spectral_features
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()
    baseline_row = connection.execute(
        """
        SELECT freq_grid, psd_norm, bucket_seconds
        FROM spectral_baselines
        WHERE entity_id = ?
        """,
        [entity_id],
    ).fetchone()

    if features_row is None and baseline_row is None:
        return None

    features: SpectralFeatures | None = None
    if features_row is not None:
        features = SpectralFeatures(
            entity_id=str(features_row[0]),
            dominant_period_hours=(
                float(features_row[1]) if features_row[1] is not None else None
            ),
            dominant_power_frac=(
                float(features_row[2]) if features_row[2] is not None else None
            ),
            spectral_entropy=(
                float(features_row[3]) if features_row[3] is not None else None
            ),
            total_power=(
                float(features_row[4]) if features_row[4] is not None else None
            ),
            computed_at=(
                features_row[5] if isinstance(features_row[5], datetime) else None
            ),
        )

    freq_grid: list[float] = []
    psd_norm: list[float] = []
    was_downsampled = False
    bucket_seconds: int | None = None
    if baseline_row is not None:
        freq_grid = _as_float_list(baseline_row[0])
        psd_norm = _as_float_list(baseline_row[1])
        if baseline_row[2] is not None:
            bucket_seconds = int(baseline_row[2])
        if downsample:
            freq_grid, psd_norm, was_downsampled = _downsample_pair(
                freq_grid, psd_norm, max_points
            )
    if bucket_seconds is None:
        bucket_seconds = get_entity_bucket_seconds(connection, entity_id)

    score_rows = connection.execute(
        """
        SELECT window_start, window_end, energy_z, shape_js_z, flagged
        FROM spectral_window_scores
        WHERE entity_id = ?
        ORDER BY window_start DESC
        LIMIT ?
        """,
        [entity_id, DEFAULT_RECENT_SCORES],
    ).fetchall()
    recent_scores = []
    for r in score_rows:
        energy = float(r[2]) if r[2] is not None else None
        shape = float(r[3]) if r[3] is not None else None
        candidates = [value for value in (energy, shape) if value is not None]
        z_value = max(candidates) if candidates else None
        hint = uncertainty_band(
            z_value,
            z_threshold,
            warn_band if warn_band is not None else 0.5,
        )
        band = hint["band"]
        if bool(r[4]) and band != "flagged":
            band = "flagged"
        recent_scores.append(
            SpectralWindowScore(
                window_start=r[0] if isinstance(r[0], datetime) else None,
                window_end=r[1] if isinstance(r[1], datetime) else None,
                energy_z=energy,
                shape_js_z=shape,
                flagged=bool(r[4]),
                z=hint["z"],
                band=band,
                display=hint["display"],
            )
        )

    return SpectrumResponse(
        entity_id=entity_id,
        features=features,
        freq_grid=freq_grid,
        psd_norm=psd_norm,
        downsampled=was_downsampled,
        bucket_seconds=bucket_seconds,
        recent_scores=recent_scores,
        z_threshold=z_threshold,
        warn_band=warn_band,
    )


def get_entity_stft(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    config: dict[str, Any],
    start: datetime | None = None,
    end: datetime | None = None,
) -> StftMatrixResponse:
    """Compute a capped STFT power matrix on-read from bucket counts."""
    from src.detectors.spectral.persist import (
        spectral_step_buckets,
        spectral_window_buckets,
    )
    from src.detectors.spectral.stft_matrix import (
        STFT_UI_MAX_FREQ_BINS,
        STFT_UI_MAX_TIME_BINS,
        compute_stft_power_matrix,
        stft_matrix_to_dict,
    )
    from src.config import spectral_settings

    bucket_seconds = get_entity_bucket_seconds(connection, entity_id)
    if bucket_seconds is None:
        bucket_seconds = int(config.get("bucketing", {}).get("bucket_seconds", 600))

    window_buckets = spectral_window_buckets(config)
    step_buckets = spectral_step_buckets(config, window_buckets)
    fft_window = str(spectral_settings(config).get("window", "hann"))

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
        ORDER BY bucket_start ASC
        """,
        params,
    ).fetchall()

    starts: list[datetime] = []
    counts: list[float] = []
    for row in rows:
        if not isinstance(row[0], datetime):
            continue
        starts.append(row[0])
        counts.append(float(row[1]) if row[1] is not None else 0.0)

    result = compute_stft_power_matrix(
        counts,
        starts,
        bucket_seconds=int(bucket_seconds),
        window_buckets=window_buckets,
        step_buckets=step_buckets,
        window=fft_window,
        max_freq_bins=STFT_UI_MAX_FREQ_BINS,
        max_time_bins=STFT_UI_MAX_TIME_BINS,
    )
    payload = stft_matrix_to_dict(result, entity_id=entity_id)
    return StftMatrixResponse.model_validate(payload)


def list_entity_buckets(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = DEFAULT_BUCKET_LIMIT,
    offset: int = 0,
    order: str | None = None,
) -> list[BucketPoint]:
    limit = clamp_limit(limit, DEFAULT_BUCKET_LIMIT, DEFAULT_BUCKET_LIMIT)
    offset = max(0, int(offset))
    resolved_order = resolve_series_order(order, start=start, end=end)
    clauses = ["entity_id = ?"]
    params: list[Any] = [entity_id]
    if start is not None:
        clauses.append("bucket_start >= ?")
        params.append(start)
    if end is not None:
        clauses.append("bucket_start <= ?")
        params.append(end)
    where = " AND ".join(clauses)
    direction = "DESC" if resolved_order == "newest" else "ASC"
    rows = connection.execute(
        f"""
        SELECT bucket_start, event_count
        FROM entity_bucket_counts
        WHERE {where}
        ORDER BY bucket_start {direction}
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    return [
        BucketPoint(
            bucket_start=r[0] if isinstance(r[0], datetime) else None,
            event_count=float(r[1]) if r[1] is not None else 0.0,
        )
        for r in rows
    ]


def count_entity_buckets(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> int:
    clauses = ["entity_id = ?"]
    params: list[Any] = [entity_id]
    if start is not None:
        clauses.append("bucket_start >= ?")
        params.append(start)
    if end is not None:
        clauses.append("bucket_start <= ?")
        params.append(end)
    where = " AND ".join(clauses)
    row = connection.execute(
        f"SELECT COUNT(*) FROM entity_bucket_counts WHERE {where}",
        params,
    ).fetchone()
    return int(row[0]) if row else 0


def get_entity_bucket_seconds(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
) -> int | None:
    """Return stored bucket width for an entity, or None if no counts exist."""
    row = connection.execute(
        """
        SELECT bucket_seconds
        FROM entity_bucket_counts
        WHERE entity_id = ?
        LIMIT 1
        """,
        [entity_id],
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])


def list_pipeline_runs(
    connection: duckdb.DuckDBPyConnection,
    *,
    limit: int = DEFAULT_RUNS_LIMIT,
    offset: int = 0,
) -> list[PipelineRunItem]:
    limit = clamp_limit(limit, DEFAULT_RUNS_LIMIT, MAX_RUNS_LIMIT)
    offset = max(0, int(offset))
    rows = connection.execute(
        """
        SELECT run_id, stage, started_at, finished_at, status
        FROM pipeline_runs
        ORDER BY started_at DESC
        LIMIT ? OFFSET ?
        """,
        [limit, offset],
    ).fetchall()
    return [
        PipelineRunItem(
            run_id=str(row[0]),
            stage=str(row[1] or ""),
            started_at=row[2] if isinstance(row[2], datetime) else None,
            finished_at=row[3] if isinstance(row[3], datetime) else None,
            status=str(row[4] or ""),
        )
        for row in rows
    ]


def count_pipeline_runs(connection: duckdb.DuckDBPyConnection) -> int:
    row = connection.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()
    return int(row[0]) if row else 0


def incident_kpis(connection: duckdb.DuckDBPyConnection) -> IncidentKpis:
    total_row = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()
    total = int(total_row[0]) if total_row else 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for severity, count in connection.execute(
        "SELECT severity, COUNT(*) FROM incidents GROUP BY severity"
    ).fetchall():
        key = str(severity or "").lower()
        if key in counts:
            counts[key] = int(count)
    last = connection.execute(
        """
        SELECT finished_at
        FROM pipeline_runs
        WHERE stage = 'correlate' AND status = 'success'
        ORDER BY finished_at DESC NULLS LAST
        LIMIT 1
        """
    ).fetchone()
    last_correlate = last[0] if last and isinstance(last[0], datetime) else None
    last_report_row = connection.execute(
        """
        SELECT finished_at
        FROM pipeline_runs
        WHERE stage = 'report' AND status = 'success'
        ORDER BY finished_at DESC NULLS LAST
        LIMIT 1
        """
    ).fetchone()
    last_report = (
        last_report_row[0]
        if last_report_row and isinstance(last_report_row[0], datetime)
        else None
    )
    detector_counts = {key: 0 for key in DETECTOR_COUNT_KEYS}
    for source, count in connection.execute(
        "SELECT source_detector, COUNT(*) FROM anomaly_events GROUP BY source_detector"
    ).fetchall():
        key = str(source or "")
        detector_counts[key] = int(count)
    log_source_counts: list[LogSourceCount] = []
    for source, count in connection.execute(
        """
        SELECT COALESCE(log_source, 'unknown'), COUNT(*)
        FROM parsed_events
        GROUP BY 1
        ORDER BY 2 DESC, 1
        LIMIT ?
        """,
        [LOG_SOURCE_KPI_LIMIT],
    ).fetchall():
        log_source_counts.append(
            LogSourceCount(log_source=str(source), count=int(count))
        )
    return IncidentKpis(
        total=total,
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        last_correlate_at=last_correlate,
        last_report_at=last_report,
        detector_counts=detector_counts,
        log_source_counts=log_source_counts,
    )


def list_incident_edges(
    connection: duckdb.DuckDBPyConnection,
    incident_id: str,
    *,
    limit: int = DEFAULT_INCIDENT_TIMELINE_LIMIT,
    offset: int = 0,
) -> IncidentEdgesResult | None:
    incident = get_incident(connection, incident_id)
    if incident is None:
        return None
    anomaly_ids = incident.contributing_anomaly_ids
    if not anomaly_ids:
        return IncidentEdgesResult(total=0, edges=[])
    placeholders = ", ".join("?" for _ in anomaly_ids)
    total_row = connection.execute(
        f"""
        SELECT COUNT(*)
        FROM correlation_edges
        WHERE dst_anomaly_id IN ({placeholders})
        """,
        anomaly_ids,
    ).fetchone()
    total = int(total_row[0]) if total_row else 0
    limit = clamp_limit(limit, DEFAULT_INCIDENT_TIMELINE_LIMIT, MAX_TIMELINE_LIMIT)
    offset = max(0, int(offset))
    rows = connection.execute(
        f"""
        SELECT
          c.edge_id,
          c.src_event_id,
          c.dst_anomaly_id,
          c.relation_type,
          c.session_id,
          p.event_timestamp,
          t.template_string,
          p.raw_fields,
          p.log_source
        FROM correlation_edges c
        LEFT JOIN parsed_events p ON p.event_id = c.src_event_id
        LEFT JOIN templates t ON t.template_id = p.template_id
        WHERE c.dst_anomaly_id IN ({placeholders})
        ORDER BY p.event_timestamp NULLS LAST, c.edge_id
        LIMIT ? OFFSET ?
        """,
        [*anomaly_ids, limit, offset],
    ).fetchall()
    edges: list[IncidentEdgeItem] = []
    for row in rows:
        fields = _parse_json_object(row[7])
        template = row[6]
        snippet = str(template) if template else _fields_snippet(fields)
        log_source = str(row[8]) if row[8] is not None else None
        edges.append(
            IncidentEdgeItem(
                edge_id=str(row[0]),
                src_event_id=int(row[1]) if row[1] is not None else None,
                dst_anomaly_id=str(row[2]),
                relation_type=str(row[3] or ""),
                session_id=str(row[4]) if row[4] is not None else None,
                event_timestamp=row[5] if isinstance(row[5], datetime) else None,
                snippet=snippet,
                template_string=str(template) if template is not None else None,
                log_source=log_source,
                raw_fields=fields,
            )
        )
    return IncidentEdgesResult(total=total, edges=edges)


def list_incident_timeline(
    connection: duckdb.DuckDBPyConnection,
    incident_id: str,
    *,
    limit: int = DEFAULT_INCIDENT_TIMELINE_LIMIT,
    offset: int = 0,
) -> tuple[list[IncidentTimelineEvent], int] | None:
    result = list_incident_edges(
        connection, incident_id, limit=limit, offset=offset
    )
    if result is None:
        return None
    items = [
        IncidentTimelineEvent(
            event_id=edge.src_event_id,
            event_timestamp=edge.event_timestamp,
            relation_type=edge.relation_type,
            template_string=edge.template_string,
            log_source=edge.log_source,
            raw_fields=edge.raw_fields,
            dst_anomaly_id=edge.dst_anomaly_id,
            session_id=edge.session_id,
            snippet=edge.snippet,
        )
        for edge in result.edges
    ]
    return items, result.total


def _fields_snippet(fields: dict[str, Any], *, max_len: int = 120) -> str | None:
    if not fields:
        return None
    text = "; ".join(f"{key}={value}" for key, value in fields.items())
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def search_entities(
    connection: duckdb.DuckDBPyConnection,
    q: str | None = None,
    *,
    limit: int = DEFAULT_ENTITY_SEARCH_LIMIT,
    offset: int = 0,
) -> list[EntityMeta]:
    limit = clamp_limit(limit, DEFAULT_ENTITY_SEARCH_LIMIT, MAX_ENTITY_SEARCH_LIMIT)
    offset = max(0, int(offset))
    if q:
        rows = connection.execute(
            """
            SELECT entity_id, entity_type, first_seen, last_seen, label
            FROM entities
            WHERE entity_id ILIKE '%' || ? || '%'
            ORDER BY last_seen DESC NULLS LAST, entity_id
            LIMIT ? OFFSET ?
            """,
            [q, limit, offset],
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT entity_id, entity_type, first_seen, last_seen, label
            FROM entities
            ORDER BY last_seen DESC NULLS LAST, entity_id
            LIMIT ? OFFSET ?
            """,
            [limit, offset],
        ).fetchall()
    return [
        EntityMeta(
            entity_id=str(row[0]),
            entity_type=row[1],
            first_seen=row[2] if isinstance(row[2], datetime) else None,
            last_seen=row[3] if isinstance(row[3], datetime) else None,
            label=row[4],
        )
        for row in rows
    ]


def count_entities(
    connection: duckdb.DuckDBPyConnection,
    q: str | None = None,
) -> int:
    if q:
        row = connection.execute(
            """
            SELECT COUNT(*) FROM entities
            WHERE entity_id ILIKE '%' || ? || '%'
            """,
            [q],
        ).fetchone()
    else:
        row = connection.execute("SELECT COUNT(*) FROM entities").fetchone()
    return int(row[0]) if row else 0


def list_top_entities_by_anomaly_count(
    connection: duckdb.DuckDBPyConnection,
    *,
    limit: int = DEFAULT_ENTITY_RANK_LIMIT,
    offset: int = 0,
) -> list[EntityAnomalyRank]:
    """Rank entities by anomaly_events count (then incident count)."""
    limit = clamp_limit(limit, DEFAULT_ENTITY_RANK_LIMIT, MAX_ENTITY_RANK_LIMIT)
    offset = max(0, int(offset))
    rows = connection.execute(
        """
        SELECT
            e.entity_id,
            e.entity_type,
            e.label,
            e.first_seen,
            e.last_seen,
            COALESCE(ae.anomaly_count, 0) AS anomaly_count,
            COALESCE(inc.incident_count, 0) AS incident_count
        FROM entities AS e
        LEFT JOIN (
            SELECT entity_id, COUNT(*) AS anomaly_count
            FROM anomaly_events
            GROUP BY entity_id
        ) AS ae ON ae.entity_id = e.entity_id
        LEFT JOIN (
            SELECT entity_id, COUNT(*) AS incident_count
            FROM incidents
            GROUP BY entity_id
        ) AS inc ON inc.entity_id = e.entity_id
        ORDER BY anomaly_count DESC, incident_count DESC,
                 e.last_seen DESC NULLS LAST, e.entity_id
        LIMIT ? OFFSET ?
        """,
        [limit, offset],
    ).fetchall()
    return [
        EntityAnomalyRank(
            entity_id=str(row[0]),
            entity_type=row[1],
            label=row[2],
            first_seen=row[3] if isinstance(row[3], datetime) else None,
            last_seen=row[4] if isinstance(row[4], datetime) else None,
            anomaly_count=int(row[5] or 0),
            incident_count=int(row[6] or 0),
        )
        for row in rows
    ]


def list_entity_incidents(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
) -> list[IncidentItem]:
    return list_incidents(
        connection, entity_id=entity_id, limit=limit, offset=offset
    )


def list_flagged_windows(
    connection: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[FlaggedWindow]:
    windows: list[FlaggedWindow] = []
    for source, table_name in (
        ("statistical", "statistical_window_scores"),
        ("spectral", "spectral_window_scores"),
        ("changepoint", "changepoint_window_scores"),
        ("seasonal", "seasonal_window_scores"),
    ):
        present = connection.execute(
            """
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'main' AND lower(table_name) = ?
            LIMIT 1
            """,
            [table_name.lower()],
        ).fetchone()
        if present is None:
            continue
        clauses = ["entity_id = ?", "flagged = TRUE"]
        params: list[Any] = [entity_id]
        if start is not None:
            clauses.append("window_end >= ?")
            params.append(start)
        if end is not None:
            clauses.append("window_start <= ?")
            params.append(end)
        rows = connection.execute(
            f"""
            SELECT window_start, window_end
            FROM {table_name}
            WHERE {' AND '.join(clauses)}
            ORDER BY window_start
            """,
            params,
        ).fetchall()
        for row in rows:
            windows.append(
                FlaggedWindow(
                    source=source,
                    window_start=row[0] if isinstance(row[0], datetime) else None,
                    window_end=row[1] if isinstance(row[1], datetime) else None,
                )
            )
    return windows
