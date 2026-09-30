"""Cheap warehouse joins that complete R7 flag metadata at correlate time."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

import numpy as np
from sklearn.preprocessing import StandardScaler

from src.explainability.payload import ExplainMergeSettings, json_safe
from src.explainability.playbooks import DEFAULT_PLAYBOOKS, playbook_for


def _table_exists(connection: Any, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_name = ? AND table_schema = 'main'
        """,
        [table_name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _as_utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _window_key(
    entity_id: str, window_start: datetime, window_end: datetime
) -> tuple[str, datetime, datetime]:
    return (entity_id, window_start, window_end)


def _in_window(ts: datetime | None, start: datetime, end: datetime) -> bool:
    ts_utc = _as_utc(ts)
    start_utc = _as_utc(start)
    end_utc = _as_utc(end)
    if ts_utc is None or start_utc is None or end_utc is None:
        return False
    return start_utc <= ts_utc < end_utc


def _load_events(
    connection: Any,
    entity_ids: list[str],
) -> list[tuple[str, datetime, str | None, str | None, str | None]]:
    if not entity_ids or not _table_exists(connection, "parsed_events"):
        return []
    placeholders = ", ".join("?" for _ in entity_ids)
    has_templates = _table_exists(connection, "templates")
    join_sql = (
        "LEFT JOIN templates t ON t.template_id = p.template_id" if has_templates else ""
    )
    string_sql = "t.template_string" if has_templates else "CAST(NULL AS VARCHAR)"
    rows = connection.execute(
        f"""
        SELECT p.entity_id, p.event_timestamp, p.log_source,
               p.template_id, {string_sql}
        FROM parsed_events p
        {join_sql}
        WHERE p.entity_id IN ({placeholders})
        """,
        list(entity_ids),
    ).fetchall()
    out: list[tuple[str, datetime, str | None, str | None, str | None]] = []
    for entity_id, ts, log_source, template_id, template_string in rows:
        utc = _as_utc(ts)
        if utc is None:
            continue
        out.append(
            (
                str(entity_id),
                utc,
                str(log_source) if log_source else None,
                str(template_id) if template_id is not None else None,
                str(template_string) if template_string is not None else None,
            )
        )
    return out


def _load_buckets(
    connection: Any,
    entity_ids: list[str],
) -> list[tuple[str, datetime, float]]:
    if not entity_ids or not _table_exists(connection, "entity_bucket_counts"):
        return []
    placeholders = ", ".join("?" for _ in entity_ids)
    rows = connection.execute(
        f"""
        SELECT entity_id, bucket_start, event_count
        FROM entity_bucket_counts
        WHERE entity_id IN ({placeholders})
        """,
        list(entity_ids),
    ).fetchall()
    out: list[tuple[str, datetime, float]] = []
    for entity_id, bucket_start, event_count in rows:
        utc = _as_utc(bucket_start)
        if utc is None:
            continue
        try:
            count = float(event_count or 0.0)
        except (TypeError, ValueError):
            count = 0.0
        out.append((str(entity_id), utc, count))
    return out


def _sources_and_templates_by_window(
    events: list[tuple[str, datetime, str | None, str | None, str | None]],
    windows: list[tuple[str, datetime, datetime]],
    *,
    log_source_limit: int,
    template_limit: int,
) -> tuple[
    dict[tuple[str, datetime, datetime], list[dict[str, Any]]],
    dict[tuple[str, datetime, datetime], list[dict[str, Any]]],
]:
    source_counts: dict[tuple[str, datetime, datetime], Counter[str]] = defaultdict(
        Counter
    )
    template_counts: dict[
        tuple[str, datetime, datetime], Counter[tuple[str, str | None]]
    ] = defaultdict(Counter)
    for entity_id, start, end in windows:
        key = _window_key(entity_id, start, end)
        for ev_entity, ts, log_source, template_id, template_string in events:
            if ev_entity != entity_id or not _in_window(ts, start, end):
                continue
            source_counts[key][log_source or "(unknown)"] += 1
            if template_id:
                template_counts[key][(template_id, template_string)] += 1
    sources: dict[tuple[str, datetime, datetime], list[dict[str, Any]]] = {}
    templates: dict[tuple[str, datetime, datetime], list[dict[str, Any]]] = {}
    for key, counter in source_counts.items():
        ranked = counter.most_common(log_source_limit)
        sources[key] = [
            {"log_source": name, "event_count": int(count)} for name, count in ranked
        ]
    for key, counter in template_counts.items():
        ranked = counter.most_common(template_limit)
        templates[key] = [
            {
                "template_id": template_id,
                "template_string": template_string,
                "event_count": int(count),
            }
            for (template_id, template_string), count in ranked
        ]
    return sources, templates


def _gaps_by_window(
    buckets: list[tuple[str, datetime, float]],
    windows: list[tuple[str, datetime, datetime]],
    *,
    gap_zero_fraction: float,
) -> dict[tuple[str, datetime, datetime], dict[str, Any]]:
    out: dict[tuple[str, datetime, datetime], dict[str, Any]] = {}
    for entity_id, start, end in windows:
        key = _window_key(entity_id, start, end)
        n_buckets = 0
        n_zero = 0
        for b_entity, ts, count in buckets:
            if b_entity != entity_id or not _in_window(ts, start, end):
                continue
            n_buckets += 1
            if count == 0.0:
                n_zero += 1
        fraction = (n_zero / n_buckets) if n_buckets else None
        possible = (
            bool(fraction is not None and fraction >= gap_zero_fraction)
            if n_buckets
            else None
        )
        out[key] = {
            "bucket_count": n_buckets,
            "zero_bucket_count": n_zero,
            "zero_fraction": fraction,
            "possible_gap": possible,
        }
    return out


def cluster_run_stats(
    connection: Any, cluster_run_id: str
) -> dict[str, Any]:
    if not _table_exists(connection, "entity_clusters"):
        return {}
    rows = connection.execute(
        """
        SELECT cluster_id, COUNT(*)
        FROM entity_clusters
        WHERE cluster_run_id = ?
        GROUP BY cluster_id
        """,
        [cluster_run_id],
    ).fetchall()
    sizes = {int(cluster_id): int(count) for cluster_id, count in rows}
    clustered_sizes = [count for cid, count in sizes.items() if cid != -1]
    n_outliers = sizes.get(-1, 0)
    return {
        "n_entities": int(sum(sizes.values())),
        "n_outliers": n_outliers,
        "n_clustered": int(sum(clustered_sizes)),
        "n_clusters": len(clustered_sizes),
        "largest_cluster_size": max(clustered_sizes) if clustered_sizes else 0,
        "peer_cluster_size": 0,
    }


def nearest_outlier_distances(
    connection: Any, cluster_run_id: str
) -> dict[str, float]:
    """Min scaled Euclidean distance from each DBSCAN -1 entity to a clustered peer."""
    if not _table_exists(connection, "entity_spectral_features"):
        return {}
    if not _table_exists(connection, "entity_clusters"):
        return {}
    rows = connection.execute(
        """
        SELECT
          c.entity_id,
          c.cluster_id,
          f.dominant_period_hours,
          f.dominant_power_frac,
          f.spectral_entropy,
          f.total_power
        FROM entity_clusters c
        JOIN entity_spectral_features f ON f.entity_id = c.entity_id
        WHERE c.cluster_run_id = ?
        """,
        [cluster_run_id],
    ).fetchall()
    if len(rows) < 2:
        return {}
    entity_ids = [str(row[0]) for row in rows]
    labels = [int(row[1]) for row in rows]
    matrix = np.array(
        [[float(row[2]), float(row[3]), float(row[4]), float(row[5])] for row in rows],
        dtype=np.float64,
    )
    clustered_idx = [i for i, label in enumerate(labels) if label != -1]
    outlier_idx = [i for i, label in enumerate(labels) if label == -1]
    if not clustered_idx or not outlier_idx:
        return {}
    scaled = StandardScaler().fit_transform(matrix)
    clustered = scaled[clustered_idx]
    out: dict[str, float] = {}
    for index in outlier_idx:
        diffs = clustered - scaled[index]
        dist = float(np.min(np.linalg.norm(diffs, axis=1)))
        if dist == dist:
            out[entity_ids[index]] = dist
    return out


def attach_explainability(
    connection: Any,
    anomalies: list[Any],
    settings: ExplainMergeSettings,
) -> None:
    """Mutate each anomaly's metadata dict with R7 context (in-place)."""
    if not anomalies:
        return
    playbooks = settings.playbooks if settings.playbooks is not None else DEFAULT_PLAYBOOKS
    windows = [
        (row.entity_id, row.window_start, row.window_end) for row in anomalies
    ]
    entity_ids = sorted({row.entity_id for row in anomalies})
    events = _load_events(connection, entity_ids)
    buckets = _load_buckets(connection, entity_ids)
    sources, templates = _sources_and_templates_by_window(
        events,
        windows,
        log_source_limit=settings.log_source_limit,
        template_limit=settings.ml_top_templates,
    )
    gaps = _gaps_by_window(
        buckets, windows, gap_zero_fraction=settings.gap_zero_fraction
    )

    cluster_cache: dict[str, dict[str, Any]] = {}
    distance_cache: dict[str, dict[str, float]] = {}

    for anomaly in anomalies:
        meta = anomaly.metadata
        key = _window_key(anomaly.entity_id, anomaly.window_start, anomaly.window_end)
        meta.setdefault("bucket_seconds", settings.bucket_seconds)
        gap = gaps.get(key)
        if gap is not None:
            meta["gap"] = gap
        log_sources = sources.get(key)
        if log_sources:
            meta["log_sources"] = log_sources
        if anomaly.source_detector == "ml":
            top = templates.get(key)
            attr_templates = meta.get("attribution_templates")
            if isinstance(attr_templates, list) and attr_templates:
                # Prefer feature-contribution ranking; keep event counts when ids match.
                count_by_id = {
                    str(row.get("template_id")): row
                    for row in (top or [])
                    if isinstance(row, dict) and row.get("template_id") is not None
                }
                merged: list[dict[str, Any]] = []
                for row in attr_templates:
                    if not isinstance(row, dict):
                        continue
                    tid = row.get("template_id")
                    if tid is None or str(tid) == "":
                        continue
                    base = dict(count_by_id.get(str(tid)) or {})
                    base["template_id"] = str(tid)
                    if row.get("template_string") is not None:
                        base["template_string"] = row.get("template_string")
                    elif "template_string" not in base:
                        base["template_string"] = None
                    if "event_count" not in base:
                        base["event_count"] = int(row.get("event_count") or 0)
                    contribution = row.get("contribution")
                    if contribution is not None:
                        try:
                            base["contribution"] = float(contribution)
                        except (TypeError, ValueError):
                            pass
                    merged.append(base)
                if merged:
                    meta["top_templates"] = merged
            elif top:
                meta["top_templates"] = top
            meta.setdefault("mad_k", settings.ml_mad_k)
            meta.pop("attribution_templates", None)
        if anomaly.source_detector == "cluster_outlier":
            run_id = str(meta.get("cluster_run_id") or "")
            if run_id and run_id not in cluster_cache:
                cluster_cache[run_id] = cluster_run_stats(connection, run_id)
                distance_cache[run_id] = nearest_outlier_distances(
                    connection, run_id
                )
            stats = cluster_cache.get(run_id) or {}
            meta.update(stats)
            meta.setdefault("cluster_id", -1)
            distance = (distance_cache.get(run_id) or {}).get(anomaly.entity_id)
            if distance is not None:
                meta["nearest_distance"] = distance
        model_type = None
        if anomaly.source_detector == "ml":
            raw_model = meta.get("model_type")
            if raw_model is not None:
                model_type = str(raw_model)
        playbook = playbook_for(
            anomaly.source_detector,
            playbooks=playbooks,
            model_type=model_type,
        )
        if playbook:
            meta["playbook"] = playbook
        sanitized = json_safe(meta)
        meta.clear()
        if isinstance(sanitized, dict):
            meta.update(sanitized)
