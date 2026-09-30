"""Normalize flagged detector windows (+ cluster outliers) → anomaly_events (SDD §7.7)."""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from src.explainability.enrich import attach_explainability
from src.explainability.payload import (
    ExplainMergeSettings,
    spectral_crossing_legs,
)

logger = logging.getLogger(__name__)

ANOMALY_NAMESPACE = uuid.UUID("a8e0c018-1111-4222-8333-444455556666")

CLUSTER_OUTLIER_POLICIES = frozenset(
    {"overlapping_flags", "last_n_days", "entity_lifetime"}
)
DEFAULT_CLUSTER_OUTLIER_WINDOW = "overlapping_flags"
DEFAULT_CLUSTER_OUTLIER_LOOKBACK_DAYS = 14


class CorrelationError(Exception):
    """Raised when correlate cannot proceed (e.g. no detector sources)."""


class NothingToCorrelate(CorrelationError):
    """No flagged detector windows or cluster outliers — soft-skip in run-all."""


@dataclass(frozen=True)
class AnomalyEvent:
    anomaly_id: str
    entity_id: str
    window_start: datetime
    window_end: datetime
    source_detector: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MergeResult:
    anomalies: list[AnomalyEvent]
    discovered_sources: list[str]


def make_anomaly_id(source_detector: str, entity_id: str, window_start: datetime) -> str:
    """Deterministic UUID5 from (source, entity, window_start)."""
    key = f"{source_detector}|{entity_id}|{_ensure_utc(window_start).isoformat()}"
    return str(uuid.uuid5(ANOMALY_NAMESPACE, key))


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _finite_float(value: Any) -> float | None:
    """Return a finite float, or None for missing / NaN / non-numeric values."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:  # NaN
        return None
    return number


def cluster_outlier_window_for(
    *,
    first_seen: datetime | None,
    last_seen: datetime | None,
    other_flagged: Sequence[tuple[datetime, datetime]],
    policy: str,
    lookback_days: int,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Map a cluster-outlier entity onto a bounded anomaly window.

    ``overlapping_flags`` uses the union of this entity's other flagged windows
    this run; if none exist, it falls through to ``last_n_days``.
    """
    if policy not in CLUSTER_OUTLIER_POLICIES:
        raise CorrelationError(
            f"correlation.cluster_outlier_window must be one of "
            f"{sorted(CLUSTER_OUTLIER_POLICIES)}, got {policy!r}"
        )
    now_utc = _ensure_utc(now) if now is not None else datetime.now(timezone.utc)
    first = _ensure_utc(first_seen) if isinstance(first_seen, datetime) else None
    last = _ensure_utc(last_seen) if isinstance(last_seen, datetime) else None

    resolved = policy
    if resolved == "overlapping_flags":
        windows = [
            (_ensure_utc(start), _ensure_utc(end))
            for start, end in other_flagged
            if isinstance(start, datetime) and isinstance(end, datetime)
        ]
        if windows:
            return min(start for start, _ in windows), max(end for _, end in windows)
        resolved = "last_n_days"

    if resolved == "last_n_days":
        # Spec: [max(last_seen, now) - lookback, last_seen]. When last_seen is
        # in the past, using `now` as the left anchor inverts the window, so
        # the right edge stays last_seen (or now if unseen) and lookback is
        # contiguous behind it.
        end = last if last is not None else now_utc
        start = end - timedelta(days=lookback_days)
        if start > end:
            start, end = end, start
        return start, end

    start = first if first is not None else now_utc
    end = last if last is not None else start
    if start > end:
        start, end = end, start
    return start, end


def _table_exists(connection: Any, table_name: str) -> bool:
    row = connection.execute(
        """
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_name = ? AND table_schema = 'main'
        """,
        [table_name],
    ).fetchone()
    return bool(row and int(row[0]) > 0)


def _parse_shape_bins(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    return []


def _parse_ml_attribution(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def _bucket_seconds_by_entity(connection: Any) -> dict[str, int]:
    mapping: dict[str, int] = {}
    if not _table_exists(connection, "spectral_baselines"):
        return mapping
    rows = connection.execute(
        "SELECT entity_id, bucket_seconds FROM spectral_baselines"
    ).fetchall()
    for entity_id, bucket_seconds in rows:
        if bucket_seconds is None:
            continue
        try:
            mapping[str(entity_id)] = int(bucket_seconds)
        except (TypeError, ValueError):
            continue
    return mapping


def discover_and_merge(
    connection: Any,
    *,
    ml_model_type: str = "isolation_forest",
    ml_flagging: str = "mad_threshold",
    cluster_outlier_window: str = DEFAULT_CLUSTER_OUTLIER_WINDOW,
    cluster_outlier_lookback_days: int = DEFAULT_CLUSTER_OUTLIER_LOOKBACK_DAYS,
    explain: ExplainMergeSettings | None = None,
) -> MergeResult:
    """Discover available flagged sources and map them to AnomalyEvent rows.

    Raises NothingToCorrelate when no qualifying sources exist.
    """
    anomalies: list[AnomalyEvent] = []
    discovered: list[str] = []
    settings = explain or ExplainMergeSettings()
    bucket_by_entity = _bucket_seconds_by_entity(connection)

    if _table_exists(connection, "statistical_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, rate_z
            FROM statistical_window_scores
            WHERE flagged = TRUE
            """
        ).fetchall()
        if rows:
            discovered.append("statistical")
            logger.info("correlate source statistical: %d flagged windows", len(rows))
            for entity_id, window_start, window_end, rate_z in rows:
                if not isinstance(window_start, datetime):
                    continue
                rate = _finite_float(rate_z)
                if rate is None:
                    continue
                end = window_end if isinstance(window_end, datetime) else window_start
                eid = str(entity_id)
                anomalies.append(
                    AnomalyEvent(
                        anomaly_id=make_anomaly_id("statistical", eid, window_start),
                        entity_id=eid,
                        window_start=_ensure_utc(window_start),
                        window_end=_ensure_utc(end),
                        source_detector="statistical",
                        score=rate,
                        metadata={
                            "rate_z": rate,
                            "rule": "rate_z >= z_threshold",
                            "z_threshold": settings.statistical_z_threshold,
                            "bucket_seconds": bucket_by_entity.get(
                                eid, settings.bucket_seconds
                            ),
                        },
                    )
                )
        else:
            logger.info("correlate source statistical: present but 0 flagged")

    if _table_exists(connection, "changepoint_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, cusum_high, cusum_low,
                   direction
            FROM changepoint_window_scores
            WHERE flagged = TRUE
            """
        ).fetchall()
        if rows:
            discovered.append("changepoint")
            logger.info("correlate source changepoint: %d flagged windows", len(rows))
            for (
                entity_id,
                window_start,
                window_end,
                cusum_high,
                cusum_low,
                direction,
            ) in rows:
                if not isinstance(window_start, datetime):
                    continue
                high = _finite_float(cusum_high)
                low = _finite_float(cusum_low)
                if high is None and low is None:
                    continue
                score = max(v for v in (high, low) if v is not None)
                end = window_end if isinstance(window_end, datetime) else window_start
                eid = str(entity_id)
                anomalies.append(
                    AnomalyEvent(
                        anomaly_id=make_anomaly_id("changepoint", eid, window_start),
                        entity_id=eid,
                        window_start=_ensure_utc(window_start),
                        window_end=_ensure_utc(end),
                        source_detector="changepoint",
                        score=score,
                        metadata={
                            "cusum_high": high,
                            "cusum_low": low,
                            "decision_h": settings.changepoint_decision_h,
                            "drift_k": settings.changepoint_drift_k,
                            "direction": (
                                str(direction) if direction is not None else None
                            ),
                            "rule": "cusum_sigma >= decision_h",
                            "bucket_seconds": bucket_by_entity.get(
                                eid, settings.bucket_seconds
                            ),
                        },
                    )
                )
        else:
            logger.info("correlate source changepoint: present but 0 flagged")

    if _table_exists(connection, "seasonal_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, residual_z, residual,
                   seasonal_level, direction
            FROM seasonal_window_scores
            WHERE flagged = TRUE
            """
        ).fetchall()
        if rows:
            discovered.append("seasonal")
            logger.info("correlate source seasonal: %d flagged windows", len(rows))
            for (
                entity_id,
                window_start,
                window_end,
                residual_z,
                residual,
                seasonal_level,
                direction,
            ) in rows:
                if not isinstance(window_start, datetime):
                    continue
                z_value = _finite_float(residual_z)
                if z_value is None:
                    continue
                end = window_end if isinstance(window_end, datetime) else window_start
                eid = str(entity_id)
                anomalies.append(
                    AnomalyEvent(
                        anomaly_id=make_anomaly_id("seasonal", eid, window_start),
                        entity_id=eid,
                        window_start=_ensure_utc(window_start),
                        window_end=_ensure_utc(end),
                        source_detector="seasonal",
                        score=abs(z_value),
                        metadata={
                            "residual_z": z_value,
                            "residual": _finite_float(residual),
                            "seasonal_level": _finite_float(seasonal_level),
                            "z_threshold": settings.seasonal_z_threshold,
                            "period_buckets": settings.seasonal_period_buckets,
                            "direction": (
                                str(direction) if direction is not None else None
                            ),
                            "rule": "|residual_z| >= z_threshold",
                            "bucket_seconds": bucket_by_entity.get(
                                eid, settings.bucket_seconds
                            ),
                        },
                    )
                )
        else:
            logger.info("correlate source seasonal: present but 0 flagged")

    if _table_exists(connection, "spectral_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, energy_z, shape_js_z,
                   dominant_period_hours, shape_top_bins
            FROM spectral_window_scores
            WHERE flagged = TRUE
            """
        ).fetchall()
        if rows:
            discovered.append("spectral")
            logger.info("correlate source spectral: %d flagged windows", len(rows))
            for (
                entity_id,
                window_start,
                window_end,
                energy_z,
                shape_js_z,
                dominant_period_hours,
                shape_top_bins,
            ) in rows:
                if not isinstance(window_start, datetime):
                    continue
                ez = _finite_float(energy_z)
                sj = _finite_float(shape_js_z)
                if ez is None and sj is None:
                    continue
                end = window_end if isinstance(window_end, datetime) else window_start
                score = max(v for v in (ez, sj) if v is not None)
                eid = str(entity_id)
                energy_thr = settings.resolved_spectral_energy_threshold()
                shape_thr = settings.resolved_spectral_shape_threshold()
                metadata: dict[str, Any] = {
                    "rule": settings.spectral_rule,
                    "flag_mode": settings.spectral_flag_mode,
                    "z_threshold": settings.spectral_z_threshold,
                    "energy_z_threshold": energy_thr,
                    "shape_js_z_threshold": shape_thr,
                    "crossing_legs": spectral_crossing_legs(
                        ez, sj, energy_thr, shape_thr
                    ),
                    "bucket_seconds": bucket_by_entity.get(
                        eid, settings.bucket_seconds
                    ),
                }
                if ez is not None:
                    metadata["energy_z"] = ez
                if sj is not None:
                    metadata["shape_js_z"] = sj
                period = _finite_float(dominant_period_hours)
                if period is not None:
                    metadata["dominant_period_hours"] = period
                bins = _parse_shape_bins(shape_top_bins)
                if bins:
                    metadata["shape_top_bins"] = bins
                anomalies.append(
                    AnomalyEvent(
                        anomaly_id=make_anomaly_id("spectral", eid, window_start),
                        entity_id=eid,
                        window_start=_ensure_utc(window_start),
                        window_end=_ensure_utc(end),
                        source_detector="spectral",
                        score=score,
                        metadata=metadata,
                    )
                )
        else:
            logger.info("correlate source spectral: present but 0 flagged")

    if _table_exists(connection, "ml_window_scores"):
        rows = connection.execute(
            """
            SELECT entity_id, window_start, window_end, model_score,
                   model_snapshot_id, mad_z, attribution_json
            FROM ml_window_scores
            WHERE flagged = TRUE
            """
        ).fetchall()
        if rows:
            discovered.append("ml")
            logger.info("correlate source ml: %d flagged windows", len(rows))
            for (
                entity_id,
                window_start,
                window_end,
                model_score,
                model_snapshot_id,
                mad_z,
                attribution_json,
            ) in rows:
                if not isinstance(window_start, datetime):
                    continue
                score = _finite_float(model_score)
                if score is None:
                    continue
                end = window_end if isinstance(window_end, datetime) else window_start
                eid = str(entity_id)
                metadata = {
                    "model_type": ml_model_type,
                    "flagging": ml_flagging,
                    "model_score": score,
                    "mad_k": settings.ml_mad_k,
                    "bucket_seconds": bucket_by_entity.get(
                        eid, settings.bucket_seconds
                    ),
                }
                snapshot = (
                    str(model_snapshot_id) if model_snapshot_id is not None else None
                )
                if snapshot:
                    metadata["model_snapshot_id"] = snapshot
                mad = _finite_float(mad_z)
                if mad is not None:
                    metadata["mad_z"] = mad
                attribution = _parse_ml_attribution(attribution_json)
                if attribution:
                    features = attribution.get("top_contributing_features")
                    if isinstance(features, list) and features:
                        metadata["top_contributing_features"] = features
                    attr_templates = attribution.get("top_templates")
                    if isinstance(attr_templates, list) and attr_templates:
                        metadata["attribution_templates"] = attr_templates
                    ensemble_meta = attribution.get("ensemble")
                    if isinstance(ensemble_meta, dict) and ensemble_meta:
                        metadata["ensemble"] = ensemble_meta
                anomalies.append(
                    AnomalyEvent(
                        anomaly_id=make_anomaly_id("ml", eid, window_start),
                        entity_id=eid,
                        window_start=_ensure_utc(window_start),
                        window_end=_ensure_utc(end),
                        source_detector="ml",
                        score=score,
                        metadata=metadata,
                    )
                )
        else:
            logger.info("correlate source ml: present but 0 flagged")

    if _table_exists(connection, "entity_clusters"):
        latest = connection.execute(
            """
            SELECT cluster_run_id
            FROM entity_clusters
            ORDER BY computed_at DESC
            LIMIT 1
            """
        ).fetchone()
        if latest:
            cluster_run_id = str(latest[0])
            rows = connection.execute(
                """
                SELECT c.entity_id, e.first_seen, e.last_seen, c.cluster_run_id
                FROM entity_clusters c
                LEFT JOIN entities e ON e.entity_id = c.entity_id
                WHERE c.cluster_id = -1 AND c.cluster_run_id = ?
                """,
                [cluster_run_id],
            ).fetchall()
            if rows:
                other_flagged_by_entity: dict[str, list[tuple[datetime, datetime]]] = (
                    defaultdict(list)
                )
                for anomaly in anomalies:
                    other_flagged_by_entity[anomaly.entity_id].append(
                        (anomaly.window_start, anomaly.window_end)
                    )
                baseline_ids: set[str] = set()
                if _table_exists(connection, "spectral_baselines"):
                    baseline_rows = connection.execute(
                        "SELECT entity_id FROM spectral_baselines"
                    ).fetchall()
                    baseline_ids = {str(row[0]) for row in baseline_rows}
                kept_outliers = [
                    row for row in rows if str(row[0]) in baseline_ids
                ]
                skipped_cold_start = len(rows) - len(kept_outliers)
                if skipped_cold_start:
                    logger.info(
                        "correlate skip cluster_outlier without baseline: %d entities",
                        skipped_cold_start,
                    )
                if kept_outliers:
                    discovered.append("cluster_outlier")
                    logger.info(
                        "correlate source cluster_outlier: %d entities (run %s)",
                        len(kept_outliers),
                        cluster_run_id,
                    )
                    now = datetime.now(timezone.utc)
                    for entity_id, first_seen, last_seen, run_id in kept_outliers:
                        start, end = cluster_outlier_window_for(
                            first_seen=first_seen if isinstance(first_seen, datetime) else None,
                            last_seen=last_seen if isinstance(last_seen, datetime) else None,
                            other_flagged=other_flagged_by_entity[str(entity_id)],
                            policy=cluster_outlier_window,
                            lookback_days=cluster_outlier_lookback_days,
                            now=now,
                        )
                        anomalies.append(
                            AnomalyEvent(
                                anomaly_id=make_anomaly_id(
                                    "cluster_outlier", str(entity_id), start
                                ),
                                entity_id=str(entity_id),
                                window_start=start,
                                window_end=end,
                                source_detector="cluster_outlier",
                                score=1.0,
                                metadata={
                                    "cluster_run_id": str(run_id),
                                    "cluster_id": -1,
                                    "window_policy": cluster_outlier_window,
                                    "lookback_days": cluster_outlier_lookback_days,
                                    "bucket_seconds": bucket_by_entity.get(
                                        str(entity_id), settings.bucket_seconds
                                    ),
                                },
                            )
                        )
                else:
                    logger.info(
                        "correlate source cluster_outlier: present but 0 outliers "
                        "after cold-start skip"
                    )
            else:
                logger.info("correlate source cluster_outlier: present but 0 outliers")
        else:
            logger.info("correlate source cluster_outlier: table empty")

    if not discovered:
        raise NothingToCorrelate(
            "nothing to correlate: no flagged detector windows or cluster outliers found"
        )

    attach_explainability(connection, anomalies, settings)

    logger.info(
        "correlate discovered sources: %s (%d anomalies)",
        ",".join(discovered),
        len(anomalies),
    )
    return MergeResult(anomalies=anomalies, discovered_sources=discovered)


def metadata_json(metadata: dict[str, Any]) -> str:
    return json.dumps(metadata)
