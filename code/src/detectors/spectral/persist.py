"""Orchestrate Phase 6 detect-spectral and cluster stages."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from src.config import (
    ConfigError,
    explainability_settings,
    spectral_cluster_min_entities,
    spectral_flagging_settings,
    spectral_max_buckets_per_entity,
    spectral_settings,
)
from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.detectors.spectral.baseline import compute_baseline
from src.detectors.spectral.clustering import cluster_entities, stable_cluster_run_id
from src.detectors.spectral.features import EntitySpectralFeatures, spectral_summary_features
from src.detectors.spectral.series import as_count_series, series_has_nonfinite
from src.detectors.spectral.windowed import windowed_deviation
from src.detectors.spectral.writers import (
    clear_entity_clusters_table,
    clear_entity_spectral_features_table,
    clear_spectral_baselines_table,
    clear_spectral_scores_output,
    clear_spectral_window_scores_table,
    insert_entity_clusters,
    insert_entity_spectral_features,
    insert_spectral_baseline,
    spectral_scores_dir,
    sync_spectral_window_scores_from_parquet,
    write_entity_spectral_windows,
)
from src.orchestration.workers import map_entities, resolve_backend, resolve_worker_count
from src.timeseries.analysis_window import (
    attach_analysis_window_params,
    bucket_series_sql,
    execute_query,
    resolve_analysis_window,
)

logger = logging.getLogger(__name__)


@dataclass
class SpectralSummary:
    entities_processed: int = 0
    entities_skipped_insufficient_history: int = 0
    entities_skipped_empty: int = 0
    entities_skipped_cap: int = 0
    entities_failed: int = 0
    baselines_written: int = 0
    features_written: int = 0
    windows_total: int = 0
    windows_flagged: int = 0
    max_energy_z: float = 0.0
    max_shape_js_z: float = 0.0
    n_workers_used: int = 1
    parallel_backend: str = "none"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClusterSummary:
    entities_clustered: int = 0
    outliers: int = 0
    cluster_run_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SpectralError(Exception):
    """Raised when detect-spectral cannot proceed."""


class ClusterError(Exception):
    """Raised when cluster cannot proceed."""


class NothingToCluster(Exception):
    """Soft-skip: no entity_spectral_features yet (empty after detect-spectral cold start)."""


def spectral_window_buckets(config: dict[str, Any]) -> int:
    window_hours = config["spectral"]["window_hours"]
    bucket_seconds = config["bucketing"]["bucket_seconds"]
    return max(1, round(float(window_hours) * 3600 / bucket_seconds))


def spectral_step_buckets(config: dict[str, Any], window_buckets: int) -> int:
    step_fraction = config["spectral"]["step_fraction"]
    return max(1, round(window_buckets * float(step_fraction)))


def _assert_stored_bucket_seconds_match(connection: Any, expected: int) -> None:
    """Refuse to score series stored at a different bucket width than config."""
    rows = connection.execute(
        "SELECT DISTINCT bucket_seconds FROM entity_bucket_counts"
    ).fetchall()
    found = {int(row[0]) for row in rows if row[0] is not None}
    if found != {expected}:
        raise SpectralError(
            "entity_bucket_counts.bucket_seconds "
            f"{sorted(found)} != bucketing.bucket_seconds={expected}; "
            "re-run bucket with the current config before detect-spectral"
        )


def _validate_spectral_config(
    config: dict[str, Any],
) -> tuple[int, int, int, int]:
    bucket_seconds = config["bucketing"]["bucket_seconds"]
    if not isinstance(bucket_seconds, int) or bucket_seconds <= 0:
        raise SpectralError(
            f"bucketing.bucket_seconds must be a positive integer, got {bucket_seconds!r}"
        )

    window_buckets = spectral_window_buckets(config)
    step_buckets = spectral_step_buckets(config, window_buckets)
    baseline_max_nperseg = config["spectral"]["baseline_max_nperseg"]

    if not isinstance(baseline_max_nperseg, int) or baseline_max_nperseg <= 0:
        raise SpectralError(
            "spectral.baseline_max_nperseg must be a positive integer"
        )

    return (
        window_buckets,
        step_buckets,
        int(baseline_max_nperseg),
        bucket_seconds,
    )


@dataclass(frozen=True)
class SpectralEntityWork:
    entity_id: str
    bucket_starts: tuple[datetime, ...]
    event_counts: tuple[float, ...]
    bucket_seconds: int
    window_buckets: int
    step_buckets: int
    z_threshold: float
    baseline_max_nperseg: int
    fft_window: str
    min_welch_length: int
    max_buckets_per_entity: int
    top_js_bins: int = 3
    energy_z_threshold: float | None = None
    shape_js_z_threshold: float | None = None
    flag_mode: str = "or"
    discount_last_window: bool = False


@dataclass(frozen=True)
class SpectralEntityResult:
    entity_id: str
    skip_reason: str | None
    baseline: Any = None
    features: EntitySpectralFeatures | None = None
    window_rows: tuple = ()


def compute_entity_spectral(work: SpectralEntityWork) -> SpectralEntityResult:
    """Compute baseline, features, and windows for one entity (pickleable)."""
    if not work.bucket_starts:
        return SpectralEntityResult(work.entity_id, "empty")
    if len(work.event_counts) > work.max_buckets_per_entity:
        return SpectralEntityResult(work.entity_id, "cap_exceeded")

    counts = as_count_series(work.event_counts)
    if series_has_nonfinite(counts):
        return SpectralEntityResult(work.entity_id, "non_finite")
    baseline = compute_baseline(
        counts,
        entity_id=work.entity_id,
        bucket_seconds=work.bucket_seconds,
        baseline_max_nperseg=work.baseline_max_nperseg,
        window=work.fft_window,
        min_welch_length=work.min_welch_length,
    )
    if baseline is None:
        return SpectralEntityResult(work.entity_id, "insufficient_history")

    features = spectral_summary_features(baseline)
    if counts.size < work.window_buckets:
        return SpectralEntityResult(
            work.entity_id,
            "insufficient_history",
            baseline=baseline,
            features=features,
        )

    window_rows = windowed_deviation(
        counts,
        list(work.bucket_starts),
        baseline,
        bucket_seconds=work.bucket_seconds,
        window_buckets=work.window_buckets,
        step_buckets=work.step_buckets,
        z_threshold=work.z_threshold,
        window=work.fft_window,
        min_welch_length=work.min_welch_length,
        top_js_bins=work.top_js_bins,
        energy_z_threshold=work.energy_z_threshold,
        shape_js_z_threshold=work.shape_js_z_threshold,
        flag_mode=work.flag_mode,
        discount_last_window=work.discount_last_window,
    )
    if not window_rows:
        return SpectralEntityResult(
            work.entity_id,
            "insufficient_history",
            baseline=baseline,
            features=features,
        )
    return SpectralEntityResult(
        work.entity_id,
        None,
        baseline=baseline,
        features=features,
        window_rows=tuple(window_rows),
    )


def _collect_spectral_work(
    bucket_rows: list[Any],
    columns: list[str],
    *,
    window_buckets: int,
    step_buckets: int,
    z_threshold: float,
    baseline_max_nperseg: int,
    fft_window: str,
    min_welch_length: int,
    max_buckets_per_entity: int,
    top_js_bins: int = 3,
    energy_z_threshold: float | None = None,
    shape_js_z_threshold: float | None = None,
    flag_mode: str = "or",
    discount_last_window: bool = False,
) -> list[SpectralEntityWork]:
    work_items: list[SpectralEntityWork] = []
    current_entity: str | None = None
    current_starts: list[datetime] = []
    current_counts: list[float] = []
    entity_bucket_seconds: int | None = None

    def flush() -> None:
        nonlocal current_entity, current_starts, current_counts, entity_bucket_seconds
        if current_entity is None or entity_bucket_seconds is None:
            return
        work_items.append(
            SpectralEntityWork(
                entity_id=current_entity,
                bucket_starts=tuple(current_starts),
                event_counts=tuple(current_counts),
                bucket_seconds=entity_bucket_seconds,
                window_buckets=window_buckets,
                step_buckets=step_buckets,
                z_threshold=z_threshold,
                baseline_max_nperseg=baseline_max_nperseg,
                fft_window=fft_window,
                min_welch_length=min_welch_length,
                max_buckets_per_entity=max_buckets_per_entity,
                top_js_bins=top_js_bins,
                energy_z_threshold=energy_z_threshold,
                shape_js_z_threshold=shape_js_z_threshold,
                flag_mode=flag_mode,
                discount_last_window=discount_last_window,
            )
        )
        current_starts = []
        current_counts = []
        entity_bucket_seconds = None

    for values in bucket_rows:
        row = dict(zip(columns, values, strict=True))
        entity_id = str(row["entity_id"])
        bucket_start = row["bucket_start"]
        row_bucket_seconds = int(row["bucket_seconds"])
        event_count = float(row["event_count"])
        if not isinstance(bucket_start, datetime):
            continue
        if current_entity is not None and entity_id != current_entity:
            flush()
        current_entity = entity_id
        entity_bucket_seconds = row_bucket_seconds
        current_starts.append(bucket_start)
        current_counts.append(event_count)
    flush()
    return work_items


def _apply_spectral_result(
    result: SpectralEntityResult | Exception,
    *,
    work: SpectralEntityWork,
    scores_dir: Any,
    connection: Any,
    summary: SpectralSummary,
) -> None:
    if isinstance(result, Exception):
        summary.entities_failed += 1
        logger.error(
            "detect-spectral failed for entity_id=%s: %r",
            work.entity_id,
            result,
        )
        return
    if result.skip_reason == "cap_exceeded":
        summary.entities_skipped_cap += 1
        logger.info(
            "detect-spectral skipped entity_id=%s: more than %s buckets",
            work.entity_id,
            work.max_buckets_per_entity,
        )
        return
    if result.baseline is None:
        if result.skip_reason == "empty":
            summary.entities_skipped_empty += 1
        else:
            summary.entities_skipped_insufficient_history += 1
        return

    insert_spectral_baseline(connection, result.baseline)
    summary.baselines_written += 1
    if result.features is not None and result.skip_reason is None:
        insert_entity_spectral_features(connection, result.features)
        summary.features_written += 1

    if result.skip_reason is not None or not result.window_rows:
        summary.entities_skipped_insufficient_history += 1
        return

    window_rows = list(result.window_rows)
    path = write_entity_spectral_windows(scores_dir, result.entity_id, window_rows)
    if path is None:
        summary.entities_skipped_empty += 1
        return

    summary.entities_processed += 1
    summary.windows_total += len(window_rows)
    summary.windows_flagged += sum(1 for row in window_rows if row.flagged)
    max_e = max(row.energy_z for row in window_rows)
    max_s = max(row.shape_js_z for row in window_rows)
    if max_e > summary.max_energy_z:
        summary.max_energy_z = max_e
    if max_s > summary.max_shape_js_z:
        summary.max_shape_js_z = max_s


def run_detect_spectral(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> SpectralSummary:
    """Run Welch baseline + STFT window scoring for all entities."""
    connection = get_connection(config)
    summary = SpectralSummary()
    (
        window_buckets,
        step_buckets,
        baseline_max_nperseg,
        bucket_seconds,
    ) = _validate_spectral_config(config)
    try:
        flagging = spectral_flagging_settings(config)
    except ConfigError as exc:
        raise SpectralError(str(exc)) from exc
    z_threshold = float(flagging["z_threshold"])
    energy_z_threshold = float(flagging["energy_z_threshold"])
    shape_js_z_threshold = float(flagging["shape_js_z_threshold"])
    flag_mode = str(flagging["flag_mode"])
    discount_last_window = bool(flagging["discount_last_window"])
    fft = spectral_settings(config)
    fft_window = str(fft["window"])
    min_welch_length = int(fft["min_welch_length"])
    try:
        max_buckets_per_entity = spectral_max_buckets_per_entity(config)
        top_js_bins = int(explainability_settings(config)["spectral_top_js_bins"])
    except ConfigError as exc:
        raise SpectralError(str(exc)) from exc
    scores_dir = spectral_scores_dir(config)
    backend = resolve_backend(config)
    params = {
        "config_path": config_path,
        "scores_dir": str(scores_dir),
        "window_buckets": window_buckets,
        "step_buckets": step_buckets,
        "z_threshold": z_threshold,
        "energy_z_threshold": energy_z_threshold,
        "shape_js_z_threshold": shape_js_z_threshold,
        "flag_mode": flag_mode,
        "discount_last_window": discount_last_window,
        "baseline_max_nperseg": baseline_max_nperseg,
        "bucket_seconds": bucket_seconds,
        "fft_window": fft_window,
        "min_welch_length": min_welch_length,
        "max_buckets_per_entity": max_buckets_per_entity,
        "top_js_bins": top_js_bins,
        "parallel_backend": backend,
    }
    analysis_window = resolve_analysis_window(config, connection, source="buckets")
    attach_analysis_window_params(params, analysis_window)
    run_id = record_run_start(connection, stage="detect-spectral", params=params)

    try:
        bucket_count = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        if int(bucket_count) == 0:
            raise SpectralError("No entity_bucket_counts found; run bucket first")

        _assert_stored_bucket_seconds_match(connection, bucket_seconds)

        clear_spectral_scores_output(config)
        clear_spectral_window_scores_table(connection)
        clear_spectral_baselines_table(connection)
        clear_entity_spectral_features_table(connection)

        sql, sql_params = bucket_series_sql(analysis_window)
        relation = execute_query(connection, sql, sql_params)
        columns = [desc[0] for desc in relation.description]
        bucket_rows = relation.fetchall()
        work_items = _collect_spectral_work(
            bucket_rows,
            columns,
            window_buckets=window_buckets,
            step_buckets=step_buckets,
            z_threshold=z_threshold,
            baseline_max_nperseg=baseline_max_nperseg,
            fft_window=fft_window,
            min_welch_length=min_welch_length,
            max_buckets_per_entity=max_buckets_per_entity,
            top_js_bins=top_js_bins,
            energy_z_threshold=energy_z_threshold,
            shape_js_z_threshold=shape_js_z_threshold,
            flag_mode=flag_mode,
            discount_last_window=discount_last_window,
        )
        n_workers = resolve_worker_count(config, len(work_items))
        summary.n_workers_used = n_workers
        summary.parallel_backend = backend
        params["n_workers_used"] = n_workers

        results = map_entities(
            compute_entity_spectral,
            work_items,
            backend=backend,
            n_workers=n_workers,
        )
        for result, work in zip(results, work_items, strict=True):
            _apply_spectral_result(
                result,
                work=work,
                scores_dir=scores_dir,
                connection=connection,
                summary=summary,
            )

        if summary.entities_processed > 0:
            sync_spectral_window_scores_from_parquet(
                connection, scores_dir, run_id=run_id, config=config
            )
        register_parquet_views(connection, config)

        params_with_summary = {**params, "summary": summary.as_dict()}
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        if summary.entities_failed > 0:
            raise SpectralError(
                f"detect-spectral failed for {summary.entities_failed} entit"
                f"{'y' if summary.entities_failed == 1 else 'ies'}"
            )
        record_run_finish(connection, run_id, "success")

        logger.info("detect-spectral summary: %s", summary.as_dict())
        print("detect-spectral summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()


def _load_entity_spectral_features(connection: Any) -> list[EntitySpectralFeatures]:
    relation = connection.execute(
        """
        SELECT
            entity_id,
            dominant_period_hours,
            dominant_power_frac,
            spectral_entropy,
            total_power,
            computed_at
        FROM entity_spectral_features
        ORDER BY entity_id
        """
    )
    columns = [desc[0] for desc in relation.description]
    rows: list[EntitySpectralFeatures] = []
    for values in relation.fetchall():
        row = dict(zip(columns, values, strict=True))
        rows.append(
            EntitySpectralFeatures(
                entity_id=str(row["entity_id"]),
                dominant_period_hours=float(row["dominant_period_hours"]),
                dominant_power_frac=float(row["dominant_power_frac"]),
                spectral_entropy=float(row["spectral_entropy"]),
                total_power=float(row["total_power"]),
                computed_at=row["computed_at"],
            )
        )
    return rows


def run_cluster(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> ClusterSummary:
    """DBSCAN cluster over ``entity_spectral_features``."""
    connection = get_connection(config)
    summary = ClusterSummary()

    cluster_eps = config["spectral"]["cluster_eps"]
    cluster_min_samples = config["spectral"]["cluster_min_samples"]
    try:
        min_entities = spectral_cluster_min_entities(config)
    except ConfigError as exc:
        raise ClusterError(str(exc)) from exc
    params = {
        "config_path": config_path,
        "cluster_eps": cluster_eps,
        "cluster_min_samples": cluster_min_samples,
        "cluster_min_entities": min_entities,
    }
    run_id = record_run_start(connection, stage="cluster", params=params)

    try:
        feature_rows = _load_entity_spectral_features(connection)
        cluster_run_id = stable_cluster_run_id(
            feature_rows,
            cluster_eps=float(cluster_eps),
            cluster_min_samples=int(cluster_min_samples),
            cluster_min_entities=min_entities,
        )
        summary.cluster_run_id = cluster_run_id
        params["cluster_run_id"] = cluster_run_id
        params["manifest"]["cluster_run_id"] = cluster_run_id
        if not feature_rows:
            params_with_summary = {
                **params,
                "summary": {**summary.as_dict(), "nothing_to_cluster": True},
            }
            connection.execute(
                """
                UPDATE pipeline_runs
                SET params_json = ?::JSON
                WHERE run_id = ?
                """,
                [json.dumps(params_with_summary), run_id],
            )
            record_run_finish(connection, run_id, "success")
            print("cluster summary:")
            print("  nothing to cluster")
            logger.info(
                "cluster: nothing to cluster (no entity_spectral_features)"
            )
            raise NothingToCluster(
                "nothing to cluster: no entity_spectral_features; "
                "run detect-spectral first or wait for sufficient history"
            )

        n_features = len(feature_rows)
        if n_features < min_entities:
            clear_entity_clusters_table(connection)
            params_with_summary = {
                **params,
                "summary": {
                    **summary.as_dict(),
                    "nothing_to_cluster": True,
                    "entities_available": n_features,
                    "cluster_min_entities": min_entities,
                },
            }
            connection.execute(
                """
                UPDATE pipeline_runs
                SET params_json = ?::JSON
                WHERE run_id = ?
                """,
                [json.dumps(params_with_summary), run_id],
            )
            record_run_finish(connection, run_id, "success")
            message = (
                f"nothing to cluster: only {n_features} entities (min {min_entities})"
            )
            print("cluster summary:")
            print(f"  {message}")
            logger.info("cluster: %s", message)
            raise NothingToCluster(message)

        assignments = cluster_entities(
            feature_rows,
            cluster_eps=float(cluster_eps),
            cluster_min_samples=int(cluster_min_samples),
            cluster_run_id=cluster_run_id,
        )

        clear_entity_clusters_table(connection)
        insert_entity_clusters(connection, assignments)

        summary.entities_clustered = len(assignments)
        summary.outliers = sum(1 for row in assignments if row.cluster_id == -1)

        params_with_summary = {**params, "summary": summary.as_dict()}
        connection.execute(
            """
            UPDATE pipeline_runs
            SET params_json = ?::JSON
            WHERE run_id = ?
            """,
            [json.dumps(params_with_summary), run_id],
        )
        record_run_finish(connection, run_id, "success")

        logger.info("cluster summary: %s", summary.as_dict())
        print("cluster summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except NothingToCluster:
        raise
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
