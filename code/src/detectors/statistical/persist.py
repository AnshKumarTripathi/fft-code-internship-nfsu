"""Orchestrate Phase 5 detect-statistical: buckets → window scores."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.db.connection import (
    get_connection,
    record_run_finish,
    record_run_start,
    register_parquet_views,
)
from src.detectors.statistical.rate_checks import StatisticalWindowScore, score_rate_windows
from src.detectors.statistical.writers import (
    clear_statistical_scores_output,
    clear_statistical_window_scores_table,
    statistical_scores_dir,
    sync_statistical_window_scores_from_parquet,
    write_entity_statistical_scores,
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
class StatisticalSummary:
    entities_scored: int = 0
    entities_skipped_insufficient_history: int = 0
    entities_skipped_empty: int = 0
    entities_failed: int = 0
    windows_total: int = 0
    windows_flagged: int = 0
    max_rate_z: float = 0.0
    n_workers_used: int = 1
    parallel_backend: str = "none"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class StatisticalEntityWork:
    entity_id: str
    bucket_starts: tuple[datetime, ...]
    event_counts: tuple[float, ...]
    bucket_seconds: int
    window_buckets: int
    z_threshold: float


@dataclass(frozen=True)
class StatisticalEntityResult:
    entity_id: str
    rows: tuple[StatisticalWindowScore, ...]
    skip_reason: str | None


class StatisticalError(Exception):
    """Raised when detect-statistical cannot proceed."""


def _validate_statistical_config(config: dict[str, Any]) -> tuple[int, float, int]:
    window_buckets = config["statistical"]["window_buckets"]
    z_threshold = config["statistical"]["z_threshold"]
    bucket_seconds = config["bucketing"]["bucket_seconds"]

    if not isinstance(window_buckets, int) or window_buckets <= 0:
        raise StatisticalError(
            f"statistical.window_buckets must be a positive integer, got {window_buckets!r}"
        )
    if not isinstance(bucket_seconds, int) or bucket_seconds <= 0:
        raise StatisticalError(
            f"bucketing.bucket_seconds must be a positive integer, got {bucket_seconds!r}"
        )
    if not isinstance(z_threshold, (int, float)):
        raise StatisticalError(
            f"statistical.z_threshold must be numeric, got {z_threshold!r}"
        )
    return window_buckets, float(z_threshold), bucket_seconds


def score_entity_windows(work: StatisticalEntityWork) -> StatisticalEntityResult:
    """Compute statistical windows for one entity (pickleable worker)."""
    if not work.bucket_starts:
        return StatisticalEntityResult(work.entity_id, (), "empty")
    rows = score_rate_windows(
        work.bucket_starts,
        work.event_counts,
        work.bucket_seconds,
        entity_id=work.entity_id,
        window_buckets=work.window_buckets,
        z_threshold=work.z_threshold,
    )
    if not rows:
        reason = (
            "insufficient_history"
            if len(work.event_counts) >= work.window_buckets
            else "empty"
        )
        return StatisticalEntityResult(work.entity_id, (), reason)
    return StatisticalEntityResult(work.entity_id, tuple(rows), None)


def _collect_entity_work(
    connection: Any,
    window_buckets: int,
    z_threshold: float,
    *,
    analysis_window: Any = None,
) -> list[StatisticalEntityWork]:
    sql, sql_params = bucket_series_sql(analysis_window)
    relation = execute_query(connection, sql, sql_params)
    columns = [desc[0] for desc in relation.description]
    work_items: list[StatisticalEntityWork] = []
    current_entity: str | None = None
    current_starts: list[datetime] = []
    current_counts: list[float] = []
    entity_bucket_seconds: int | None = None

    def flush() -> None:
        nonlocal current_entity, current_starts, current_counts, entity_bucket_seconds
        if current_entity is None or entity_bucket_seconds is None:
            return
        work_items.append(
            StatisticalEntityWork(
                entity_id=current_entity,
                bucket_starts=tuple(current_starts),
                event_counts=tuple(current_counts),
                bucket_seconds=entity_bucket_seconds,
                window_buckets=window_buckets,
                z_threshold=z_threshold,
            )
        )
        current_starts = []
        current_counts = []
        entity_bucket_seconds = None

    while True:
        batch = relation.fetchmany(10_000)
        if not batch and current_entity is None:
            break
        for values in batch:
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
        if not batch:
            flush()
            break
    return work_items


def _apply_statistical_result(
    result: StatisticalEntityResult | Exception,
    *,
    scores_dir: Path,
    summary: StatisticalSummary,
) -> None:
    if isinstance(result, Exception):
        summary.entities_failed += 1
        logger.error("detect-statistical entity failed: %s", repr(result))
        return
    if result.skip_reason == "empty":
        summary.entities_skipped_empty += 1
        return
    if result.skip_reason == "insufficient_history":
        summary.entities_skipped_insufficient_history += 1
        return
    rows = list(result.rows)
    path = write_entity_statistical_scores(scores_dir, result.entity_id, rows)
    if path is None:
        summary.entities_skipped_empty += 1
        return
    summary.entities_scored += 1
    summary.windows_total += len(rows)
    summary.windows_flagged += sum(1 for row in rows if row.flagged)
    entity_max_z = max(row.rate_z for row in rows)
    if entity_max_z > summary.max_rate_z:
        summary.max_rate_z = entity_max_z


def run_detect_statistical(
    config: dict[str, Any],
    *,
    config_path: str | None = None,
) -> StatisticalSummary:
    """Score sliding-window rates from ``entity_bucket_counts``."""
    connection = get_connection(config)
    summary = StatisticalSummary()
    window_buckets, z_threshold, bucket_seconds = _validate_statistical_config(config)
    scores_dir = statistical_scores_dir(config)
    backend = resolve_backend(config)
    params = {
        "config_path": config_path,
        "scores_dir": str(scores_dir),
        "window_buckets": window_buckets,
        "z_threshold": z_threshold,
        "bucket_seconds": bucket_seconds,
        "parallel_backend": backend,
    }
    analysis_window = resolve_analysis_window(config, connection, source="buckets")
    attach_analysis_window_params(params, analysis_window)
    run_id = record_run_start(connection, stage="detect-statistical", params=params)

    try:
        bucket_count = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        if int(bucket_count) == 0:
            raise StatisticalError(
                "No entity_bucket_counts found; run bucket first"
            )

        clear_statistical_scores_output(config)
        clear_statistical_window_scores_table(connection)

        work_items = _collect_entity_work(
            connection,
            window_buckets,
            z_threshold,
            analysis_window=analysis_window,
        )
        n_workers = resolve_worker_count(config, len(work_items))
        summary.n_workers_used = n_workers
        summary.parallel_backend = backend
        params["n_workers_used"] = n_workers

        results = map_entities(
            score_entity_windows,
            work_items,
            backend=backend,
            n_workers=n_workers,
        )
        for result, work in zip(results, work_items, strict=True):
            if isinstance(result, Exception):
                logger.error(
                    "detect-statistical failed for entity_id=%s: %r",
                    work.entity_id,
                    result,
                )
            _apply_statistical_result(result, scores_dir=scores_dir, summary=summary)

        if summary.entities_scored > 0:
            sync_statistical_window_scores_from_parquet(
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
            raise StatisticalError(
                f"detect-statistical failed for {summary.entities_failed} entit"
                f"{'y' if summary.entities_failed == 1 else 'ies'}"
            )
        record_run_finish(connection, run_id, "success")

        logger.info("detect-statistical summary: %s", summary.as_dict())
        print("detect-statistical summary:")
        for key, value in summary.as_dict().items():
            print(f"  {key}: {value}")
        return summary
    except Exception:
        record_run_finish(connection, run_id, "failed")
        raise
    finally:
        connection.close()
