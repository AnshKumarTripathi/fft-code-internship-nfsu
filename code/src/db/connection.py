"""DuckDB warehouse connection helpers.

Phase 1 creates all §6 tables as native DuckDB tables via schema.sql
(CREATE TABLE IF NOT EXISTS). Later phases may add Parquet files and
CREATE OR REPLACE VIEW overlays without deleting this DDL file.

Phase 2 registers ``ingest_staging`` over ``parsed_dir/ingest_staging/*.parquet``
when those files exist; otherwise registration is a no-op.

Phase 3 keeps ``parsed_events`` as the native §6 table (FK-safe for
``correlation_edges``) and registers ``parsed_events_parquet`` over hive
Parquet under ``parsed_dir/events/``. Parse writes Parquet and syncs the table.

Phase 4 registers ``entity_bucket_counts_parquet`` over hive Parquet under
``timeseries_dir/entity_id=*/``. Bucket writes Parquet and syncs the native
``entity_bucket_counts`` table.

Phase 5 registers ``statistical_window_scores_parquet`` over hive Parquet under
``scores_dir/statistical/entity_id=*/``.

Phase 6 registers ``spectral_window_scores_parquet`` over hive Parquet under
``scores_dir/spectral/entity_id=*/``. Spectral baselines/features/clusters are
native DuckDB tables written by detect-spectral and cluster.

Phase 7 registers ``ml_window_scores_parquet`` over hive Parquet under
``scores_dir/ml/entity_id=*/``.

Phase 52 registers ``changepoint_window_scores_parquet`` over hive Parquet under
``scores_dir/changepoint/entity_id=*/``.
Phase 61 registers ``seasonal_window_scores_parquet`` over ``scores_dir/seasonal/``.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from src.config import ensure_data_directories
from src.db.parquet_shards import create_view_from_readable_parquet
from src.db.run_manifest import build_run_manifest
from src.db.writer_lock import WarehouseBusyError, WriterLock, writer_lock_path

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"
ALLOWED_FINISH_STATUSES = frozenset({"success", "failed"})

# Retries when a brief same-process config clash still surfaces (safety net).
_CONNECT_RETRIES = 12
_CONNECT_RETRY_BASE_S = 0.05


def get_connection(config: dict[str, Any]) -> duckdb.DuckDBPyConnection:
    """Open warehouse at paths.db_path, ensure dirs/schema, return connection.

    Acquires an exclusive writer lock so a second pipeline process fails with
    ``WarehouseBusyError`` instead of a raw DuckDB I/O error.
    """
    ensure_data_directories(config)
    db_path = Path(config["paths"]["db_path"])
    lock = WriterLock(writer_lock_path(db_path))
    lock.acquire()
    connection: duckdb.DuckDBPyConnection | None = None
    try:
        try:
            connection = _connect_with_retry(str(db_path))
        except Exception as exc:
            if _is_duckdb_lock_error(exc):
                raise WarehouseBusyError(
                    f"Warehouse is locked by another writer ({db_path}). "
                    "Wait for the running pipeline stage to finish."
                ) from exc
            raise
        apply_schema(connection, SCHEMA_PATH)
        apply_additive_columns(connection)
        register_parquet_views(connection, config)
        return _LockedConnection(connection, lock)
    except BaseException:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        lock.release()
        raise


def get_read_only_connection(config: dict[str, Any]) -> duckdb.DuckDBPyConnection:
    """Open warehouse for dashboard/API reads (no schema/view registration).

    Uses the **same** DuckDB access mode as ``get_connection`` (not
    ``read_only=True``). In-process Pipeline jobs open writers on a background
    thread; DuckDB rejects mixing ``read_only`` flags on one file in one
    process ("different configuration"). Shared default mode lets the UI poll
    while stages run. Callers must not write through this handle; exclusive
    writers still take ``WriterLock`` via ``get_connection``.

    Raises FileNotFoundError if the warehouse file does not exist.
    """
    db_path = Path(config["paths"]["db_path"])
    if not db_path.is_file():
        raise FileNotFoundError(
            f"Warehouse not found: {db_path}. "
            "Run the batch pipeline (e.g. run-all) before starting the dashboard."
        )
    return _connect_with_retry(str(db_path))


def _connect_with_retry(db_path: str) -> duckdb.DuckDBPyConnection:
    last_exc: BaseException | None = None
    for attempt in range(_CONNECT_RETRIES):
        try:
            return duckdb.connect(db_path)
        except Exception as exc:
            last_exc = exc
            if not _is_duckdb_config_conflict(exc) and not _is_duckdb_lock_error(exc):
                raise
            # Config conflict: retry. Lock from another process: also retry briefly
            # so a just-closed writer does not fail an immediate UI poll.
            if attempt + 1 >= _CONNECT_RETRIES:
                break
            time.sleep(_CONNECT_RETRY_BASE_S * (attempt + 1))
    assert last_exc is not None
    if _is_duckdb_config_conflict(last_exc) or _is_duckdb_lock_error(last_exc):
        raise WarehouseBusyError(
            f"Warehouse is busy ({db_path}). "
            "Wait for the running pipeline stage to finish."
        ) from last_exc
    raise last_exc


def _is_duckdb_config_conflict(exc: BaseException) -> bool:
    detail = str(exc).lower()
    return "different configuration" in detail


def _is_duckdb_lock_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    detail = str(exc).lower()
    return (
        name == "IOException"
        or "lock" in detail
        or "conflicting" in detail
        or _is_duckdb_config_conflict(exc)
    )


class _LockedConnection:
    """Proxy so ``close()`` releases the writer lock.

    DuckDB's ``close`` attribute is read-only on current builds, so we cannot
    monkey-patch the native connection.
    """

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        lock: WriterLock,
    ) -> None:
        object.__setattr__(self, "_connection", connection)
        object.__setattr__(self, "_lock", lock)
        object.__setattr__(self, "_closed", False)

    def close(self) -> None:
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        try:
            self._connection.close()
        finally:
            self._lock.release()

    def __enter__(self) -> _LockedConnection:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def apply_schema(
    connection: duckdb.DuckDBPyConnection,
    schema_path: str | Path,
) -> None:
    """Execute schema.sql idempotently (CREATE TABLE IF NOT EXISTS)."""
    sql = Path(schema_path).read_text(encoding="utf-8")
    connection.execute(sql)


def apply_additive_columns(connection: duckdb.DuckDBPyConnection) -> None:
    """Add R5 snapshot columns on warehouses created before those fields existed."""
    connection.execute(
        "ALTER TABLE parsed_events ADD COLUMN IF NOT EXISTS parser_snapshot_id VARCHAR"
    )
    connection.execute(
        "ALTER TABLE ml_window_scores ADD COLUMN IF NOT EXISTS model_snapshot_id VARCHAR"
    )
    connection.execute(
        "ALTER TABLE spectral_window_scores ADD COLUMN IF NOT EXISTS dominant_period_hours DOUBLE"
    )
    connection.execute(
        "ALTER TABLE spectral_window_scores ADD COLUMN IF NOT EXISTS shape_top_bins VARCHAR"
    )
    connection.execute(
        "ALTER TABLE ml_window_scores ADD COLUMN IF NOT EXISTS mad_z DOUBLE"
    )
    connection.execute(
        "ALTER TABLE ml_window_scores ADD COLUMN IF NOT EXISTS attribution_json VARCHAR"
    )


def register_parquet_views(
    connection: duckdb.DuckDBPyConnection,
    config: dict[str, Any],
) -> None:
    """Register Parquet globs as views when present; no-op on empty dirs.

    Phase 2: ``ingest_staging`` over ``parsed_dir/ingest_staging/*.parquet``.
    Phase 3: ``parsed_events_parquet`` over ``parsed_dir/events/**/*.parquet``.
    Phase 4: ``entity_bucket_counts_parquet`` over ``timeseries_dir/entity_id=*/*.parquet``.
    Phase 5: ``statistical_window_scores_parquet`` over ``scores_dir/statistical/entity_id=*/*.parquet``.
    Phase 6: ``spectral_window_scores_parquet`` over ``scores_dir/spectral/entity_id=*/*.parquet``.
    Phase 7: ``ml_window_scores_parquet`` over ``scores_dir/ml/entity_id=*/*.parquet``.
    Phase 52: ``changepoint_window_scores_parquet`` over ``scores_dir/changepoint/entity_id=*/*.parquet``.
    Phase 61: ``seasonal_window_scores_parquet`` over ``scores_dir/seasonal/entity_id=*/*.parquet``.
    Canonical §6 tables remain native (loaded by their stages).
    """
    parsed_dir = Path(config["paths"]["parsed_dir"])
    timeseries_dir = Path(config["paths"]["timeseries_dir"])
    scores_dir = Path(config["paths"]["scores_dir"])
    _register_ingest_staging_view(connection, parsed_dir)
    _register_parsed_events_parquet_view(connection, parsed_dir)
    _register_entity_bucket_counts_parquet_view(connection, timeseries_dir)
    _register_statistical_window_scores_parquet_view(connection, scores_dir)
    _register_spectral_window_scores_parquet_view(connection, scores_dir)
    _register_ml_window_scores_parquet_view(connection, scores_dir)
    _register_changepoint_window_scores_parquet_view(connection, scores_dir)
    _register_seasonal_window_scores_parquet_view(connection, scores_dir)


def _register_ingest_staging_view(
    connection: duckdb.DuckDBPyConnection,
    parsed_dir: Path,
) -> None:
    staging_dir = parsed_dir / "ingest_staging"
    parquet_files = list(staging_dir.glob("*.parquet")) if staging_dir.is_dir() else []
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "ingest_staging", sorted(parquet_files)
    )


def _register_parsed_events_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    parsed_dir: Path,
) -> None:
    events_dir = parsed_dir / "events"
    if not events_dir.is_dir():
        return
    event_files = list(events_dir.glob("**/*.parquet"))
    if not event_files:
        return
    create_view_from_readable_parquet(
        connection,
        "parsed_events_parquet",
        sorted(event_files),
        hive_partitioning=False,
    )


def _register_entity_bucket_counts_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    timeseries_dir: Path,
) -> None:
    if not timeseries_dir.is_dir():
        return
    parquet_files = list(timeseries_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "entity_bucket_counts_parquet", sorted(parquet_files)
    )


def _register_statistical_window_scores_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    scores_dir: Path,
) -> None:
    statistical_dir = scores_dir / "statistical"
    if not statistical_dir.is_dir():
        return
    parquet_files = list(statistical_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "statistical_window_scores_parquet", sorted(parquet_files)
    )


def _register_spectral_window_scores_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    scores_dir: Path,
) -> None:
    spectral_dir = scores_dir / "spectral"
    if not spectral_dir.is_dir():
        return
    parquet_files = list(spectral_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "spectral_window_scores_parquet", sorted(parquet_files)
    )


def _register_ml_window_scores_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    scores_dir: Path,
) -> None:
    ml_dir = scores_dir / "ml"
    if not ml_dir.is_dir():
        return
    parquet_files = list(ml_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "ml_window_scores_parquet", sorted(parquet_files)
    )


def _register_changepoint_window_scores_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    scores_dir: Path,
) -> None:
    changepoint_dir = scores_dir / "changepoint"
    if not changepoint_dir.is_dir():
        return
    parquet_files = list(changepoint_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "changepoint_window_scores_parquet", sorted(parquet_files)
    )


def _register_seasonal_window_scores_parquet_view(
    connection: duckdb.DuckDBPyConnection,
    scores_dir: Path,
) -> None:
    seasonal_dir = scores_dir / "seasonal"
    if not seasonal_dir.is_dir():
        return
    parquet_files = list(seasonal_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return
    create_view_from_readable_parquet(
        connection, "seasonal_window_scores_parquet", sorted(parquet_files)
    )


def record_run_start(
    connection: duckdb.DuckDBPyConnection,
    stage: str,
    params: dict[str, Any] | None = None,
) -> str:
    """Insert pipeline_runs row with status='running'; return run_id.

    Mutates ``params`` in place (when provided) by adding ``manifest`` so
    later summary UPDATEs that spread the same dict keep git/config hashes.
    """
    payload = params if params is not None else {}
    payload["manifest"] = build_run_manifest(config_path=payload.get("config_path"))
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)
    params_json = json.dumps(payload)
    connection.execute(
        """
        INSERT INTO pipeline_runs (run_id, stage, started_at, finished_at, status, params_json)
        VALUES (?, ?, ?, NULL, 'running', ?::JSON)
        """,
        [run_id, stage, started_at, params_json],
    )
    return run_id


def record_run_finish(
    connection: duckdb.DuckDBPyConnection,
    run_id: str,
    status: str,
) -> None:
    """Set finished_at and status for an existing pipeline_runs row."""
    if status not in ALLOWED_FINISH_STATUSES:
        raise ValueError(
            f"status must be one of {sorted(ALLOWED_FINISH_STATUSES)}, got {status!r}"
        )
    finished_at = datetime.now(timezone.utc)
    connection.execute(
        """
        UPDATE pipeline_runs
        SET finished_at = ?, status = ?
        WHERE run_id = ?
        """,
        [finished_at, status, run_id],
    )
