"""Parquet + DuckDB writers for Phase 4 entity_bucket_counts."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.hive_paths import hive_entity_dir
from src.timeseries.bucketing import BucketCountRow

logger = logging.getLogger(__name__)


def timeseries_output_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["timeseries_dir"])


def clear_timeseries_output(config: dict[str, Any]) -> Path:
    """Delete and recreate ``timeseries_dir`` (full refresh)."""
    output_dir = timeseries_output_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_buckets(
    timeseries_dir: Path,
    entity_id: str,
    rows: list[BucketCountRow],
) -> Path | None:
    """Write one hive partition per entity; return path or None if empty."""
    if not rows:
        return None

    partition_dir = hive_entity_dir(timeseries_dir, entity_id)
    partition_dir.mkdir(parents=True, exist_ok=True)
    path = partition_dir / "part-00000.parquet"

    records = []
    for row in rows:
        records.append(
            {
                "entity_id": entity_id,
                "bucket_start": row.bucket_start.isoformat(),
                "bucket_seconds": row.bucket_seconds,
                "event_count": row.event_count,
            }
        )
    frame = pd.DataFrame.from_records(records)
    frame.to_parquet(path, index=False)
    return path


def clear_entity_bucket_counts_table(connection: Any) -> None:
    connection.execute("DELETE FROM entity_bucket_counts")


def sync_entity_bucket_counts_from_parquet(
    connection: Any,
    timeseries_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    """Load §6 columns from Parquet into native ``entity_bucket_counts``.

    Uses the ``entity_id`` column written into each file (not the sanitized
    hive folder name) so Windows-safe paths stay correct in the warehouse.
    Corrupt shards are skipped (R6).
    """
    parquet_files = list(timeseries_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO entity_bucket_counts (
            entity_id, bucket_start, bucket_seconds, event_count
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(bucket_start AS TIMESTAMP) AS bucket_start,
            CAST(bucket_seconds AS INTEGER) AS bucket_seconds,
            CAST(event_count AS DOUBLE) AS event_count
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="bucket",
        config=config,
    )
    count = connection.execute("SELECT COUNT(*) FROM entity_bucket_counts").fetchone()[0]
    return int(count)
