"""Parquet + DuckDB writers for Phase 52 changepoint_window_scores."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.detectors.changepoint.cusum import ChangepointWindowScore
from src.hive_paths import hive_entity_dir


def changepoint_scores_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["scores_dir"]) / "changepoint"


def clear_changepoint_scores_output(config: dict[str, Any]) -> Path:
    """Delete and recreate ``scores_dir/changepoint/`` (full refresh)."""
    output_dir = changepoint_scores_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_changepoint_scores(
    scores_dir: Path,
    entity_id: str,
    rows: list[ChangepointWindowScore],
) -> Path | None:
    """Write one hive partition per entity; return path or None if empty."""
    if not rows:
        return None

    partition_dir = hive_entity_dir(scores_dir, entity_id)
    partition_dir.mkdir(parents=True, exist_ok=True)
    path = partition_dir / "part-00000.parquet"

    records = []
    for row in rows:
        records.append(
            {
                "entity_id": entity_id,
                "window_start": row.window_start.isoformat(),
                "window_end": row.window_end.isoformat(),
                "cusum_high": row.cusum_high,
                "cusum_low": row.cusum_low,
                "flagged": row.flagged,
                "direction": row.direction,
            }
        )
    frame = pd.DataFrame.from_records(records)
    frame.to_parquet(path, index=False)
    return path


def clear_changepoint_window_scores_table(connection: Any) -> None:
    connection.execute("DELETE FROM changepoint_window_scores")


def sync_changepoint_window_scores_from_parquet(
    connection: Any,
    scores_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    """Load additive columns from Parquet into native ``changepoint_window_scores``."""
    parquet_files = list(scores_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO changepoint_window_scores (
            entity_id, window_start, window_end, cusum_high, cusum_low,
            flagged, direction
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(window_start AS TIMESTAMP) AS window_start,
            CAST(window_end AS TIMESTAMP) AS window_end,
            CAST(cusum_high AS DOUBLE) AS cusum_high,
            CAST(cusum_low AS DOUBLE) AS cusum_low,
            CAST(flagged AS BOOLEAN) AS flagged,
            CAST(direction AS VARCHAR) AS direction
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="detect-changepoint",
        config=config,
    )
    count = connection.execute(
        "SELECT COUNT(*) FROM changepoint_window_scores"
    ).fetchone()[0]
    return int(count)
