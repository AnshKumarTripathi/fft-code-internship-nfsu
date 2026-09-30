"""Parquet + DuckDB writers for Phase 61 seasonal_window_scores."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.detectors.seasonal.residual import SeasonalWindowScore
from src.hive_paths import hive_entity_dir


def seasonal_scores_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["scores_dir"]) / "seasonal"


def clear_seasonal_scores_output(config: dict[str, Any]) -> Path:
    """Delete and recreate ``scores_dir/seasonal/`` (full refresh)."""
    output_dir = seasonal_scores_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_seasonal_scores(
    scores_dir: Path,
    entity_id: str,
    rows: list[SeasonalWindowScore],
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
                "residual_z": row.residual_z,
                "residual": row.residual,
                "seasonal_level": row.seasonal_level,
                "flagged": row.flagged,
                "direction": row.direction,
            }
        )
    frame = pd.DataFrame.from_records(records)
    frame.to_parquet(path, index=False)
    return path


def clear_seasonal_window_scores_table(connection: Any) -> None:
    connection.execute("DELETE FROM seasonal_window_scores")


def sync_seasonal_window_scores_from_parquet(
    connection: Any,
    scores_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    """Load additive columns from Parquet into native ``seasonal_window_scores``."""
    parquet_files = list(scores_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO seasonal_window_scores (
            entity_id, window_start, window_end, residual_z, residual,
            seasonal_level, flagged, direction
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(window_start AS TIMESTAMP) AS window_start,
            CAST(window_end AS TIMESTAMP) AS window_end,
            CAST(residual_z AS DOUBLE) AS residual_z,
            CAST(residual AS DOUBLE) AS residual,
            CAST(seasonal_level AS DOUBLE) AS seasonal_level,
            CAST(flagged AS BOOLEAN) AS flagged,
            CAST(direction AS VARCHAR) AS direction
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="detect-seasonal",
        config=config,
    )
    count = connection.execute(
        "SELECT COUNT(*) FROM seasonal_window_scores"
    ).fetchone()[0]
    return int(count)
