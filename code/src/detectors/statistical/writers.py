"""Parquet + DuckDB writers for Phase 5 statistical_window_scores."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.detectors.statistical.rate_checks import StatisticalWindowScore
from src.hive_paths import hive_entity_dir


def statistical_scores_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["scores_dir"]) / "statistical"


def clear_statistical_scores_output(config: dict[str, Any]) -> Path:
    """Delete and recreate ``scores_dir/statistical/`` (full refresh)."""
    output_dir = statistical_scores_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_statistical_scores(
    scores_dir: Path,
    entity_id: str,
    rows: list[StatisticalWindowScore],
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
                "rate_z": row.rate_z,
                "flagged": row.flagged,
            }
        )
    frame = pd.DataFrame.from_records(records)
    frame.to_parquet(path, index=False)
    return path


def clear_statistical_window_scores_table(connection: Any) -> None:
    connection.execute("DELETE FROM statistical_window_scores")


def sync_statistical_window_scores_from_parquet(
    connection: Any,
    scores_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    """Load §6 columns from Parquet into native ``statistical_window_scores``."""
    parquet_files = list(scores_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO statistical_window_scores (
            entity_id, window_start, window_end, rate_z, flagged
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(window_start AS TIMESTAMP) AS window_start,
            CAST(window_end AS TIMESTAMP) AS window_end,
            CAST(rate_z AS DOUBLE) AS rate_z,
            CAST(flagged AS BOOLEAN) AS flagged
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="detect-statistical",
        config=config,
    )
    count = connection.execute(
        "SELECT COUNT(*) FROM statistical_window_scores"
    ).fetchone()[0]
    return int(count)
