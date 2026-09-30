"""Parquet + DuckDB writers for Phase 7 / 53 ml_window_scores."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.detectors.ml.isolation_forest import MlWindowScore
from src.hive_paths import hive_entity_dir


def ml_scores_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["scores_dir"]) / "ml"


def clear_ml_scores_output(config: dict[str, Any]) -> Path:
    """Delete and recreate ``scores_dir/ml/`` (full refresh)."""
    output_dir = ml_scores_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_ml_scores(
    scores_dir: Path,
    entity_id: str,
    rows: list[MlWindowScore],
) -> Path | None:
    """Write one hive partition per entity; return path or None if empty."""
    if not rows:
        return None

    partition_dir = hive_entity_dir(scores_dir, entity_id)
    partition_dir.mkdir(parents=True, exist_ok=True)
    path = partition_dir / "part-00000.parquet"

    records = []
    for row in rows:
        attribution_json = None
        if row.attribution:
            attribution_json = json.dumps(row.attribution)
        records.append(
            {
                "entity_id": entity_id,
                "window_start": row.window_start.isoformat(),
                "window_end": row.window_end.isoformat(),
                "model_score": row.model_score,
                "flagged": row.flagged,
                "model_snapshot_id": row.model_snapshot_id,
                "mad_z": row.mad_z,
                "attribution_json": attribution_json,
            }
        )
    frame = pd.DataFrame.from_records(records)
    # Force VARCHAR in Parquet even when every value is null — otherwise a
    # null-typed shard + a string shard fails DuckDB multi-file reads.
    frame["attribution_json"] = frame["attribution_json"].astype("string")
    frame.to_parquet(path, index=False)
    return path


def clear_ml_window_scores_table(connection: Any) -> None:
    connection.execute("DELETE FROM ml_window_scores")


def sync_ml_window_scores_from_parquet(
    connection: Any,
    scores_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    """Load §6 columns from Parquet into native ``ml_window_scores``."""
    parquet_files = list(scores_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO ml_window_scores (
            entity_id, window_start, window_end, model_score, flagged,
            model_snapshot_id, mad_z, attribution_json
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(window_start AS TIMESTAMP) AS window_start,
            CAST(window_end AS TIMESTAMP) AS window_end,
            CAST(model_score AS DOUBLE) AS model_score,
            CAST(flagged AS BOOLEAN) AS flagged,
            CAST(model_snapshot_id AS VARCHAR) AS model_snapshot_id,
            CAST(mad_z AS DOUBLE) AS mad_z,
            CAST(attribution_json AS VARCHAR) AS attribution_json
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="detect-ml",
        config=config,
    )
    count = connection.execute("SELECT COUNT(*) FROM ml_window_scores").fetchone()[0]
    return int(count)
