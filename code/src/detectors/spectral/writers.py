"""Parquet + DuckDB writers for Phase 6 spectral outputs."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pandas as pd

from src.db.parquet_shards import insert_from_readable_parquet
from src.detectors.spectral.baseline import SpectralBaseline
from src.detectors.spectral.clustering import EntityClusterAssignment
from src.detectors.spectral.features import EntitySpectralFeatures
from src.detectors.spectral.windowed import SpectralWindowScore
from src.hive_paths import hive_entity_dir


def spectral_scores_dir(config: dict[str, Any]) -> Path:
    return Path(config["paths"]["scores_dir"]) / "spectral"


def clear_spectral_scores_output(config: dict[str, Any]) -> Path:
    output_dir = spectral_scores_dir(config)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def write_entity_spectral_windows(
    scores_dir: Path,
    entity_id: str,
    rows: list[SpectralWindowScore],
) -> Path | None:
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
                "energy_z": row.energy_z,
                "shape_js_z": row.shape_js_z,
                "flagged": row.flagged,
                "dominant_period_hours": row.dominant_period_hours,
                "shape_top_bins": json.dumps(list(row.shape_top_bins)),
            }
        )
    frame = pd.DataFrame.from_records(records)
    frame.to_parquet(path, index=False)
    return path


def clear_spectral_window_scores_table(connection: Any) -> None:
    connection.execute("DELETE FROM spectral_window_scores")


def sync_spectral_window_scores_from_parquet(
    connection: Any,
    scores_dir: Path,
    *,
    run_id: str | None = None,
    config: dict[str, Any] | None = None,
) -> int:
    parquet_files = list(scores_dir.glob("entity_id=*/*.parquet"))
    if not parquet_files:
        return 0
    insert_from_readable_parquet(
        connection,
        parquet_files,
        """
        INSERT INTO spectral_window_scores (
            entity_id, window_start, window_end, energy_z, shape_js_z, flagged,
            dominant_period_hours, shape_top_bins
        )
        SELECT
            CAST(entity_id AS VARCHAR) AS entity_id,
            CAST(window_start AS TIMESTAMP) AS window_start,
            CAST(window_end AS TIMESTAMP) AS window_end,
            CAST(energy_z AS DOUBLE) AS energy_z,
            CAST(shape_js_z AS DOUBLE) AS shape_js_z,
            CAST(flagged AS BOOLEAN) AS flagged,
            CAST(dominant_period_hours AS DOUBLE) AS dominant_period_hours,
            CAST(shape_top_bins AS VARCHAR) AS shape_top_bins
        FROM {from_clause}
        """,
        run_id=run_id,
        stage="detect-spectral",
        config=config,
    )
    count = connection.execute("SELECT COUNT(*) FROM spectral_window_scores").fetchone()[0]
    return int(count)


def clear_spectral_baselines_table(connection: Any) -> None:
    connection.execute("DELETE FROM spectral_baselines")


def insert_spectral_baseline(connection: Any, baseline: SpectralBaseline) -> None:
    connection.execute(
        """
        INSERT INTO spectral_baselines (
            entity_id, computed_at, bucket_seconds, nperseg,
            freq_grid, psd, psd_norm
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            baseline.entity_id,
            baseline.computed_at,
            baseline.bucket_seconds,
            baseline.nperseg,
            baseline.freq_grid,
            baseline.psd,
            baseline.psd_norm,
        ],
    )


def clear_entity_spectral_features_table(connection: Any) -> None:
    connection.execute("DELETE FROM entity_spectral_features")


def insert_entity_spectral_features(
    connection: Any,
    features: EntitySpectralFeatures,
) -> None:
    connection.execute(
        """
        INSERT INTO entity_spectral_features (
            entity_id, dominant_period_hours, dominant_power_frac,
            spectral_entropy, total_power, computed_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            features.entity_id,
            features.dominant_period_hours,
            features.dominant_power_frac,
            features.spectral_entropy,
            features.total_power,
            features.computed_at,
        ],
    )


def clear_entity_clusters_table(connection: Any) -> None:
    connection.execute("DELETE FROM entity_clusters")


def insert_entity_clusters(
    connection: Any,
    rows: list[EntityClusterAssignment],
) -> None:
    for row in rows:
        connection.execute(
            """
            INSERT INTO entity_clusters (
                entity_id, cluster_run_id, cluster_id, computed_at
            )
            VALUES (?, ?, ?, ?)
            """,
            [row.entity_id, row.cluster_run_id, row.cluster_id, row.computed_at],
        )
