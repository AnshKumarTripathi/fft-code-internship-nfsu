"""Parquet multi-file schema reconciliation (R6 / detect-ml attribution_json)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

from src.db.connection import get_connection
from src.detectors.ml.isolation_forest import MlWindowScore
from src.detectors.ml.writers import (
    sync_ml_window_scores_from_parquet,
    write_entity_ml_scores,
)
from src.hive_paths import hive_entity_dir


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    return {
        "paths": {
            "raw_log_dir": str(data_root / "raw"),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        }
    }


def _row(*, attribution: dict | None = None) -> MlWindowScore:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 1, 1, 1, tzinfo=timezone.utc)
    return MlWindowScore(
        entity_id="203.0.113.50",
        window_start=start,
        window_end=end,
        model_score=0.5,
        flagged=False,
        model_snapshot_id="snap-1",
        mad_z=0.1,
        attribution=attribution,
    )


def test_write_entity_ml_scores_keeps_attribution_json_string_when_all_null(
    tmp_path: Path,
) -> None:
    scores_dir = tmp_path / "ml"
    scores_dir.mkdir()
    path = write_entity_ml_scores(scores_dir, "203.0.113.50", [_row()])
    assert path is not None
    schema = pq.read_schema(path)
    field = schema.field("attribution_json")
    assert str(field.type) in {"string", "large_string"}


def test_sync_ml_scores_mixed_null_and_string_attribution_json(
    tmp_path: Path,
) -> None:
    """Stale null-typed shards + VARCHAR shards must still load (union_by_name)."""
    config = _temp_config(tmp_path)
    connection = get_connection(config)
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type) VALUES
            ('203.0.113.50', 'src_ip'),
            ('203.0.113.51', 'src_ip')
        """
    )
    scores_dir = Path(config["paths"]["scores_dir"]) / "ml"
    scores_dir.mkdir(parents=True)

    start = "2024-01-01T00:00:00+00:00"
    end = "2024-01-01T01:00:00+00:00"
    base = {
        "window_start": [start],
        "window_end": [end],
        "model_score": [0.2],
        "flagged": [False],
        "model_snapshot_id": ["snap"],
        "mad_z": [0.0],
    }

    null_dir = hive_entity_dir(scores_dir, "203.0.113.50")
    null_dir.mkdir(parents=True)
    null_frame = pd.DataFrame(
        {**base, "entity_id": ["203.0.113.50"], "attribution_json": [None]}
    )
    # Object column of all-None → Parquet NULL type (the pre-fix failure mode).
    null_frame.to_parquet(null_dir / "part-00000.parquet", index=False)

    str_dir = hive_entity_dir(scores_dir, "203.0.113.51")
    str_dir.mkdir(parents=True)
    str_frame = pd.DataFrame(
        {
            **base,
            "entity_id": ["203.0.113.51"],
            "attribution_json": ['{"top_templates":[]}'],
        }
    )
    str_frame["attribution_json"] = str_frame["attribution_json"].astype("string")
    str_frame.to_parquet(str_dir / "part-00000.parquet", index=False)

    try:
        count = sync_ml_window_scores_from_parquet(
            connection, scores_dir, config=config
        )
        assert count == 2
        rows = connection.execute(
            "SELECT entity_id, attribution_json FROM ml_window_scores "
            "ORDER BY entity_id"
        ).fetchall()
        assert rows[0][0] == "203.0.113.50"
        assert rows[0][1] is None
        assert rows[1][0] == "203.0.113.51"
        assert rows[1][1] is not None
    finally:
        connection.close()
