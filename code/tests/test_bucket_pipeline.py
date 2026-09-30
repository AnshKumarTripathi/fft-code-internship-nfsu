"""End-to-end bucket pipeline tests (ingest → parse → bucket)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse
from src.timeseries.persist import BucketError, run_bucket
from src.timeseries.writers import timeseries_output_dir

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
    return {
        "paths": {
            "raw_log_dir": str(raw),
            "parsed_dir": str(data_root / "parsed"),
            "timeseries_dir": str(data_root / "timeseries"),
            "baseline_dir": str(data_root / "baselines"),
            "scores_dir": str(data_root / "scores"),
            "report_dir": str(data_root / "reports"),
            "db_path": str(data_root / "warehouse.duckdb"),
        },
        "bucketing": {"bucket_seconds": 600},
        "statistical": {"window_buckets": 6, "z_threshold": 4.0},
        "spectral": {
            "window_hours": 72,
            "step_fraction": 0.333,
            "baseline_max_nperseg": 1440,
            "z_threshold": 4.0,
            "cluster_eps": 1.2,
            "cluster_min_samples": 2,
        },
        "ml": {
            "model_type": "isolation_forest",
            "onnx_model_path": None,
            "contamination": 0.02,
        },
        "correlation": {
            "session_gap_minutes": 30,
            "same_ip_link": True,
            "same_host_link": True,
        },
        "reporting": {
            "template_path": "src/reporting/templates/incident_report.md.j2",
            "use_llm_narrative": False,
            "llm_model": "qwen3-coder:30b",
        },
        "orchestration": {"parallel_backend": "dask", "n_workers": 8},
        "_config_path": str(config_dir / "pipeline.yaml"),
    }


def test_bucket_requires_parsed_events(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    with pytest.raises(BucketError, match="run parse first"):
        run_bucket(config, config_path=config_path)


def test_run_bucket_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    summary = run_bucket(config, config_path=config_path)

    assert summary.entities_processed > 0
    assert summary.total_buckets_written > 0
    assert summary.total_events_bucketed > 0
    assert summary.parquet_entities > 0

    timeseries_dir = timeseries_output_dir(config)
    partitions = list(timeseries_dir.glob("entity_id=*"))
    assert partitions
    assert any(timeseries_dir.glob("entity_id=*/*.parquet"))

    connection = get_connection(config)
    try:
        bucket_row_count = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        assert bucket_row_count > 0
        assert bucket_row_count == summary.total_buckets_written

        sample_entity = connection.execute(
            "SELECT entity_id FROM entity_bucket_counts LIMIT 1"
        ).fetchone()[0]

        summed = connection.execute(
            """
            SELECT SUM(event_count)
            FROM entity_bucket_counts
            WHERE entity_id = ?
            """,
            [sample_entity],
        ).fetchone()[0]

        parsed_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM parsed_events
            WHERE entity_id = ?
            """,
            [sample_entity],
        ).fetchone()[0]

        assert float(summed) == float(parsed_count)

        run_row = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'bucket'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
    finally:
        connection.close()
