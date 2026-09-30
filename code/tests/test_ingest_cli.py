"""End-to-end ingest CLI / orchestration tests."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.db.connection import get_connection
from src.ingestion.persist import ingest_staging_dir, run_ingest

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
    shutil.copy(FIXTURE, raw / "auth.log")
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
    }


def test_run_ingest_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    summary = run_ingest(config, config_path="test")

    assert summary.files == 1
    assert summary.lines_read > 0
    assert summary.lines_kept > 0
    assert summary.lines_deduped >= 1  # fixture includes a duplicate line
    assert summary.entities_upserted > 0
    assert summary.staging_parts >= 1

    staging = ingest_staging_dir(config)
    assert any(staging.glob("*.parquet"))

    connection = get_connection(config)
    try:
        entity_count = connection.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        assert entity_count > 0

        types = connection.execute(
            "SELECT DISTINCT entity_type FROM entities"
        ).fetchall()
        assert all(row[0] in {"user", "host", "ip", "service"} for row in types)

        run_row = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'ingest'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row is not None
        assert run_row[0] == "success"

        staging_count = connection.execute(
            "SELECT COUNT(*) FROM ingest_staging"
        ).fetchone()[0]
        assert staging_count == summary.lines_kept
    finally:
        connection.close()


def test_ingest_does_not_modify_raw(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    raw_file = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    before = raw_file.read_bytes()
    run_ingest(config, config_path="test")
    assert raw_file.read_bytes() == before
