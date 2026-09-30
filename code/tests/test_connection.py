"""Tests for DuckDB connection helpers and pipeline_runs bookkeeping."""

from __future__ import annotations

from pathlib import Path

from src.db.connection import (
    get_connection,
    get_read_only_connection,
    record_run_finish,
    record_run_start,
)

EXPECTED_TABLES = {
    "entities",
    "templates",
    "parsed_events",
    "entity_bucket_counts",
    "spectral_baselines",
    "entity_spectral_features",
    "entity_clusters",
    "spectral_window_scores",
    "statistical_window_scores",
    "ml_window_scores",
    "changepoint_window_scores",
    "seasonal_window_scores",
    "anomaly_events",
    "correlation_edges",
    "incidents",
    "pipeline_runs",
    "ingest_source_files",
    "pipeline_errors",
    "analyst_actions",
}


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


def test_get_connection_creates_db_and_tables(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    connection = get_connection(config)
    try:
        assert Path(config["paths"]["db_path"]).is_file()
        rows = connection.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
        table_names = {row[0] for row in rows}
        assert EXPECTED_TABLES.issubset(table_names)
        parsed_cols = {
            str(row[0]).lower()
            for row in connection.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'main' AND table_name = 'parsed_events'"
            ).fetchall()
        }
        ml_cols = {
            str(row[0]).lower()
            for row in connection.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'main' AND table_name = 'ml_window_scores'"
            ).fetchall()
        }
        assert "parser_snapshot_id" in parsed_cols
        assert "model_snapshot_id" in ml_cols
        assert "mad_z" in ml_cols
        assert "attribution_json" in ml_cols
        spectral_cols = {
            str(row[0]).lower()
            for row in connection.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'main' AND table_name = 'spectral_window_scores'"
            ).fetchall()
        }
        assert "dominant_period_hours" in spectral_cols
        assert "shape_top_bins" in spectral_cols
    finally:
        connection.close()


def test_pipeline_runs_start_finish_round_trip(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    connection = get_connection(config)
    try:
        run_id = record_run_start(
            connection,
            stage="foundation-check",
            params={"config_path": "test"},
        )
        assert run_id

        row = connection.execute(
            "SELECT stage, status, finished_at FROM pipeline_runs WHERE run_id = ?",
            [run_id],
        ).fetchone()
        assert row is not None
        assert row[0] == "foundation-check"
        assert row[1] == "running"
        assert row[2] is None

        record_run_finish(connection, run_id, status="success")
        row = connection.execute(
            "SELECT status, finished_at FROM pipeline_runs WHERE run_id = ?",
            [run_id],
        ).fetchone()
        assert row is not None
        assert row[0] == "success"
        assert row[1] is not None
    finally:
        connection.close()


def test_schema_apply_is_idempotent(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    first = get_connection(config)
    first.close()
    second = get_connection(config)
    try:
        count = second.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = 'main' AND table_name = 'entities'"
        ).fetchone()[0]
        assert count == 1
    finally:
        second.close()


def test_get_read_only_connection_opens_existing(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    writer = get_connection(config)
    writer.close()
    reader = get_read_only_connection(config)
    try:
        assert reader.execute("SELECT 1").fetchone()[0] == 1
    finally:
        reader.close()


def test_get_read_only_connection_missing_file(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    try:
        get_read_only_connection(config)
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError as exc:
        assert "Warehouse not found" in str(exc)
