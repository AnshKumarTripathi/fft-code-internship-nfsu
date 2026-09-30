"""End-to-end detect-ml pipeline tests."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.detectors.ml.onnx_scorer import ModelNotConfiguredError
from src.detectors.ml.persist import MlError, run_detect_ml
from src.detectors.ml.writers import ml_scores_dir
from src.ingestion.persist import run_ingest
from src.parsing.persist import run_parse

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
            "min_windows_to_fit": 5,
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


def _seed_dense_parsed_events(config: dict, *, n_windows: int = 12) -> None:
    """Insert enough same-hour events so ML windows pass MIN_EVENTS."""
    connection = get_connection(config)
    try:
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('mltest', 'user', ?, ?)
            ON CONFLICT (entity_id) DO NOTHING
            """,
            [
                datetime(2024, 1, 1, tzinfo=timezone.utc),
                datetime(2024, 1, 2, tzinfo=timezone.utc),
            ],
        )
        for tid in ("t_a", "t_b", "t_rare"):
            connection.execute(
                """
                INSERT INTO templates (
                    template_id, template_string, first_seen, last_seen, occurrence_count
                )
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT (template_id) DO NOTHING
                """,
                [
                    tid,
                    f"template {tid}",
                    datetime(2024, 1, 1, tzinfo=timezone.utc),
                    datetime(2024, 1, 1, tzinfo=timezone.utc),
                ],
            )

        next_id = connection.execute(
            "SELECT COALESCE(MAX(event_id), 0) + 1 FROM parsed_events"
        ).fetchone()[0]
        event_id = int(next_id)
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        for w in range(n_windows):
            window_start = start + timedelta(hours=w)
            templates = ["t_a", "t_b"] * 5
            if w == n_windows - 1:
                templates = ["t_rare"] * 10
            for i, tid in enumerate(templates):
                ts = window_start + timedelta(seconds=i * 10)
                connection.execute(
                    """
                    INSERT INTO parsed_events (
                        event_id, entity_id, template_id, event_timestamp,
                        log_source, raw_fields, ingested_at
                    )
                    VALUES (?, 'mltest', ?, ?, 'ssh', '{}'::JSON, ?)
                    """,
                    [event_id, tid, ts, ts],
                )
                event_id += 1
    finally:
        connection.close()


def test_detect_ml_requires_parsed_events(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    with pytest.raises(MlError, match="run parse first"):
        run_detect_ml(config, config_path=config_path)


def test_run_detect_ml_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_dense_parsed_events(config)

    summary = run_detect_ml(config, config_path=config_path)

    assert summary.windows_total > 0
    assert summary.entities_scored >= 1

    scores_dir = ml_scores_dir(config)
    assert list(scores_dir.glob("entity_id=*/*.parquet"))

    connection = get_connection(config)
    try:
        score_count = connection.execute(
            "SELECT COUNT(*) FROM ml_window_scores"
        ).fetchone()[0]
        assert score_count == summary.windows_total

        cols = connection.execute(
            """
            SELECT entity_id, window_start, window_end, model_score, flagged
            FROM ml_window_scores
            LIMIT 1
            """
        ).fetchone()
        assert cols is not None

        run_row = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'detect-ml'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
    finally:
        connection.close()


def test_onnx_without_path_raises(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["ml"]["model_type"] = "onnx"
    config["ml"]["onnx_model_path"] = None

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_dense_parsed_events(config)

    with pytest.raises(ModelNotConfiguredError, match="onnx_model_path"):
        run_detect_ml(config, config_path=config_path)


def test_run_detect_ml_autoencoder_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["ml"]["model_type"] = "autoencoder"
    config["ml"]["ae_hidden_dims"] = [8, 2, 8]
    config["ml"]["ae_max_iter"] = 50

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_dense_parsed_events(config)

    summary = run_detect_ml(config, config_path=config_path)
    assert summary.model_type == "autoencoder"
    assert summary.windows_total > 0
    assert summary.model_snapshot_id

    connection = get_connection(config)
    try:
        score_count = connection.execute(
            "SELECT COUNT(*) FROM ml_window_scores"
        ).fetchone()[0]
        assert score_count == summary.windows_total
        # reuse_snapshot round-trip
        config["ml"]["mode"] = "reuse_snapshot"
        config["ml"]["snapshot_id"] = summary.model_snapshot_id
    finally:
        connection.close()

    reused = run_detect_ml(config, config_path=config_path)
    assert reused.windows_total == summary.windows_total
    assert reused.model_snapshot_id == summary.model_snapshot_id


def test_run_detect_ml_ensemble_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["ml"]["ensemble"] = {
        "enabled": True,
        "models": ["isolation_forest", "autoencoder"],
        "fusion": "majority",
    }
    config["ml"]["ae_hidden_dims"] = [8, 2, 8]
    config["ml"]["ae_max_iter"] = 50

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_dense_parsed_events(config)

    summary = run_detect_ml(config, config_path=config_path)
    assert summary.model_type == "ensemble"
    assert summary.ensemble_enabled is True
    assert summary.ensemble_fusion == "majority"
    assert summary.windows_total > 0
    assert summary.model_snapshot_id

    connection = get_connection(config)
    try:
        score_count = connection.execute(
            "SELECT COUNT(*) FROM ml_window_scores"
        ).fetchone()[0]
        assert score_count == summary.windows_total
        attribution = connection.execute(
            """
            SELECT attribution_json FROM ml_window_scores
            WHERE attribution_json IS NOT NULL
            LIMIT 1
            """
        ).fetchone()
        assert attribution is not None
        import json

        payload = json.loads(attribution[0])
        assert "ensemble" in payload
        assert "votes" in payload["ensemble"]
    finally:
        connection.close()


def test_run_detect_ml_onnx_no_if_fallthrough(tmp_path: Path) -> None:
    """ONNX with a missing sidecar must fail closed — never score via IF."""
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    fake = tmp_path / "fake.onnx"
    fake.write_bytes(b"not-a-real-onnx")
    config["ml"]["model_type"] = "onnx"
    config["ml"]["onnx_model_path"] = str(fake)

    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_dense_parsed_events(config)

    with pytest.raises(ModelNotConfiguredError):
        run_detect_ml(config, config_path=config_path)

    connection = get_connection(config)
    try:
        score_count = connection.execute(
            "SELECT COUNT(*) FROM ml_window_scores"
        ).fetchone()[0]
        assert int(score_count) == 0
    finally:
        connection.close()
