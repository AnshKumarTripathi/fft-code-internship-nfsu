"""End-to-end spectral pipeline tests."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.detectors.spectral.persist import (
    NothingToCluster,
    SpectralError,
    run_cluster,
    run_detect_spectral,
)
from src.detectors.spectral.writers import spectral_scores_dir
from tests.fixtures.seed_spectral import seed_entity_bucket_series

CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _temp_config(tmp_path: Path) -> dict:
    data_root = tmp_path / "data"
    raw = data_root / "raw"
    raw.mkdir(parents=True)
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
            "cluster_min_entities": 2,
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


def _seed_synthetic_entities(config: dict, entity_ids: list[str]) -> None:
    seed_entity_bucket_series(config, entity_ids, replace_existing=True)


def test_detect_spectral_requires_buckets(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    with pytest.raises(SpectralError, match="run bucket first"):
        run_detect_spectral(config, config_path=config_path)


def test_run_detect_spectral_and_cluster_end_to_end(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    _seed_synthetic_entities(config, ["entity_a", "entity_b", "entity_c"])
    spectral_summary = run_detect_spectral(config, config_path=config_path)

    assert spectral_summary.baselines_written == 3
    assert spectral_summary.features_written == 3
    assert spectral_summary.entities_processed == 3
    assert spectral_summary.windows_total > 0

    scores_dir = spectral_scores_dir(config)
    assert list(scores_dir.glob("entity_id=*/*.parquet"))

    connection = get_connection(config)
    try:
        baseline_count = connection.execute(
            "SELECT COUNT(*) FROM spectral_baselines"
        ).fetchone()[0]
        assert baseline_count == 3

        feature_count = connection.execute(
            "SELECT COUNT(*) FROM entity_spectral_features"
        ).fetchone()[0]
        assert feature_count == 3

        run_row = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'detect-spectral'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
    finally:
        connection.close()

    cluster_summary = run_cluster(config, config_path=config_path)
    assert cluster_summary.entities_clustered == 3

    connection = get_connection(config)
    try:
        cluster_count = connection.execute(
            "SELECT COUNT(*) FROM entity_clusters"
        ).fetchone()[0]
        assert cluster_count == 3
        cluster_run = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'cluster'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()
        assert cluster_run[0] == "success"
    finally:
        connection.close()


def test_cluster_requires_features(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")

    with pytest.raises(NothingToCluster, match="nothing to cluster"):
        run_cluster(config, config_path=config_path)


def test_cluster_skips_below_min_entities(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config["spectral"]["cluster_min_entities"] = 20
    config_path = config.pop("_config_path")
    connection = get_connection(config)
    try:
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            entity_id = f"peer{i}"
            connection.execute(
                """
                INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
                VALUES (?, 'user', ?, ?)
                """,
                [entity_id, ts, ts],
            )
            connection.execute(
                """
                INSERT INTO entity_spectral_features (
                    entity_id, dominant_period_hours, dominant_power_frac,
                    spectral_entropy, total_power, computed_at
                )
                VALUES (?, 24.0, 0.4, 2.5, 100.0, ?)
                """,
                [entity_id, ts],
            )
    finally:
        connection.close()

    with pytest.raises(NothingToCluster, match="only 5 entities \\(min 20\\)"):
        run_cluster(config, config_path=config_path)

    connection = get_connection(config)
    try:
        count = connection.execute("SELECT COUNT(*) FROM entity_clusters").fetchone()[0]
        assert int(count) == 0
        status = connection.execute(
            """
            SELECT status FROM pipeline_runs
            WHERE stage = 'cluster'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()[0]
        assert status == "success"
    finally:
        connection.close()


def test_detect_spectral_rejects_mismatched_bucket_seconds(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    _seed_synthetic_entities(config, ["entity_a"])
    connection = get_connection(config)
    try:
        connection.execute("UPDATE entity_bucket_counts SET bucket_seconds = 60")
    finally:
        connection.close()

    with pytest.raises(SpectralError, match="bucket_seconds"):
        run_detect_spectral(config, config_path=config_path)
