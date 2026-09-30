"""End-to-end detect-changepoint pipeline tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.correlation.merge_scores import discover_and_merge
from src.db.connection import get_connection
from src.detectors.changepoint.persist import ChangepointError, run_detect_changepoint
from src.detectors.changepoint.writers import changepoint_scores_dir

UTC = timezone.utc


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
        "changepoint": {
            "min_history_buckets": 48,
            "baseline_buckets": 48,
            "drift_k": 0.5,
            "decision_h": 5.0,
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
        "orchestration": {"parallel_backend": "none", "n_workers": 1},
    }


def _seed_shift_series(config: dict, entity_id: str = "alice") -> None:
    connection = get_connection(config)
    try:
        start = datetime(2024, 1, 1, tzinfo=UTC)
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES (?, 'user', ?, ?)
            """,
            [entity_id, start, start],
        )
        rows = []
        for index in range(80):
            bucket_start = start + timedelta(seconds=600 * index)
            count = 10.0 + (index % 3 - 1) if index < 48 else 40.0
            rows.append((entity_id, bucket_start, 600, count))
        connection.executemany(
            """
            INSERT INTO entity_bucket_counts
            (entity_id, bucket_start, bucket_seconds, event_count)
            VALUES (?, ?, ?, ?)
            """,
            rows,
        )
    finally:
        connection.close()


def test_detect_changepoint_requires_buckets(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    with pytest.raises(ChangepointError, match="run bucket first"):
        run_detect_changepoint(config, config_path=None)


def test_run_detect_changepoint_and_merge(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    _seed_shift_series(config)
    summary = run_detect_changepoint(config, config_path=None)
    assert summary.windows_flagged >= 1
    assert summary.entities_scored >= 1
    scores_dir = changepoint_scores_dir(config)
    assert list(scores_dir.glob("entity_id=*/*.parquet"))

    connection = get_connection(config)
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM changepoint_window_scores WHERE flagged = TRUE"
        ).fetchone()[0]
        assert int(count) >= 1
        result = discover_and_merge(connection)
        assert "changepoint" in result.discovered_sources
        flags = [a for a in result.anomalies if a.source_detector == "changepoint"]
        assert flags
        assert flags[0].metadata["rule"] == "cusum_sigma >= decision_h"
        assert flags[0].metadata["playbook"]["title"]
    finally:
        connection.close()
