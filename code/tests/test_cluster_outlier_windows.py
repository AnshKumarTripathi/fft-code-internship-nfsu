"""Bounded cluster-outlier windows (default is not entity lifetime)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.correlation.merge_scores import (
    cluster_outlier_window_for,
    discover_and_merge,
)
from src.db.connection import get_connection


def _config(tmp_path: Path) -> dict:
    data = tmp_path / "data"
    return {
        "paths": {
            "raw_log_dir": str(data / "raw"),
            "parsed_dir": str(data / "parsed"),
            "timeseries_dir": str(data / "timeseries"),
            "baseline_dir": str(data / "baselines"),
            "scores_dir": str(data / "scores"),
            "report_dir": str(data / "reports"),
            "db_path": str(data / "warehouse.duckdb"),
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


def test_overlapping_flags_falls_back_to_lookback_not_lifetime() -> None:
    first = datetime(2024, 1, 1, tzinfo=timezone.utc)
    last = first + timedelta(days=30)
    start, end = cluster_outlier_window_for(
        first_seen=first,
        last_seen=last,
        other_flagged=[],
        policy="overlapping_flags",
        lookback_days=14,
        now=last,
    )
    assert end - start <= timedelta(days=14)
    assert end - start < timedelta(days=30)


def test_overlapping_flags_uses_other_flagged_windows() -> None:
    first = datetime(2024, 1, 1, tzinfo=timezone.utc)
    last = first + timedelta(days=30)
    flag_start = datetime(2024, 1, 20, 12, tzinfo=timezone.utc)
    flag_end = flag_start + timedelta(hours=1)
    start, end = cluster_outlier_window_for(
        first_seen=first,
        last_seen=last,
        other_flagged=[(flag_start, flag_end)],
        policy="overlapping_flags",
        lookback_days=14,
        now=last,
    )
    assert start == flag_start
    assert end == flag_end


def test_entity_lifetime_opt_in_spans_first_to_last() -> None:
    first = datetime(2024, 1, 1, tzinfo=timezone.utc)
    last = first + timedelta(days=30)
    start, end = cluster_outlier_window_for(
        first_seen=first,
        last_seen=last,
        other_flagged=[],
        policy="entity_lifetime",
        lookback_days=14,
        now=last,
    )
    assert start == first
    assert end == last


def test_default_merge_window_is_not_lifetime(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    first = datetime(2024, 1, 1, tzinfo=timezone.utc)
    last = first + timedelta(days=30)
    try:
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('bob', 'user', ?, ?)
            """,
            [first, last],
        )
        connection.execute(
            """
            INSERT INTO spectral_baselines
            (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
            VALUES ('bob', ?, 600, 8, [0.0, 0.1], [1.0, 0.5], [0.6, 0.4])
            """,
            [last],
        )
        connection.execute(
            """
            INSERT INTO entity_clusters
            (entity_id, cluster_run_id, cluster_id, computed_at)
            VALUES ('bob', 'run-1', -1, ?)
            """,
            [last],
        )
        result = discover_and_merge(connection)
        assert result.discovered_sources == ["cluster_outlier"]
        assert len(result.anomalies) == 1
        span = result.anomalies[0].window_end - result.anomalies[0].window_start
        assert span < timedelta(days=30)
        assert result.anomalies[0].metadata["window_policy"] == "overlapping_flags"
    finally:
        connection.close()


def test_entity_lifetime_merge_spans_first_seen_last_seen(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    first = datetime(2024, 1, 1, tzinfo=timezone.utc)
    last = first + timedelta(days=30)
    try:
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('bob', 'user', ?, ?)
            """,
            [first, last],
        )
        connection.execute(
            """
            INSERT INTO spectral_baselines
            (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
            VALUES ('bob', ?, 600, 8, [0.0, 0.1], [1.0, 0.5], [0.6, 0.4])
            """,
            [last],
        )
        connection.execute(
            """
            INSERT INTO entity_clusters
            (entity_id, cluster_run_id, cluster_id, computed_at)
            VALUES ('bob', 'run-1', -1, ?)
            """,
            [last],
        )
        result = discover_and_merge(
            connection, cluster_outlier_window="entity_lifetime"
        )
        anomaly = result.anomalies[0]
        assert anomaly.window_end - anomaly.window_start >= timedelta(days=30)
        assert anomaly.metadata["window_policy"] == "entity_lifetime"
    finally:
        connection.close()
