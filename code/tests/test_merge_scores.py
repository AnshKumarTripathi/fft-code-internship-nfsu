"""Unit tests for merge_scores source discovery and mapping."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.correlation.merge_scores import CorrelationError, discover_and_merge
from src.correlation.persist import (
    DEFAULT_PROMOTION_MODE,
    PROMOTION_MODES,
    _validate_correlation_config,
)
from src.db.connection import get_connection

CODE_ROOT = Path(__file__).resolve().parents[1]


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


def _seed_entity(connection, entity_id: str = "alice") -> None:
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
        VALUES (?, 'user', ?, ?)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [entity_id, ts, ts],
    )


def test_no_sources_raises(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        with pytest.raises(CorrelationError, match="nothing to correlate"):
            discover_and_merge(connection)
    finally:
        connection.close()


def test_statistical_only_merge(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection)
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE),
                   ('alice', ?, ?, 1.0, FALSE)
            """,
            [start, end, start.replace(hour=14), end.replace(hour=15)],
        )
        result = discover_and_merge(connection)
        assert result.discovered_sources == ["statistical"]
        assert len(result.anomalies) == 1
        assert result.anomalies[0].source_detector == "statistical"
        assert result.anomalies[0].score == 5.0
        assert result.anomalies[0].metadata["rate_z"] == 5.0
        assert result.anomalies[0].metadata["rule"] == "rate_z >= z_threshold"
        assert result.anomalies[0].metadata["z_threshold"] == 4.0
        assert result.anomalies[0].metadata["playbook"]["title"]
    finally:
        connection.close()


def test_multi_source_merge(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection)
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 4.5, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES ('alice', ?, ?, 6.0, 3.0, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO ml_window_scores
            (entity_id, window_start, window_end, model_score, flagged)
            VALUES ('alice', ?, ?, 0.9, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO changepoint_window_scores
            (entity_id, window_start, window_end, cusum_high, cusum_low,
             flagged, direction)
            VALUES ('alice', ?, ?, 8.0, 0.1, TRUE, 'up')
            """,
            [start, end],
        )
        result = discover_and_merge(connection, ml_model_type="isolation_forest")
        sources = set(result.discovered_sources)
        assert sources == {"statistical", "spectral", "ml", "changepoint"}
        assert {a.source_detector for a in result.anomalies} == sources
        spectral = next(a for a in result.anomalies if a.source_detector == "spectral")
        assert spectral.score == 6.0
        ml = next(a for a in result.anomalies if a.source_detector == "ml")
        assert ml.metadata["model_type"] == "isolation_forest"
        assert ml.metadata["flagging"] == "mad_threshold"
        assert ml.metadata["model_score"] == 0.9
    finally:
        connection.close()


def test_null_spectral_scores_are_skipped(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection)
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES
              ('alice', ?, ?, NULL, NULL, TRUE),
              ('alice', ?, ?, NULL, 5.5, TRUE)
            """,
            [start, end, start.replace(hour=14), end.replace(hour=15)],
        )
        result = discover_and_merge(connection)
        assert result.discovered_sources == ["spectral"]
        assert len(result.anomalies) == 1
        assert result.anomalies[0].score == 5.5
        meta = result.anomalies[0].metadata
        assert meta["shape_js_z"] == 5.5
        assert "energy_z" not in meta
        assert meta["rule"] == "energy_or_shape"
        assert meta["crossing_legs"] == ["shape_js_z"]
    finally:
        connection.close()


def _seed_spectral_baseline(connection, entity_id: str, ts: datetime) -> None:
    connection.execute(
        """
        INSERT INTO spectral_baselines
        (entity_id, computed_at, bucket_seconds, nperseg, freq_grid, psd, psd_norm)
        VALUES (?, ?, 600, 8, [0.0, 0.1], [1.0, 0.5], [0.6, 0.4])
        """,
        [entity_id, ts],
    )


def test_cluster_outlier_merge(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection, "bob")
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        _seed_spectral_baseline(connection, "bob", ts)
        connection.execute(
            """
            INSERT INTO entity_clusters
            (entity_id, cluster_run_id, cluster_id, computed_at)
            VALUES ('bob', 'run-1', -1, ?)
            """,
            [ts],
        )
        result = discover_and_merge(connection)
        assert result.discovered_sources == ["cluster_outlier"]
        assert len(result.anomalies) == 1
        assert result.anomalies[0].score == 1.0
        assert result.anomalies[0].metadata["cluster_run_id"] == "run-1"
    finally:
        connection.close()


def test_cluster_outlier_without_baseline_not_emitted(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection, "cold")
        ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        connection.execute(
            """
            INSERT INTO entity_clusters
            (entity_id, cluster_run_id, cluster_id, computed_at)
            VALUES ('cold', 'run-1', -1, ?)
            """,
            [ts],
        )
        with pytest.raises(CorrelationError, match="nothing to correlate"):
            discover_and_merge(connection)
    finally:
        connection.close()


def test_promotion_defaults_preserve_any_flag() -> None:
    settings = _validate_correlation_config({"correlation": {}})
    assert settings.promotion_mode == DEFAULT_PROMOTION_MODE == "any_flag"
    assert settings.promotion_min_detectors == 2
    assert settings.agreement_threshold == 2


def test_promotion_severity_boost_uses_yaml_min() -> None:
    settings = _validate_correlation_config(
        {
            "correlation": {
                "promotion": {"mode": "severity_boost", "min_detectors": 3},
            }
        }
    )
    assert settings.promotion_mode == "severity_boost"
    assert settings.agreement_threshold == 3


def test_promotion_any_flag_ignores_yaml_min_for_severity() -> None:
    settings = _validate_correlation_config(
        {
            "correlation": {
                "promotion": {"mode": "any_flag", "min_detectors": 5},
            }
        }
    )
    assert settings.agreement_threshold == 2


def test_promotion_invalid_mode_raises() -> None:
    with pytest.raises(CorrelationError, match="promotion.mode"):
        _validate_correlation_config(
            {"correlation": {"promotion": {"mode": "weighted"}}}
        )
    assert "any_flag" in PROMOTION_MODES
    assert "severity_boost" in PROMOTION_MODES
    assert "min_detectors" in PROMOTION_MODES


def test_five_detectors_participate_in_merge(tmp_path: Path) -> None:
    """Phase 54: all mergeable source_detector values count toward agreement."""
    connection = get_connection(_config(tmp_path))
    try:
        _seed_entity(connection)
        start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, 13, tzinfo=timezone.utc)
        _seed_spectral_baseline(connection, "alice", start)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 4.5, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES ('alice', ?, ?, 6.0, 3.0, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO ml_window_scores
            (entity_id, window_start, window_end, model_score, flagged)
            VALUES ('alice', ?, ?, 0.9, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO changepoint_window_scores
            (entity_id, window_start, window_end, cusum_high, cusum_low,
             flagged, direction)
            VALUES ('alice', ?, ?, 8.0, 0.1, TRUE, 'up')
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO entity_clusters
            (entity_id, cluster_run_id, cluster_id, computed_at)
            VALUES ('alice', 'run-1', -1, ?)
            """,
            [start],
        )
        result = discover_and_merge(connection)
        sources = set(result.discovered_sources)
        assert sources == {
            "statistical",
            "spectral",
            "ml",
            "changepoint",
            "cluster_outlier",
        }
        assert {a.source_detector for a in result.anomalies} == sources
    finally:
        connection.close()
