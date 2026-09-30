"""End-to-end correlate pipeline tests (partial-input matrix)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.correlation.merge_scores import CorrelationError
from src.correlation.persist import run_correlate
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


def _seed_base(connection, entity_id: str = "alice") -> tuple[datetime, datetime]:
    start = datetime(2024, 1, 1, 12, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
        VALUES (?, 'user', ?, ?)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [entity_id, start, end],
    )
    connection.execute(
        """
        INSERT INTO templates
        (template_id, template_string, first_seen, last_seen, occurrence_count)
        VALUES ('t1', 'Accepted password for <*>', ?, ?, 1)
        ON CONFLICT (template_id) DO NOTHING
        """,
        [start, end],
    )
    for i in range(5):
        ts = start + timedelta(minutes=i * 5)
        connection.execute(
            """
            INSERT INTO parsed_events
            (event_id, entity_id, template_id, event_timestamp, log_source, raw_fields, ingested_at)
            VALUES (?, ?, 't1', ?, 'ssh', ?::JSON, ?)
            """,
            [
                i + 1,
                entity_id,
                ts,
                '{"src_ip": "10.0.0.1", "username": "alice"}',
                ts,
            ],
        )
    return start, end


def test_correlate_no_sources(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(CorrelationError, match="nothing to correlate"):
        run_correlate(config, config_path=None)


def test_correlate_statistical_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE)
            """,
            [start, end],
        )
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.sources == ["statistical"]
    assert summary.anomalies == 1
    assert summary.incidents >= 1

    connection = get_connection(config)
    try:
        assert connection.execute("SELECT COUNT(*) FROM anomaly_events").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] >= 1
        assert connection.execute("SELECT COUNT(*) FROM correlation_edges").fetchone()[0] >= 1
        src = connection.execute(
            "SELECT source_detector FROM anomaly_events"
        ).fetchone()[0]
        assert src == "statistical"
    finally:
        connection.close()


def test_correlate_spectral_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO spectral_window_scores
            (entity_id, window_start, window_end, energy_z, shape_js_z, flagged)
            VALUES ('alice', ?, ?, 5.0, 2.0, TRUE)
            """,
            [start, end],
        )
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.sources == ["spectral"]
    assert summary.incidents >= 1


def test_correlate_ml_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO ml_window_scores
            (entity_id, window_start, window_end, model_score, flagged)
            VALUES ('alice', ?, ?, 0.8, TRUE)
            """,
            [start, end],
        )
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.sources == ["ml"]
    assert summary.incidents >= 1


def test_correlate_multi_source(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE)
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
    finally:
        connection.close()

    summary = run_correlate(config)
    assert set(summary.sources) == {"statistical", "ml"}
    assert summary.anomalies == 2

    connection = get_connection(config)
    try:
        detectors = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT source_detector FROM anomaly_events"
            ).fetchall()
        }
        assert detectors == {"statistical", "ml"}
        severity = connection.execute("SELECT severity FROM incidents").fetchone()[0]
        assert severity == "high"
        incident_id = connection.execute(
            "SELECT incident_id FROM incidents"
        ).fetchone()[0]
    finally:
        connection.close()

    # Default any_flag re-correlate keeps the same incident id + severity.
    summary2 = run_correlate(config)
    assert summary2.incidents == 1
    connection = get_connection(config)
    try:
        row = connection.execute(
            "SELECT incident_id, severity FROM incidents"
        ).fetchone()
        assert row[0] == incident_id
        assert row[1] == "high"
    finally:
        connection.close()


def test_correlate_min_detectors_drops_single_keeps_multi(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["correlation"]["promotion"] = {
        "mode": "min_detectors",
        "min_detectors": 2,
    }
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE)
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
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.anomalies == 2
    assert summary.incidents == 1
    assert summary.severity_counts == {"high": 1}


def test_correlate_min_detectors_hides_single_detector_only(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["correlation"]["promotion"] = {
        "mode": "min_detectors",
        "min_detectors": 2,
    }
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE)
            """,
            [start, end],
        )
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.anomalies == 1
    assert summary.incidents == 0

    connection = get_connection(config)
    try:
        assert connection.execute("SELECT COUNT(*) FROM anomaly_events").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0
    finally:
        connection.close()


def test_correlate_severity_boost_raises_threshold(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config["correlation"]["promotion"] = {
        "mode": "severity_boost",
        "min_detectors": 3,
    }
    connection = get_connection(config)
    try:
        start, end = _seed_base(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.0, TRUE)
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
    finally:
        connection.close()

    summary = run_correlate(config)
    assert summary.anomalies == 2
    assert summary.incidents == 1
    # Two detectors < min_detectors=3 → medium (n>=2), not high.
    assert summary.severity_counts == {"medium": 1}