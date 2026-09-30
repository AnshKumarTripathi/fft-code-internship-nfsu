"""R7 explainability payload: structured why-flagged on merge, API, and reports."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from src.correlation.merge_scores import discover_and_merge
from src.db.connection import get_connection
from src.detectors.spectral.baseline import compute_baseline
from src.detectors.spectral.windowed import windowed_deviation
from src.explainability.payload import explanation_from_anomaly, spectral_crossing_legs
from src.reporting.report_generator import (
    IncidentRow,
    build_context,
    render_incident_markdown,
)

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import create_app  # noqa: E402
from tests.test_api_dashboard import _full_config, _write_config  # noqa: E402
from tests.fixtures.synthetic_entities import generate_periodic_counts

UTC = timezone.utc
BUCKET_SECONDS = 600


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
    ts = datetime(2024, 1, 1, tzinfo=UTC)
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
        VALUES (?, 'user', ?, ?)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [entity_id, ts, ts],
    )


def test_spectral_crossing_legs_energy_shape_and_both() -> None:
    assert spectral_crossing_legs(6.0, 1.0, 4.0) == ["energy_z"]
    assert spectral_crossing_legs(1.0, 5.0, 4.0) == ["shape_js_z"]
    assert spectral_crossing_legs(4.0, 4.0, 4.0) == ["energy_z", "shape_js_z"]
    assert spectral_crossing_legs(None, 5.5, 4.0) == ["shape_js_z"]
    assert spectral_crossing_legs(3.9, 3.9, 4.0) == []


def test_windowed_scores_include_dominant_period() -> None:
    period = 24 * 3600 // BUCKET_SECONDS
    starts, counts = generate_periodic_counts(
        n_buckets=800,
        period_buckets=period,
        bucket_seconds=BUCKET_SECONDS,
    )
    baseline = compute_baseline(
        counts,
        entity_id="alice",
        bucket_seconds=BUCKET_SECONDS,
        baseline_max_nperseg=1440,
    )
    assert baseline is not None
    rows = windowed_deviation(
        counts,
        starts,
        baseline,
        bucket_seconds=BUCKET_SECONDS,
        window_buckets=period * 3,
        step_buckets=period,
        z_threshold=4.0,
    )
    assert rows
    periods = [row.dominant_period_hours for row in rows if row.dominant_period_hours]
    assert periods
    median = float(np.median(periods))
    assert median == pytest.approx(24.0, rel=0.25)


def test_statistical_merge_includes_log_sources_and_gap(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    try:
        _seed_entity(connection)
        connection.execute(
            """
            INSERT INTO statistical_window_scores
            (entity_id, window_start, window_end, rate_z, flagged)
            VALUES ('alice', ?, ?, 5.2, TRUE)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO templates
            (template_id, template_string, first_seen, last_seen, occurrence_count)
            VALUES
              ('t1', 'ssh line', ?, ?, 2),
              ('t2', 'windows line', ?, ?, 1)
            """,
            [start, start, start, start],
        )
        connection.execute(
            """
            INSERT INTO parsed_events
            (event_id, entity_id, template_id, event_timestamp, log_source,
             raw_fields, ingested_at)
            VALUES
              (1, 'alice', 't1', ?, 'ssh', '{}'::JSON, ?),
              (2, 'alice', 't1', ?, 'ssh', '{}'::JSON, ?),
              (3, 'alice', 't2', ?, 'windows', '{}'::JSON, ?)
            """,
            [start, start, start + timedelta(minutes=10), start,
             start + timedelta(minutes=20), start],
        )
        connection.execute(
            """
            INSERT INTO entity_bucket_counts
            (entity_id, bucket_start, bucket_seconds, event_count)
            VALUES
              ('alice', ?, 600, 4.0),
              ('alice', ?, 600, 0.0),
              ('alice', ?, 600, 0.0)
            """,
            [start, start + timedelta(minutes=10), start + timedelta(minutes=20)],
        )
        result = discover_and_merge(connection)
        meta = result.anomalies[0].metadata
        sources = {row["log_source"]: row["event_count"] for row in meta["log_sources"]}
        assert sources["ssh"] == 2
        assert sources["windows"] == 1
        assert meta["gap"]["bucket_count"] == 3
        assert meta["gap"]["zero_bucket_count"] == 2
        assert meta["gap"]["possible_gap"] is True
        expl = explanation_from_anomaly(
            detector="statistical",
            entity_id="alice",
            window_start=start,
            window_end=end,
            score=5.2,
            metadata=meta,
        )
        assert expl["statistical"]["rate_z"] == 5.2
        assert expl["playbook"]["title"]
        assert "rate_z" in expl["headline"]
    finally:
        connection.close()


def test_ml_merge_includes_snapshot_and_mad_z(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    try:
        _seed_entity(connection)
        connection.execute(
            """
            INSERT INTO ml_window_scores
            (entity_id, window_start, window_end, model_score, flagged,
             model_snapshot_id, mad_z)
            VALUES ('alice', ?, ?, 0.9, TRUE, 'snap-ml-1', 4.8)
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO templates
            (template_id, template_string, first_seen, last_seen, occurrence_count)
            VALUES ('t-auth', 'Failed password for <*>', ?, ?, 3)
            """,
            [start, start],
        )
        connection.execute(
            """
            INSERT INTO parsed_events
            (event_id, entity_id, template_id, event_timestamp, log_source,
             raw_fields, ingested_at)
            VALUES (1, 'alice', 't-auth', ?, 'ssh', '{}'::JSON, ?)
            """,
            [start, start],
        )
        result = discover_and_merge(
            connection, ml_model_type="isolation_forest", ml_flagging="mad_threshold"
        )
        meta = result.anomalies[0].metadata
        assert meta["model_snapshot_id"] == "snap-ml-1"
        assert meta["mad_z"] == 4.8
        assert meta["flagging"] == "mad_threshold"
        assert meta["top_templates"][0]["template_id"] == "t-auth"
        expl = explanation_from_anomaly(
            detector="ml",
            entity_id="alice",
            window_start=start,
            window_end=end,
            score=0.9,
            metadata=meta,
        )
        assert expl["ml"]["model_snapshot_id"] == "snap-ml-1"
        assert expl["ml"]["mad_z"] == 4.8
    finally:
        connection.close()


def test_cluster_merge_includes_size_distance_lookback(tmp_path: Path) -> None:
    connection = get_connection(_config(tmp_path))
    ts = datetime(2024, 1, 14, tzinfo=UTC)
    try:
        for entity_id, cluster_id, period in (
            ("alice", 0, 24.0),
            ("bob", 0, 24.1),
            ("carol", -1, 0.7),
        ):
            _seed_entity(connection, entity_id)
            connection.execute(
                """
                INSERT INTO spectral_baselines
                (entity_id, computed_at, bucket_seconds, nperseg,
                 freq_grid, psd, psd_norm)
                VALUES (?, ?, 600, 8, [0.0, 0.1], [1.0, 0.5], [0.6, 0.4])
                """,
                [entity_id, ts],
            )
            connection.execute(
                """
                INSERT INTO entity_spectral_features
                (entity_id, dominant_period_hours, dominant_power_frac,
                 spectral_entropy, total_power, computed_at)
                VALUES (?, ?, 0.5, 1.0, 3.0, ?)
                """,
                [entity_id, period, ts],
            )
            connection.execute(
                """
                INSERT INTO entity_clusters
                (entity_id, cluster_run_id, cluster_id, computed_at)
                VALUES (?, 'run-1', ?, ?)
                """,
                [entity_id, cluster_id, ts],
            )
        result = discover_and_merge(connection)
        outlier = next(a for a in result.anomalies if a.entity_id == "carol")
        meta = outlier.metadata
        assert meta["cluster_run_id"] == "run-1"
        assert meta["n_entities"] == 3
        assert meta["n_outliers"] == 1
        assert meta["n_clustered"] == 2
        assert meta["lookback_days"] == 14
        assert meta["window_policy"] == "overlapping_flags"
        assert meta["nearest_distance"] is not None
        assert meta["nearest_distance"] > 0
        expl = explanation_from_anomaly(
            detector="cluster_outlier",
            entity_id="carol",
            window_start=outlier.window_start,
            window_end=outlier.window_end,
            score=1.0,
            metadata=meta,
        )
        assert expl["cluster"]["n_entities"] == 3
        assert expl["cluster"]["lookback_days"] == 14
        assert "peer-group outlier" in expl["headline"]
    finally:
        connection.close()


def test_report_why_flagged_section_without_llm(tmp_path: Path) -> None:
    config = _config(tmp_path)
    connection = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    try:
        _seed_entity(connection)
        connection.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end,
             source_detector, score, metadata)
            VALUES (
              'anom-1', 'alice', ?, ?, 'spectral', 6.1,
              '{"energy_z": 6.1, "shape_js_z": 1.2, "crossing_legs": ["energy_z"], "rule": "energy_or_shape", "z_threshold": 4.0, "dominant_period_hours": 0.67, "bucket_seconds": 600}'::JSON
            )
            """,
            [start, end],
        )
        connection.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-1', 'alice', ?, ?, 'high', 'spectral flag', ?)
            """,
            [start, end, ["anom-1"]],
        )
        incident = IncidentRow(
            incident_id="inc-1",
            entity_id="alice",
            start_time=start,
            end_time=end,
            severity="high",
            summary_text="spectral flag",
            contributing_anomaly_ids=["anom-1"],
        )
        context = build_context(connection, incident)
        markdown = render_incident_markdown(
            context, template_path=config["reporting"]["template_path"]
        )
    finally:
        connection.close()
    assert "## Why flagged" in markdown
    assert "energy_z" in markdown
    assert "Investigate a rhythm change" in markdown
    assert context["anomalies"][0]["explanation"]["spectral"]["crossing_legs"] == [
        "energy_z"
    ]


def test_api_incident_anomalies_include_explanation(tmp_path: Path) -> None:
    config = _full_config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, 12, tzinfo=UTC)
    end = start + timedelta(hours=1)
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('alice', 'user', ?, ?)
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO anomaly_events
            (anomaly_id, entity_id, window_start, window_end,
             source_detector, score, metadata)
            VALUES (
              'anom-r7', 'alice', ?, ?, 'spectral', 6.0,
              '{"energy_z": 6.0, "shape_js_z": 4.5, "crossing_legs": ["energy_z", "shape_js_z"], "rule": "energy_or_shape", "z_threshold": 4.0, "dominant_period_hours": 0.67, "bucket_seconds": 600}'::JSON
            )
            """,
            [start, end],
        )
        conn.execute(
            """
            INSERT INTO incidents
            (incident_id, entity_id, start_time, end_time, severity,
             summary_text, contributing_anomaly_ids)
            VALUES ('inc-r7', 'alice', ?, ?, 'high', 'both legs', ?)
            """,
            [start, end, ["anom-r7"]],
        )
    finally:
        conn.close()
    client = TestClient(create_app(_write_config(tmp_path, config)))
    response = client.get("/api/v1/incidents/inc-r7")
    assert response.status_code == 200
    expl = response.json()["anomalies"][0]["explanation"]
    assert expl["detector"] == "spectral"
    assert expl["entity_id"] == "alice"
    assert expl["bucket_seconds"] == 600
    assert expl["spectral"]["crossing_legs"] == ["energy_z", "shape_js_z"]
    assert expl["spectral"]["dominant_period_hours"] == 0.67
    assert expl["playbook"]["title"]
    assert expl["headline"]
