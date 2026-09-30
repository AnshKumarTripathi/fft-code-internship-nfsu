"""Phase 92 — analysis window bounds heavy detectors on merged history."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from src.config import ConfigError, load_config, sharding_settings
from src.db.connection import get_connection
from src.detectors.statistical.persist import run_detect_statistical
from src.timeseries.analysis_window import (
    AnalysisWindow,
    bucket_series_sql,
    resolve_analysis_window,
)

UTC = timezone.utc
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"


def _base_config(tmp_path: Path) -> dict:
    data = tmp_path / "data"
    raw = data / "raw"
    shards = raw / "shards"
    config_dir = tmp_path / "config"
    raw.mkdir(parents=True)
    shards.mkdir(parents=True)
    config_dir.mkdir(parents=True)
    import shutil

    shutil.copy(DRAIN3_INI, config_dir / "drain3.ini")
    return {
        "paths": {
            "raw_log_dir": str(raw),
            "parsed_dir": str(data / "parsed"),
            "timeseries_dir": str(data / "timeseries"),
            "baseline_dir": str(data / "baselines"),
            "scores_dir": str(data / "scores"),
            "report_dir": str(data / "reports"),
            "analyses_dir": str(data / "analyses"),
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
            "max_buckets_per_entity": 100,
        },
        "ml": {
            "model_type": "isolation_forest",
            "onnx_model_path": None,
            "contamination": 0.02,
            "flagging": "mad_threshold",
            "mad_k": 4.0,
            "min_windows_to_fit": 5,
            "mode": "refit_and_snapshot",
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
        "orchestration": {"parallel_backend": "threads", "n_workers": 2},
        "parse": {
            "mode": "train_and_snapshot",
            "start_empty": True,
            "snapshot_id": None,
        },
        "sharding": {
            "enabled": False,
            "target_shard_bytes": 200,
            "target_shard_lines": None,
            "output_dir": str(shards),
            "max_shards": 50,
            "prefer_server_path": True,
            "analysis_window": {
                "enabled": False,
                "last_days": 30,
                "start_utc": None,
                "end_utc": None,
            },
        },
        "_config_dir": str(config_dir),
    }


def _write_config(tmp_path: Path, config: dict) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def _seed_bucket_series(
    config: dict,
    *,
    entity_id: str = "alice",
    days: int = 10,
    spike_day_offset: int | None = None,
) -> None:
    """Insert dense 600s buckets spanning ``days`` ending at a fixed anchor."""
    connection = get_connection(config)
    try:
        anchor = datetime(2024, 2, 10, 12, 0, tzinfo=UTC)
        buckets_per_day = 24 * 6  # 600s
        n = days * buckets_per_day
        start0 = anchor - timedelta(seconds=600 * (n - 1))
        connection.execute(
            """
            INSERT INTO entities
            (entity_id, entity_type, first_seen, last_seen, label)
            VALUES (?, 'user', ?, ?, 'alice')
            """,
            [entity_id, start0, anchor],
        )
        rows = []
        for index in range(n):
            bucket_start = start0 + timedelta(seconds=600 * index)
            day_index = index // buckets_per_day
            count = 5.0
            if spike_day_offset is not None and day_index == spike_day_offset:
                count = 500.0
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


def test_config_default_disabled(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    path = _write_config(tmp_path, config)
    loaded = load_config(path)
    window = sharding_settings(loaded)["analysis_window"]
    assert window["enabled"] is False
    assert window["last_days"] == 30
    assert window["start_utc"] is None


def test_config_rejects_partial_absolute(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 7,
        "start_utc": "2024-01-01T00:00:00+00:00",
        "end_utc": None,
    }
    path = _write_config(tmp_path, config)
    with pytest.raises(ConfigError, match="both"):
        load_config(path)


def test_config_rejects_inverted_absolute(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 7,
        "start_utc": "2024-02-01T00:00:00+00:00",
        "end_utc": "2024-01-01T00:00:00+00:00",
    }
    path = _write_config(tmp_path, config)
    with pytest.raises(ConfigError, match="<="):
        load_config(path)


def test_resolve_last_days_from_anchor(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    _seed_bucket_series(config, days=20)
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 5,
        "start_utc": None,
        "end_utc": None,
    }
    connection = get_connection(config)
    try:
        window = resolve_analysis_window(config, connection, source="buckets")
    finally:
        connection.close()
    assert window is not None
    assert window.mode == "last_days"
    assert window.last_days == 5
    assert window.end_utc - window.start_utc == timedelta(days=5)


def test_resolve_absolute_bounds(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    get_connection(config).close()
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 30,
        "start_utc": "2024-01-05T00:00:00+00:00",
        "end_utc": "2024-01-20T00:00:00+00:00",
    }
    connection = get_connection(config)
    try:
        window = resolve_analysis_window(config, connection, source="buckets")
    finally:
        connection.close()
    assert window is not None
    assert window.mode == "absolute"
    assert window.start_utc == datetime(2024, 1, 5, tzinfo=UTC)


def test_bucket_sql_filters_outside_window(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    _seed_bucket_series(config, days=10)
    window = AnalysisWindow(
        mode="absolute",
        start_utc=datetime(2024, 2, 8, tzinfo=UTC),
        end_utc=datetime(2024, 2, 10, 23, tzinfo=UTC),
    )
    sql, params = bucket_series_sql(window)
    connection = get_connection(config)
    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        filtered = connection.execute(sql, params).fetchall()
    finally:
        connection.close()
    assert int(total) > len(filtered) > 0
    for row in filtered:
        ts = row[1]
        assert isinstance(ts, datetime)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        assert window.start_utc <= ts <= window.end_utc


def test_statistical_window_cuts_series_and_keeps_warehouse(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    # Spike only on early days (outside a 2-day window).
    _seed_bucket_series(config, days=12, spike_day_offset=1)
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 2,
        "start_utc": None,
        "end_utc": None,
    }
    config["statistical"] = {"window_buckets": 3, "z_threshold": 3.0}

    connection = get_connection(config)
    try:
        before_buckets = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        before_events = connection.execute(
            "SELECT COUNT(*) FROM parsed_events"
        ).fetchone()[0]
    finally:
        connection.close()

    run_detect_statistical(config)

    connection = get_connection(config)
    try:
        after_buckets = connection.execute(
            "SELECT COUNT(*) FROM entity_bucket_counts"
        ).fetchone()[0]
        after_events = connection.execute(
            "SELECT COUNT(*) FROM parsed_events"
        ).fetchone()[0]
        run_row = connection.execute(
            """
            SELECT params_json FROM pipeline_runs
            WHERE stage = 'detect-statistical'
            ORDER BY started_at DESC LIMIT 1
            """
        ).fetchone()
        score_times = connection.execute(
            """
            SELECT window_start FROM statistical_window_scores
            """
        ).fetchall()
        params = json.loads(run_row[0])
    finally:
        connection.close()

    assert after_buckets == before_buckets
    assert after_events == before_events
    assert params["analysis_window"]["enabled"] is True
    assert params["analysis_window"]["mode"] == "last_days"
    assert params["analysis_window"]["last_days"] == 2

    window_start = datetime.fromisoformat(params["analysis_window"]["start_utc"])
    if window_start.tzinfo is not None:
        window_start_naive = window_start.astimezone(UTC).replace(tzinfo=None)
    else:
        window_start_naive = window_start
    for (ws,) in score_times:
        assert isinstance(ws, datetime)
        cmp = ws.replace(tzinfo=None) if ws.tzinfo is not None else ws
        assert cmp >= window_start_naive


def test_disabled_matches_no_filter_clause(tmp_path: Path) -> None:
    config = _base_config(tmp_path)
    connection = get_connection(config)
    try:
        window = resolve_analysis_window(config, connection)
        sql, params = bucket_series_sql(window)
    finally:
        connection.close()
    assert window is None
    assert "WHERE" not in sql.upper().split("FROM", 1)[-1].split("ORDER", 1)[0]
    assert params == []


def test_api_exposes_analysis_window_fields(tmp_path: Path) -> None:
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from src.api.main import create_app
    from tests.test_api_dashboard import _seed_empty_warehouse

    config = _base_config(tmp_path)
    config["sharding"]["analysis_window"] = {
        "enabled": True,
        "last_days": 14,
        "start_utc": None,
        "end_utc": None,
    }
    config["pipeline_ui"] = {
        "upload_dir": str(Path(config["paths"]["raw_log_dir"]) / "uploads"),
        "max_upload_bytes": 52_428_800,
        "max_files_per_request": 50,
        "allowed_suffixes": [".log"],
    }
    Path(config["pipeline_ui"]["upload_dir"]).mkdir(parents=True, exist_ok=True)
    _seed_empty_warehouse(config)
    client = TestClient(create_app(_write_config(tmp_path, config)))
    body = client.get("/api/v1/pipeline/sharding").json()
    assert body["analysis_window_enabled"] is True
    assert body["analysis_window_last_days"] == 14
