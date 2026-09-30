"""R5: frozen Drain3/ML snapshots, stable event_id, ingest_row_id, cluster/ML manifest."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from src.db.connection import get_connection
from src.detectors.ml.isolation_forest import (
    IsolationBundle,
    TemplateWindow,
    fit_isolation_bundle,
    score_windows_with_bundle,
)
from src.detectors.ml.persist import run_detect_ml
from src.detectors.ml.snapshots import load_ml_snapshot, save_ml_snapshot
from src.detectors.spectral.persist import NothingToCluster, run_cluster
from src.ingestion.persist import ingest_staging_dir, run_ingest
from src.parsing.persist import ParseError, run_parse
from src.parsing.snapshots import EMPTY_PARSER_SNAPSHOT_ID

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


def _params_json(connection, stage: str) -> dict:
    row = connection.execute(
        """
        SELECT params_json FROM pipeline_runs
        WHERE stage = ? AND status = 'success'
        ORDER BY started_at DESC LIMIT 1
        """,
        [stage],
    ).fetchone()
    assert row is not None
    payload = row[0]
    if isinstance(payload, str):
        payload = json.loads(payload)
    assert isinstance(payload, dict)
    return payload


def _event_pairs(connection) -> list[tuple]:
    return connection.execute(
        """
        SELECT event_id, template_id, entity_id
        FROM parsed_events
        ORDER BY event_id, template_id, entity_id
        """
    ).fetchall()


def _staging_ingest_ids(config: dict) -> list[str]:
    parts = sorted((ingest_staging_dir(config)).glob("*.parquet"))
    assert parts
    frame = pd.concat([pd.read_parquet(path) for path in parts], ignore_index=True)
    return sorted(str(value) for value in frame["ingest_row_id"].tolist())


def test_reuse_parser_snapshot_keeps_template_and_event_ids(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["parse"] = {
        "mode": "train_and_snapshot",
        "start_empty": True,
        "snapshot_id": None,
    }
    run_ingest(config, config_path=config_path)
    trained = run_parse(config, config_path=config_path)
    assert trained.parser_snapshot_id == EMPTY_PARSER_SNAPSHOT_ID
    assert trained.parser_trained_snapshot_id
    assert trained.events_written > 0

    connection = get_connection(config)
    try:
        parse_params = _params_json(connection, "parse")
        assert parse_params["manifest"]["parser_snapshot_id"] == EMPTY_PARSER_SNAPSHOT_ID
        assert parse_params["manifest"]["parser_trained_snapshot_id"] == (
            trained.parser_trained_snapshot_id
        )
    finally:
        connection.close()

    config["parse"] = {
        "mode": "reuse_snapshot",
        "start_empty": False,
        "snapshot_id": trained.parser_trained_snapshot_id,
    }
    run_parse(config, config_path=config_path)
    connection = get_connection(config)
    try:
        first_reuse = _event_pairs(connection)
        assert first_reuse
    finally:
        connection.close()

    run_parse(config, config_path=config_path)
    connection = get_connection(config)
    try:
        second_reuse = _event_pairs(connection)
        assert second_reuse == first_reuse
        reuse_params = _params_json(connection, "parse")
        assert (
            reuse_params["manifest"]["parser_snapshot_id"]
            == trained.parser_trained_snapshot_id
        )
        snapshot_ids = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT parser_snapshot_id FROM parsed_events"
            ).fetchall()
        }
        assert snapshot_ids == {trained.parser_trained_snapshot_id}
    finally:
        connection.close()


def test_reuse_snapshot_requires_snapshot_id(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["parse"] = {"mode": "reuse_snapshot", "snapshot_id": None}
    run_ingest(config, config_path=config_path)
    with pytest.raises(ParseError, match="snapshot_id"):
        run_parse(config, config_path=config_path)


def test_ingest_row_id_stable_until_file_bytes_change(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    first_ids = _staging_ingest_ids(config)
    assert first_ids
    run_ingest(config, config_path=config_path)
    assert _staging_ingest_ids(config) == first_ids

    raw = Path(config["paths"]["raw_log_dir"]) / "auth.log"
    raw.write_bytes(raw.read_bytes() + b"\n# mutated\n")
    run_ingest(config, config_path=config_path)
    mutated_ids = _staging_ingest_ids(config)
    assert mutated_ids
    assert mutated_ids != first_ids


def _ml_windows() -> list[TemplateWindow]:
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    normal = tuple(["A", "B"] * 10)
    windows: list[TemplateWindow] = []
    for i in range(24):
        windows.append(
            TemplateWindow(
                entity_id="normal",
                window_start=start + timedelta(hours=i),
                window_end=start + timedelta(hours=i + 1),
                template_ids=normal,
            )
        )
    return windows


def test_ml_snapshot_reuse_without_refit(tmp_path: Path) -> None:
    windows = _ml_windows()
    fitted = fit_isolation_bundle(windows, contamination=0.05)
    assert fitted is not None
    bundle, raw_scores, predictions = fitted
    snapshot_id = save_ml_snapshot(tmp_path / "baselines", bundle)
    loaded = load_ml_snapshot(tmp_path / "baselines", snapshot_id)
    assert isinstance(loaded, IsolationBundle)
    rows = score_windows_with_bundle(
        windows,
        loaded,
        model_snapshot_id=snapshot_id,
        raw_scores=raw_scores,
        predictions=predictions,
    )
    assert rows
    assert all(row.model_snapshot_id == snapshot_id for row in rows)
    again = score_windows_with_bundle(windows, loaded, model_snapshot_id=snapshot_id)
    assert [row.model_score for row in again] == [row.model_score for row in rows]


def _seed_ml_events(config: dict, *, n_windows: int = 12) -> None:
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
        for tid in ("t_a", "t_b"):
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
        event_id = 1
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        for w in range(n_windows):
            window_start = start + timedelta(hours=w)
            templates = ["t_a", "t_b"] * 5
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


def test_detect_ml_records_model_snapshot_on_manifest(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    run_ingest(config, config_path=config_path)
    run_parse(config, config_path=config_path)
    _seed_ml_events(config)

    config["ml"]["mode"] = "refit_and_snapshot"
    first = run_detect_ml(config, config_path=config_path)
    assert first.model_snapshot_id
    assert first.windows_total > 0

    connection = get_connection(config)
    try:
        params = _params_json(connection, "detect-ml")
        assert params["manifest"]["model_snapshot_id"] == first.model_snapshot_id
        assert params["manifest"]["onnx_model_hash"] is None
        stored = connection.execute(
            "SELECT DISTINCT model_snapshot_id FROM ml_window_scores"
        ).fetchall()
        assert stored == [(first.model_snapshot_id,)]
    finally:
        connection.close()

    config["ml"]["mode"] = "reuse_snapshot"
    config["ml"]["snapshot_id"] = first.model_snapshot_id
    reused = run_detect_ml(config, config_path=config_path)
    assert reused.model_snapshot_id == first.model_snapshot_id


def test_cluster_run_id_on_manifest_is_stable(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    with pytest.raises(NothingToCluster, match="nothing to cluster"):
        run_cluster(config, config_path=config_path)
    connection = get_connection(config)
    try:
        first = _params_json(connection, "cluster")["manifest"]["cluster_run_id"]
        assert first
    finally:
        connection.close()
    with pytest.raises(NothingToCluster, match="nothing to cluster"):
        run_cluster(config, config_path=config_path)
    connection = get_connection(config)
    try:
        second = _params_json(connection, "cluster")["manifest"]["cluster_run_id"]
        assert second == first
    finally:
        connection.close()
