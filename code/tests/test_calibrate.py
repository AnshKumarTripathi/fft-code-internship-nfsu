"""Tests for Phase 50 threshold calibration and iou_0_1 overlap."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.db.connection import get_connection
from src.evaluation.calibrate import (
    DEFAULT_THRESHOLD,
    ScoredWindow,
    detections_at_threshold,
    run_calibration,
)
from src.evaluation.labels import EvaluationError, LabelRow
from src.evaluation.metrics import (
    Detection,
    interval_iou,
    score_detections,
    windows_match,
)

UTC = timezone.utc
BASE = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
DEMO_LABELS = (
    Path(__file__).resolve().parent / "fixtures" / "labels" / "demo_eval.csv"
)


def _naive_utc(ts: datetime) -> datetime:
    return ts.astimezone(UTC).replace(tzinfo=None)


def _config(tmp_path: Path, labels_path: str | None) -> dict:
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
        "orchestration": {"parallel_backend": "none", "n_workers": 1},
        "evaluation": {
            "labels_path": labels_path,
            "output_dir": str(tmp_path / "eval_out"),
            "overlap_rule": "any",
            "write_entity_labels": False,
        },
    }


def _seed_entity(connection, entity_id: str) -> None:
    ts = _naive_utc(datetime(2024, 1, 1, tzinfo=UTC))
    connection.execute(
        """
        INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
        VALUES (?, 'user', ?, ?, NULL)
        ON CONFLICT (entity_id) DO NOTHING
        """,
        [entity_id, ts, ts],
    )


def test_interval_iou_partial_overlap() -> None:
    a0 = datetime(2024, 1, 1, 10, 0, tzinfo=UTC)
    a1 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    b0 = datetime(2024, 1, 1, 11, 0, tzinfo=UTC)
    b1 = datetime(2024, 1, 1, 13, 0, tzinfo=UTC)
    # intersection 1h, union 3h → IoU = 1/3
    assert abs(interval_iou(a0, a1, b0, b1) - (1.0 / 3.0)) < 1e-9


def test_iou_0_1_rejects_tiny_touch() -> None:
    label_start = BASE
    label_end = BASE + timedelta(hours=10)
    # 1-minute touch at the start → IoU = 60 / (10h + 1m - 1m) seconds ≈ 60/36000 = 0.0017
    det_start = BASE
    det_end = BASE + timedelta(minutes=1)
    assert windows_match(
        label_start, label_end, det_start, det_end, overlap_rule="any"
    )
    assert not windows_match(
        label_start, label_end, det_start, det_end, overlap_rule="iou_0_1"
    )


def test_iou_0_1_accepts_substantial_overlap() -> None:
    label_start = BASE
    label_end = BASE + timedelta(hours=1)
    det_start = BASE
    det_end = BASE + timedelta(hours=1)
    assert windows_match(
        label_start, label_end, det_start, det_end, overlap_rule="iou_0_1"
    )
    metrics = score_detections(
        [
            LabelRow(
                entity_id="alice",
                label="attacker",
                window_start=label_start,
                window_end=label_end,
                attack_type=None,
            )
        ],
        [Detection("alice", det_start, det_end)],
        overlap_rule="iou_0_1",
    )
    assert metrics.tp == 1
    assert metrics.fn == 0


def test_detections_at_threshold_statistical() -> None:
    windows = [
        ScoredWindow("alice", BASE, BASE + timedelta(hours=1), rate_z=3.2),
        ScoredWindow("alice", BASE, BASE + timedelta(hours=1), rate_z=4.5),
    ]
    at_4 = detections_at_threshold("statistical", windows, 4.0)
    assert len(at_4) == 1
    at_3 = detections_at_threshold("statistical", windows, 3.0)
    assert len(at_3) == 2


def test_detections_at_threshold_spectral_or() -> None:
    windows = [
        ScoredWindow(
            "web-01",
            BASE,
            BASE + timedelta(hours=1),
            energy_z=2.0,
            shape_js_z=5.0,
        ),
        ScoredWindow(
            "web-01",
            BASE,
            BASE + timedelta(hours=1),
            energy_z=1.0,
            shape_js_z=1.0,
        ),
    ]
    flagged = detections_at_threshold("spectral", windows, 4.0)
    assert len(flagged) == 1


def test_run_calibration_writes_artifact(tmp_path: Path) -> None:
    labels_path = tmp_path / "labels.csv"
    labels_path.write_text(
        "entity_id,window_start,window_end,label,attack_type\n"
        "alice,2024-01-01T10:00:00Z,2024-01-01T11:00:00Z,attacker,bruteforce\n"
        "charlie,,,benign,\n",
        encoding="utf-8",
    )
    config = _config(tmp_path, labels_path=str(labels_path))
    connection = get_connection(config)
    try:
        _seed_entity(connection, "alice")
        _seed_entity(connection, "charlie")
        connection.execute(
            """
            INSERT INTO statistical_window_scores
                (entity_id, window_start, window_end, rate_z, flagged)
            VALUES
                ('alice', ?, ?, 6.0, TRUE),
                ('alice', ?, ?, 3.2, FALSE),
                ('charlie', ?, ?, 5.0, TRUE)
            """,
            [
                _naive_utc(BASE),
                _naive_utc(BASE + timedelta(hours=1)),
                _naive_utc(BASE + timedelta(hours=2)),
                _naive_utc(BASE + timedelta(hours=3)),
                _naive_utc(BASE),
                _naive_utc(BASE + timedelta(hours=1)),
            ],
        )
    finally:
        connection.close()

    summary = run_calibration(config, taus=(3.0, 4.0, 5.0))
    assert Path(summary.output_json_path).is_file()
    assert Path(summary.output_md_path).is_file()
    payload = json.loads(Path(summary.output_json_path).read_text(encoding="utf-8"))
    assert payload["phase"] == 50
    assert "statistical" in payload["detectors"]
    assert "4.0" in payload["detectors"]["statistical"]["by_tau"]
    assert payload["decision"]["yaml_defaults_unchanged"] is True
    assert DEFAULT_THRESHOLD == 4.0


def test_run_calibration_requires_scores(tmp_path: Path) -> None:
    labels_path = tmp_path / "labels.csv"
    labels_path.write_text(
        "entity_id,window_start,window_end,label,attack_type\n"
        "alice,,,attacker,\n",
        encoding="utf-8",
    )
    config = _config(tmp_path, labels_path=str(labels_path))
    get_connection(config).close()
    with pytest.raises(EvaluationError, match="window scores"):
        run_calibration(config)
