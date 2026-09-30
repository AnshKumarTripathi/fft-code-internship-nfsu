"""Phase 14 IsolationForest flagging policy tests."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.config import ConfigError, ml_settings
from src.db.connection import get_connection
from src.detectors.ml.isolation_forest import TemplateWindow, apply_ml_flagging, fit_score_windows
from src.detectors.ml.persist import MlError, run_detect_ml

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"
CODE_ROOT = Path(__file__).resolve().parents[1]
DRAIN3_INI = CODE_ROOT / "config" / "drain3.ini"
UTC = timezone.utc


def _window(index: int, templates: tuple[str, ...], entity: str = "alice") -> TemplateWindow:
    start = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(hours=index)
    return TemplateWindow(
        entity_id=entity,
        window_start=start,
        window_end=start + timedelta(hours=1),
        template_ids=templates,
    )


def test_quiet_periodic_mad_threshold_does_not_force_two_percent() -> None:
    periodic = tuple(["A", "B"] * 10)
    windows = [_window(i, periodic) for i in range(80)]
    scores = fit_score_windows(windows, contamination=0.02, flagging="mad_threshold")
    flagged = sum(1 for row in scores if row.flagged)
    fraction = flagged / len(scores)
    assert flagged == 0
    assert abs(fraction - 0.02) > 0.01


def test_predict_contamination_flags_about_two_percent() -> None:
    periodic = tuple(["A", "B"] * 10)
    rare = tuple(["X", "Y", "Z", "Q", "R"] * 4)
    windows = [_window(i, periodic) for i in range(98)]
    windows.append(_window(98, rare, entity="weird"))
    windows.append(_window(99, rare, entity="weird"))
    scores = fit_score_windows(
        windows, contamination=0.02, flagging="predict"
    )
    flagged = sum(1 for row in scores if row.flagged)
    # sklearn may tie around the contamination cutoff.
    assert 1 <= flagged <= 4


def test_score_threshold_without_threshold_raises() -> None:
    with pytest.raises(ValueError, match="score_threshold"):
        apply_ml_flagging([0.1, 0.2], flagging="score_threshold", score_threshold=None)

    with pytest.raises(ConfigError, match="score_threshold"):
        ml_settings({"ml": {"flagging": "score_threshold", "score_threshold": None}})


def test_apply_ml_flagging_none_and_score_threshold() -> None:
    assert apply_ml_flagging([9.0, 0.1], flagging="none") == [False, False]
    assert apply_ml_flagging(
        [0.1, 0.9], flagging="score_threshold", score_threshold=0.5
    ) == [False, True]
    assert apply_ml_flagging(
        [1.0, 1.0, 1.0], flagging="mad_threshold", mad_k=4.0
    ) == [False, False, False]


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
            "flagging": "mad_threshold",
            "min_windows_to_fit": 20,
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


def _seed_windows(config: dict, n_windows: int) -> None:
    connection = get_connection(config)
    try:
        connection.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen)
            VALUES ('mltest', 'user', ?, ?)
            ON CONFLICT (entity_id) DO NOTHING
            """,
            [
                datetime(2024, 1, 1, tzinfo=UTC),
                datetime(2024, 1, 2, tzinfo=UTC),
            ],
        )
        connection.execute(
            """
            INSERT INTO templates (
                template_id, template_string, first_seen, last_seen, occurrence_count
            )
            VALUES ('t_a', 'template t_a', ?, ?, 1)
            ON CONFLICT (template_id) DO NOTHING
            """,
            [datetime(2024, 1, 1, tzinfo=UTC), datetime(2024, 1, 1, tzinfo=UTC)],
        )
        next_id = connection.execute(
            "SELECT COALESCE(MAX(event_id), 0) + 1 FROM parsed_events"
        ).fetchone()[0]
        event_id = int(next_id)
        start = datetime(2024, 1, 1, tzinfo=UTC)
        for w in range(n_windows):
            window_start = start + timedelta(hours=w)
            for i in range(6):
                ts = window_start + timedelta(seconds=i * 10)
                connection.execute(
                    """
                    INSERT INTO parsed_events (
                        event_id, entity_id, template_id, event_timestamp,
                        log_source, raw_fields, ingested_at
                    )
                    VALUES (?, 'mltest', 't_a', ?, 'ssh', '{}'::JSON, ?)
                    """,
                    [event_id, ts, ts],
                )
                event_id += 1
    finally:
        connection.close()


def test_min_windows_to_fit_skips_without_crash(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    _seed_windows(config, n_windows=5)

    summary = run_detect_ml(config, config_path=config_path)
    assert summary.skipped_min_windows is True
    assert summary.windows_total == 0
    assert summary.windows_flagged == 0

    connection = get_connection(config)
    try:
        count = connection.execute("SELECT COUNT(*) FROM ml_window_scores").fetchone()[0]
        assert int(count) == 0
        run_row = connection.execute(
            """
            SELECT status, params_json
            FROM pipeline_runs
            WHERE stage = 'detect-ml'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
        assert run_row[0] == "success"
        assert "skipped_min_windows" in str(run_row[1])
    finally:
        connection.close()


def test_score_threshold_flagging_without_threshold_is_ml_error(tmp_path: Path) -> None:
    config = _temp_config(tmp_path)
    config_path = config.pop("_config_path")
    config["ml"]["flagging"] = "score_threshold"
    config["ml"]["score_threshold"] = None
    with pytest.raises(MlError, match="score_threshold"):
        run_detect_ml(config, config_path=config_path)
