"""Phase 61 seasonal residual math + pipeline smoke tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from src.db.connection import get_connection
from src.detectors.seasonal.persist import SeasonalError, run_detect_seasonal
from src.detectors.seasonal.residual import score_seasonal_windows
from src.correlation.merge_scores import discover_and_merge
from src.explainability.payload import ExplainMergeSettings


def _starts(n: int, bucket_seconds: int = 600) -> list[datetime]:
    origin = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return [origin + timedelta(seconds=bucket_seconds * i) for i in range(n)]


def test_seasonal_soft_skip_short_series() -> None:
    starts = _starts(100)
    rows = score_seasonal_windows(
        starts,
        [1.0] * 100,
        600,
        entity_id="short",
        period_buckets=144,
        min_history_buckets=288,
        z_threshold=4.0,
    )
    assert rows == []


def test_seasonal_quiet_on_pure_seasonal() -> None:
    period = 24
    n = period * 4
    base = np.tile(np.linspace(1.0, 5.0, period), 4)
    rows = score_seasonal_windows(
        _starts(n),
        base.tolist(),
        600,
        entity_id="quiet",
        period_buckets=period,
        min_history_buckets=period * 2,
        z_threshold=4.0,
    )
    assert rows == []


def test_seasonal_flags_schedule_residual() -> None:
    period = 24
    n = period * 4
    base = np.tile(np.linspace(1.0, 5.0, period), 4).astype(np.float64)
    # Spike at a phase that is usually low → residual high.
    base[period * 3 + 2] = 80.0
    rows = score_seasonal_windows(
        _starts(n),
        base.tolist(),
        600,
        entity_id="spike",
        period_buckets=period,
        min_history_buckets=period * 2,
        z_threshold=4.0,
    )
    assert rows
    assert all(row.flagged for row in rows)
    assert any(row.direction == "high" for row in rows)
    assert any(abs(row.residual_z) >= 4.0 for row in rows)


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
        "seasonal": {
            "enabled": True,
            "period_buckets": 24,
            "min_history_buckets": 48,
            "z_threshold": 4.0,
        },
        "orchestration": {"parallel_backend": "none", "n_workers": 1},
    }


def test_detect_seasonal_pipeline_and_merge(tmp_path: Path) -> None:
    config = _config(tmp_path)
    conn = get_connection(config)
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    period = 24
    n = period * 4
    try:
        conn.execute(
            """
            INSERT INTO entities (entity_id, entity_type, first_seen, last_seen, label)
            VALUES ('carol', 'user', ?, ?, 'Carol')
            """,
            [start, start],
        )
        counts = np.tile(np.linspace(1.0, 5.0, period), 4).astype(np.float64)
        counts[period * 3 + 2] = 90.0
        for index, count in enumerate(counts.tolist()):
            conn.execute(
                """
                INSERT INTO entity_bucket_counts
                (entity_id, bucket_start, bucket_seconds, event_count)
                VALUES ('carol', ?, 600, ?)
                """,
                [start + timedelta(seconds=600 * index), float(count)],
            )
    finally:
        conn.close()

    summary = run_detect_seasonal(config)
    assert summary.entities_scored >= 1
    assert summary.windows_flagged >= 1

    conn = get_connection(config)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM seasonal_window_scores WHERE flagged = TRUE"
        ).fetchone()[0]
        assert int(count) >= 1
        result = discover_and_merge(
            conn,
            explain=ExplainMergeSettings(
                seasonal_z_threshold=4.0, seasonal_period_buckets=24
            ),
        )
        assert "seasonal" in result.discovered_sources
        seasonal = [a for a in result.anomalies if a.source_detector == "seasonal"]
        assert seasonal
        assert seasonal[0].metadata.get("rule") == "|residual_z| >= z_threshold"
    finally:
        conn.close()


def test_detect_seasonal_empty_buckets(tmp_path: Path) -> None:
    config = _config(tmp_path)
    conn = get_connection(config)
    conn.close()
    with pytest.raises(SeasonalError, match="run bucket first"):
        run_detect_seasonal(config)


def test_seasonal_config_validation() -> None:
    from src.config import ConfigError, _validate_seasonal_settings

    settings = {
        "enabled": True,
        "period_buckets": 144,
        "min_history_buckets": 288,
        "z_threshold": 0,
    }
    with pytest.raises(ConfigError, match="z_threshold"):
        _validate_seasonal_settings(settings)
