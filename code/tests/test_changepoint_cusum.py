"""Unit tests for two-sided CUSUM (Phase 52)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detectors.changepoint.cusum import score_cusum_windows

UTC = timezone.utc
BASE = datetime(2024, 1, 1, tzinfo=UTC)
BUCKET_SECONDS = 600


def _series(counts: list[float]) -> tuple[list[datetime], list[float]]:
    starts = [BASE + timedelta(seconds=BUCKET_SECONDS * i) for i in range(len(counts))]
    return starts, counts


def test_cusum_skips_short_history() -> None:
    starts, counts = _series([10.0] * 20)
    assert score_cusum_windows(
        starts, counts, BUCKET_SECONDS, entity_id="alice"
    ) == []


def test_cusum_quiet_on_stationary_counts() -> None:
    starts, counts = _series([10.0 + (i % 3 - 1) for i in range(80)])
    rows = score_cusum_windows(
        starts, counts, BUCKET_SECONDS, entity_id="alice"
    )
    assert rows == []


def test_cusum_flags_mean_jump() -> None:
    baseline = [10.0 + (i % 3 - 1) for i in range(48)]
    shifted = [40.0] * 32
    starts, counts = _series(baseline + shifted)
    rows = score_cusum_windows(
        starts, counts, BUCKET_SECONDS, entity_id="alice"
    )
    assert rows
    assert all(row.flagged for row in rows)
    assert any(row.direction == "up" for row in rows)
    assert rows[0].window_start >= starts[48]


def test_cusum_flags_volume_drop() -> None:
    baseline = [20.0 + (i % 3 - 1) for i in range(48)]
    dropped = [1.0] * 32
    starts, counts = _series(baseline + dropped)
    rows = score_cusum_windows(
        starts, counts, BUCKET_SECONDS, entity_id="alice"
    )
    assert rows
    assert any(row.direction == "down" for row in rows)
