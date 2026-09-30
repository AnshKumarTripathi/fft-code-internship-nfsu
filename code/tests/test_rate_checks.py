"""Unit tests for score_rate_windows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.detectors.statistical.rate_checks import MIN_WINDOWS, score_rate_windows

UTC = timezone.utc
ENTITY = "alice"
BUCKET_SECONDS = 600
WINDOW_BUCKETS = 6
Z_THRESHOLD = 4.0
BASE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)


def _make_series(counts: list[float]) -> tuple[list[datetime], list[float]]:
    starts = [BASE + timedelta(seconds=BUCKET_SECONDS * i) for i in range(len(counts))]
    return starts, counts


def _baseline_counts(n: int, value: float = 1.0) -> list[float]:
    return [value] * n


def test_insufficient_history_returns_empty() -> None:
    starts, counts = _make_series(_baseline_counts(MIN_WINDOWS - 1))
    assert (
        score_rate_windows(
            starts,
            counts,
            BUCKET_SECONDS,
            entity_id=ENTITY,
            window_buckets=WINDOW_BUCKETS,
            z_threshold=Z_THRESHOLD,
        )
        == []
    )


def test_mad_zero_constant_counts() -> None:
    n = MIN_WINDOWS + WINDOW_BUCKETS - 1
    starts, counts = _make_series(_baseline_counts(n, value=2.0))
    rows = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert rows
    assert all(row.rate_z == 0.0 for row in rows)
    assert all(not row.flagged for row in rows)


def test_burst_synthetic_flags_near_spike() -> None:
    n = MIN_WINDOWS + WINDOW_BUCKETS + 10
    counts = [1.0 + (i % 5) for i in range(n)]
    spike_center = n // 2
    counts[spike_center] = 500.0
    starts, _ = _make_series(counts)
    rows = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=2.0,
    )
    flagged = [row for row in rows if row.flagged]
    assert flagged
    flagged_indices = [i for i, row in enumerate(rows) if row.flagged]
    spike_window_start = max(0, spike_center - (WINDOW_BUCKETS - 1))
    spike_window_end = spike_center
    assert any(
        spike_window_start <= i <= spike_window_end for i in flagged_indices
    )


def test_quiet_flat_mostly_unflagged() -> None:
    n = MIN_WINDOWS + WINDOW_BUCKETS + 5
    counts = _baseline_counts(n, value=1.0)
    starts, _ = _make_series(counts)
    rows = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert rows
    assert sum(1 for row in rows if row.flagged) == 0


def test_lower_threshold_increases_flags() -> None:
    n = MIN_WINDOWS + WINDOW_BUCKETS + 10
    counts = _baseline_counts(n, value=1.0)
    counts[n // 2] = 15.0
    starts, _ = _make_series(counts)
    strict = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    loose = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=1.0,
    )
    assert sum(1 for row in loose if row.flagged) >= sum(
        1 for row in strict if row.flagged
    )


def test_window_boundaries() -> None:
    n = MIN_WINDOWS + WINDOW_BUCKETS
    starts, counts = _make_series(_baseline_counts(n))
    rows = score_rate_windows(
        starts,
        counts,
        BUCKET_SECONDS,
        entity_id=ENTITY,
        window_buckets=WINDOW_BUCKETS,
        z_threshold=Z_THRESHOLD,
    )
    assert rows
    row = rows[0]
    expected_duration = timedelta(seconds=WINDOW_BUCKETS * BUCKET_SECONDS)
    assert row.window_end - row.window_start == expected_duration


@pytest.mark.parametrize("window_buckets", [0, -1])
def test_invalid_window_buckets(window_buckets: int) -> None:
    starts, counts = _make_series(_baseline_counts(MIN_WINDOWS + 5))
    with pytest.raises(ValueError, match="window_buckets must be positive"):
        score_rate_windows(
            starts,
            counts,
            BUCKET_SECONDS,
            entity_id=ENTITY,
            window_buckets=window_buckets,
            z_threshold=Z_THRESHOLD,
        )
