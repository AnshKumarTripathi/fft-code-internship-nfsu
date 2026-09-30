"""Synthetic entity time series for spectral detector tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np

UTC = timezone.utc


def generate_periodic_counts(
    *,
    n_buckets: int,
    period_buckets: int,
    amplitude: float = 1.0,
    bucket_seconds: int = 600,
    base_time: datetime | None = None,
) -> tuple[list[datetime], np.ndarray]:
    """Build dense periodic bucket counts and aligned UTC timestamps."""
    if n_buckets <= 0:
        return [], np.array([], dtype=np.float64)
    if period_buckets <= 0:
        raise ValueError("period_buckets must be positive")

    start = base_time or datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    bucket_starts = [
        start + timedelta(seconds=bucket_seconds * i) for i in range(n_buckets)
    ]
    phase = np.arange(n_buckets, dtype=np.float64)
    counts = amplitude * (0.5 + 0.5 * np.sin(2 * np.pi * phase / period_buckets))
    return bucket_starts, counts.astype(np.float64)


def inject_rhythm_attack(
    counts: np.ndarray,
    *,
    start: int,
    length: int,
    new_period_buckets: int,
) -> np.ndarray:
    """Replace a segment with a different periodic rhythm (copy returned)."""
    if new_period_buckets <= 0:
        raise ValueError("new_period_buckets must be positive")
    attacked = counts.copy()
    end = min(start + length, len(attacked))
    segment_len = end - start
    if segment_len <= 0:
        return attacked
    phase = np.arange(segment_len, dtype=np.float64)
    attacked[start:end] = 0.5 + 0.5 * np.sin(
        2 * np.pi * phase / new_period_buckets
    )
    return attacked
