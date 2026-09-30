"""Seasonal residual detector on per-bucket event counts (Phase 61).

Builds a classical seasonal profile (median per phase of ``period_buckets``),
subtracts it from the series, and flags robust-z outliers on the residual.
Does not replace spectral or changepoint.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

import numpy as np

from src.detectors.robust_z import robust_z_scores

DEFAULT_PERIOD_BUCKETS = 144  # 24h at 600s
DEFAULT_MIN_HISTORY_BUCKETS = 288  # ≥ 2 seasonal periods
DEFAULT_Z_THRESHOLD = 4.0


@dataclass(frozen=True)
class SeasonalWindowScore:
    entity_id: str
    window_start: datetime
    window_end: datetime
    residual_z: float
    residual: float
    seasonal_level: float
    flagged: bool
    direction: str


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def effective_min_history(period_buckets: int, min_history_buckets: int) -> int:
    """Require at least two full seasonal periods (and the configured floor)."""
    return max(int(min_history_buckets), 2 * int(period_buckets))


def score_seasonal_windows(
    bucket_starts: Sequence[datetime],
    event_counts: Sequence[float],
    bucket_seconds: int,
    *,
    entity_id: str,
    period_buckets: int = DEFAULT_PERIOD_BUCKETS,
    min_history_buckets: int = DEFAULT_MIN_HISTORY_BUCKETS,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
) -> list[SeasonalWindowScore]:
    """Flag residual outliers vs a median seasonal profile.

    Entities shorter than ``max(min_history_buckets, 2 * period_buckets)``
    return ``[]``. Consecutive flagged buckets merge into one window.
    """
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")
    if period_buckets < 2:
        raise ValueError("period_buckets must be an integer >= 2")
    if min_history_buckets < 1:
        raise ValueError("min_history_buckets must be a positive integer")
    if z_threshold <= 0:
        raise ValueError("z_threshold must be positive")
    if len(bucket_starts) != len(event_counts):
        raise ValueError("bucket_starts and event_counts must have equal length")

    n_buckets = len(event_counts)
    need = effective_min_history(period_buckets, min_history_buckets)
    if n_buckets < need:
        return []

    counts = np.asarray(event_counts, dtype=np.float64)
    if counts.size == 0 or not bool(np.all(np.isfinite(counts))):
        return []

    profile = np.full(period_buckets, np.nan, dtype=np.float64)
    for phase in range(period_buckets):
        phase_vals = counts[phase::period_buckets]
        if phase_vals.size == 0:
            continue
        profile[phase] = float(np.median(phase_vals))
    # Fill any empty phase with global median so residuals stay finite.
    global_med = float(np.median(counts))
    profile = np.where(np.isfinite(profile), profile, global_med)

    phases = np.arange(n_buckets) % period_buckets
    seasonal = profile[phases]
    residuals = counts - seasonal
    z_scores = robust_z_scores(residuals.tolist())

    flagged_buckets: list[tuple[datetime, datetime, float, float, float, str]] = []
    for index, (start, residual, z, season) in enumerate(
        zip(bucket_starts, residuals, z_scores, seasonal, strict=True)
    ):
        if not isinstance(start, datetime):
            continue
        z_f = float(z)
        if not np.isfinite(z_f) or abs(z_f) < z_threshold:
            continue
        direction = "high" if z_f >= 0.0 else "low"
        window_end = start + timedelta(seconds=bucket_seconds)
        flagged_buckets.append(
            (
                _ensure_utc(start),
                _ensure_utc(window_end),
                z_f,
                float(residual),
                float(season),
                direction,
            )
        )

    return _merge_consecutive_flags(entity_id, flagged_buckets)


def _merge_consecutive_flags(
    entity_id: str,
    flagged_buckets: list[tuple[datetime, datetime, float, float, float, str]],
) -> list[SeasonalWindowScore]:
    if not flagged_buckets:
        return []

    rows: list[SeasonalWindowScore] = []
    run_start, run_end, z, residual, season, direction = flagged_buckets[0]
    for start, end, next_z, next_res, next_season, next_dir in flagged_buckets[1:]:
        if start <= run_end:
            run_end = max(run_end, end)
            if abs(next_z) >= abs(z):
                z = next_z
                residual = next_res
                season = next_season
                direction = next_dir
            continue
        rows.append(
            SeasonalWindowScore(
                entity_id=entity_id,
                window_start=run_start,
                window_end=run_end,
                residual_z=z,
                residual=residual,
                seasonal_level=season,
                flagged=True,
                direction=direction,
            )
        )
        run_start, run_end, z, residual, season, direction = (
            start,
            end,
            next_z,
            next_res,
            next_season,
            next_dir,
        )
    rows.append(
        SeasonalWindowScore(
            entity_id=entity_id,
            window_start=run_start,
            window_end=run_end,
            residual_z=z,
            residual=residual,
            seasonal_level=season,
            flagged=True,
            direction=direction,
        )
    )
    return rows
