"""Two-sided tabular CUSUM on per-bucket event counts (Phase 52).

Catches persistent mean level shifts (volume jumps and stealth drops) that
the one-sided statistical rate window can miss. Does not replace FFT.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

import numpy as np

from src.detectors.robust_z import MAD_TO_STD_CONSTANT, ROBUST_Z_EPSILON

DEFAULT_MIN_HISTORY_BUCKETS = 48
DEFAULT_BASELINE_BUCKETS = 48
DEFAULT_DRIFT_K = 0.5
DEFAULT_DECISION_H = 5.0


@dataclass(frozen=True)
class ChangepointWindowScore:
    entity_id: str
    window_start: datetime
    window_end: datetime
    cusum_high: float
    cusum_low: float
    flagged: bool
    direction: str


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _robust_location_scale(values: Sequence[float]) -> tuple[float, float]:
    arr = np.asarray(values, dtype=np.float64)
    mu = float(np.median(arr))
    mad = float(np.median(np.abs(arr - mu)))
    if mad > 0.0:
        sigma = mad / MAD_TO_STD_CONSTANT
    else:
        sigma = float(np.std(arr))
        if sigma <= ROBUST_Z_EPSILON:
            sigma = ROBUST_Z_EPSILON
    return mu, max(sigma, ROBUST_Z_EPSILON)


def score_cusum_windows(
    bucket_starts: Sequence[datetime],
    event_counts: Sequence[float],
    bucket_seconds: int,
    *,
    entity_id: str,
    min_history_buckets: int = DEFAULT_MIN_HISTORY_BUCKETS,
    baseline_buckets: int = DEFAULT_BASELINE_BUCKETS,
    drift_k: float = DEFAULT_DRIFT_K,
    decision_h: float = DEFAULT_DECISION_H,
) -> list[ChangepointWindowScore]:
    """Score a two-sided CUSUM and collapse consecutive flags into windows.

    Baseline ``mu`` / MAD-sigma come from the first ``baseline_buckets``
    samples. Scoring starts after that warm-up (cold start). Entities shorter
    than ``min_history_buckets`` return ``[]``. Consecutive flagged buckets
    merge into one window; unflagged buckets are not written.
    """
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")
    if min_history_buckets < 1:
        raise ValueError("min_history_buckets must be a positive integer")
    if baseline_buckets < 1:
        raise ValueError("baseline_buckets must be a positive integer")
    if drift_k < 0:
        raise ValueError("drift_k must be non-negative")
    if decision_h <= 0:
        raise ValueError("decision_h must be positive")
    if len(bucket_starts) != len(event_counts):
        raise ValueError("bucket_starts and event_counts must have equal length")

    n_buckets = len(event_counts)
    if n_buckets < min_history_buckets:
        return []

    n_baseline = min(baseline_buckets, n_buckets)
    mu, sigma = _robust_location_scale(event_counts[:n_baseline])
    k_abs = drift_k * sigma
    h_abs = decision_h * sigma

    s_pos = 0.0
    s_neg = 0.0
    flagged_buckets: list[tuple[datetime, datetime, float, float, str]] = []

    for index, (start, count) in enumerate(zip(bucket_starts, event_counts, strict=True)):
        if not isinstance(start, datetime):
            continue
        x = float(count)
        s_pos = max(0.0, s_pos + (x - mu - k_abs))
        s_neg = max(0.0, s_neg + (mu - k_abs - x))
        if index < n_baseline:
            continue
        high = s_pos / sigma
        low = s_neg / sigma
        if s_pos < h_abs and s_neg < h_abs:
            continue
        if s_pos >= h_abs and s_pos >= s_neg:
            direction = "up"
        else:
            direction = "down"
        window_end = start + timedelta(seconds=bucket_seconds)
        flagged_buckets.append(
            (_ensure_utc(start), _ensure_utc(window_end), high, low, direction)
        )

    return _merge_consecutive_flags(entity_id, flagged_buckets)


def _merge_consecutive_flags(
    entity_id: str,
    flagged_buckets: list[tuple[datetime, datetime, float, float, str]],
) -> list[ChangepointWindowScore]:
    if not flagged_buckets:
        return []

    rows: list[ChangepointWindowScore] = []
    run_start, run_end, high, low, direction = flagged_buckets[0]
    for start, end, next_high, next_low, next_dir in flagged_buckets[1:]:
        if start <= run_end:
            run_end = max(run_end, end)
            high = max(high, next_high)
            low = max(low, next_low)
            direction = "up" if high >= low else "down"
            continue
        rows.append(
            ChangepointWindowScore(
                entity_id=entity_id,
                window_start=run_start,
                window_end=run_end,
                cusum_high=high,
                cusum_low=low,
                flagged=True,
                direction="up" if high >= low else "down",
            )
        )
        run_start, run_end, high, low, direction = (
            start,
            end,
            next_high,
            next_low,
            next_dir,
        )
    rows.append(
        ChangepointWindowScore(
            entity_id=entity_id,
            window_start=run_start,
            window_end=run_end,
            cusum_high=high,
            cusum_low=low,
            flagged=True,
            direction=direction,
        )
    )
    return rows
