"""Sliding-window rate z-scores for the statistical detector (SDD §7.4)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Sequence

from src.detectors.robust_z import robust_z_scores

MIN_WINDOWS = 24


@dataclass(frozen=True)
class StatisticalWindowScore:
    entity_id: str
    window_start: datetime
    window_end: datetime
    rate_z: float
    flagged: bool


def score_rate_windows(
    bucket_starts: Sequence[datetime],
    event_counts: Sequence[float],
    bucket_seconds: int,
    *,
    entity_id: str,
    window_buckets: int,
    z_threshold: float,
) -> list[StatisticalWindowScore]:
    """Score sliding-window event sums with per-entity robust z-scores.

    Windows roll one bucket at a time. ``flagged`` is one-sided:
    ``rate_z >= z_threshold``. Entities with fewer than ``MIN_WINDOWS``
    windows return ``[]``.
    """
    if window_buckets <= 0:
        raise ValueError(f"window_buckets must be positive, got {window_buckets!r}")
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")
    if len(bucket_starts) != len(event_counts):
        raise ValueError("bucket_starts and event_counts must have equal length")

    n_buckets = len(event_counts)
    if n_buckets < window_buckets:
        return []

    window_sums: list[float] = []
    window_meta: list[tuple[datetime, datetime]] = []
    for i in range(n_buckets - window_buckets + 1):
        window_sum = float(sum(event_counts[i : i + window_buckets]))
        window_start = bucket_starts[i]
        window_end = bucket_starts[i + window_buckets - 1] + timedelta(
            seconds=bucket_seconds
        )
        window_sums.append(window_sum)
        window_meta.append((window_start, window_end))

    if len(window_sums) < MIN_WINDOWS:
        return []

    z_scores = robust_z_scores(window_sums)
    rows: list[StatisticalWindowScore] = []
    for (window_start, window_end), window_sum, rate_z in zip(
        window_meta, window_sums, z_scores, strict=True
    ):
        _ = window_sum
        rows.append(
            StatisticalWindowScore(
                entity_id=entity_id,
                window_start=_ensure_utc(window_start),
                window_end=_ensure_utc(window_end),
                rate_z=rate_z,
                flagged=rate_z >= z_threshold,
            )
        )
    return rows


def _ensure_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)
