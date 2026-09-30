"""Per-entity fixed-width event count bucketing (SDD §7.3).

``bucketing.bucket_seconds`` interacts with ``spectral.window_hours`` and Welch
``baseline_max_nperseg`` (SDD §7.5.5). Do not change bucket width without
revisiting spectral config.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

import numpy as np

UTC = timezone.utc


@dataclass(frozen=True)
class BucketCountRow:
    """One bin in an entity's dense count series."""

    entity_id: str
    bucket_start: datetime
    bucket_seconds: int
    event_count: float


def _to_utc_epoch(ts: datetime) -> float:
    if ts.tzinfo is None:
        aware = ts.replace(tzinfo=UTC)
    else:
        aware = ts.astimezone(UTC)
    return aware.timestamp()


def _epoch_to_utc_datetime(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=UTC)


def bucket_events(
    timestamps: Sequence[datetime],
    bucket_seconds: int,
    *,
    entity_id: str,
) -> list[BucketCountRow]:
    """Convert event timestamps for one entity into dense bucket counts.

    Bins are half-open ``[bucket_start, bucket_start + bucket_seconds)``.
    ``bucket_start = floor(ts_epoch / bucket_seconds) * bucket_seconds`` in UTC.

    Empty ``timestamps`` returns ``[]``. Zero-fill bins between the entity's
    min and max event time (inclusive of the bins containing those events).
    Those interior zeros are indistinguishable from missing logs: both are
    ``event_count == 0.0``, never NaN.
    """
    if bucket_seconds <= 0:
        raise ValueError(f"bucket_seconds must be positive, got {bucket_seconds!r}")

    if not timestamps:
        return []

    ts_epochs = np.array([_to_utc_epoch(ts) for ts in timestamps], dtype=np.float64)
    min_epoch = float(ts_epochs.min())
    max_epoch = float(ts_epochs.max())

    grid_start = math.floor(min_epoch / bucket_seconds) * bucket_seconds
    grid_end = math.ceil(max_epoch / bucket_seconds) * bucket_seconds
    # At least one full bin when min and max fall in the same bucket.
    if grid_end <= grid_start:
        grid_end = grid_start + bucket_seconds

    # Right edge for histogram: one past the last bin's right edge.
    edges = np.arange(grid_start, grid_end + bucket_seconds, bucket_seconds, dtype=np.float64)
    counts, _ = np.histogram(ts_epochs, bins=edges)

    rows: list[BucketCountRow] = []
    for left_edge, count in zip(edges[:-1], counts, strict=True):
        rows.append(
            BucketCountRow(
                entity_id=entity_id,
                bucket_start=_epoch_to_utc_datetime(float(left_edge)),
                bucket_seconds=bucket_seconds,
                event_count=float(count),
            )
        )
    return rows
